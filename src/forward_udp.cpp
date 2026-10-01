#include "forward_udp.h"

#include "resolve.h"
#include "util_str.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace pf {

namespace {

constexpr size_t kUdpBufferBytes = 65536;  // more than any IPv4 or IPv6 UDP payload
constexpr int kUdpBurst = 64;              // datagrams read from one socket per poll round

std::atomic<int> g_listenFaults{0};
std::atomic<int> g_listenFaultError{0};
std::atomic<bool> g_localhostIpv4First{true};
std::atomic<uint64_t> g_failovers{0};

// The result of opening a session's remote end, handed from a worker to the poll thread.
struct OpenResult {
    uint64_t sessionId = 0;
    std::string code;  // "" on success
    UniqueSocket sock;
    uint32_t maxPayload = 0;     // relayed: Ghost's limit; 0 = none of ours to apply
    uint32_t idleTimeoutMs = 0;  // relayed: Ghost's idle timeout; 0 = unknown
    std::vector<ResolvedAddr> addrs;  // direct: every address, in the order tried
    size_t addrIndex = 0;             // direct: the one `sock` is connected to
};

bool SameAddr(const ResolvedAddr& a, const ResolvedAddr& b) {
    return a.family == b.family && a.len == b.len && std::memcmp(&a.addr, &b.addr, static_cast<size_t>(a.len)) == 0;
}

}  // namespace

struct UdpShared {
    Rule rule;
    ForwardContext ctx;
    Clock* clock;
    RuleStats stats;
    std::atomic<bool> stop{false};
    // Signalled with `stop`: cancels a worker's name lookup, ends a listener error's pause.
    HANDLE stopEvent = nullptr;
    bool wsaOk = false;

    mutable std::mutex mu;
    std::string status = rule_status::kStopped;
    std::string detail;

    std::mutex aliveMu;
    std::condition_variable aliveCv;
    int alive = 0;  // open workers

    std::mutex resultsMu;
    std::vector<OpenResult> results;
    bool loopDone = false;  // under resultsMu: the poll thread has ended, nobody reads results

    // Direct rules: the address a session last got a reply from. Workers try it first, so
    // that only the first session of a rule pays for a dead first address.
    std::mutex stickyMu;
    bool haveSticky = false;
    ResolvedAddr sticky;

    // A connected loopback pair: a worker that posted a result, or SignalStop, sends one
    // byte to wake the poll thread at once instead of after its slice. Created by Start()
    // before any thread exists and never replaced, so reading them needs no lock.
    UniqueSocket wakeRecv;
    UniqueSocket wakeSend;
    // Set by Start() before the poll thread exists: WSARecvMsg (null when IP_PKTINFO could
    // not be enabled), and whether the listener is bound to 0.0.0.0.
    LPFN_WSARECVMSG recvMsg = nullptr;
    bool wildcard = false;

    UdpShared(const Rule& r, ForwardContext c) : rule(r), ctx(std::move(c)) {
        clock = ctx.clock ? ctx.clock : DefaultClock();
        if (!ctx.udpRelays) ctx.udpRelays = std::make_shared<std::atomic<int>>(0);
        stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        // A Winsock reference of our own: a straggler worker may outlive every other user.
        WSADATA d;
        wsaOk = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }
    ~UdpShared() {
        // Every socket closes before the Winsock reference is released.
        results.clear();
        wakeRecv.Reset();
        wakeSend.Reset();
        if (stopEvent) CloseHandle(stopEvent);
        if (wsaOk) WSACleanup();
    }
    UdpShared(const UdpShared&) = delete;
    UdpShared& operator=(const UdpShared&) = delete;

    void SetStatus(const std::string& st, const std::string& det) {
        std::lock_guard<std::mutex> lock(mu);
        status = st;
        detail = det;
    }

    void Log(LogLevel level, const std::string& text) {
        if (!ctx.log) return;
        try {
            ctx.log(level, text, LogFields{{"rule", rule.id}});
        } catch (...) {
            // A log that cannot be written must not take a forwarding thread down.
        }
    }
    std::string Who() const { return "rule \"" + rule.name + "\""; }

    // Records a failure; logs only the first of a run of the same code.
    void Fail(const std::string& code) {
        if (stats.RecordError(code)) Log(LogLevel::Warn, Who() + ": a UDP session failed: " + code);
    }

    bool ViaNode() const { return rule.egress != EgressKind::Direct; }
    // "" when this rule may listen.
    std::string NodeAvailability() const {
        if (!ViaNode()) return std::string();
        if (!ctx.tunnel) return rule_status::kNeedsGhost;
        return ctx.tunnel->Availability();
    }

    void Wake() {
        if (wakeSend) send(wakeSend.get(), "w", 1, 0);
    }
};

namespace {

bool SetNonBlocking(SOCKET s) {
    u_long one = 1;
    return ioctlsocket(s, FIONBIO, &one) == 0;
}

UniqueSocket NewUdpSocket(int family) {
    return UniqueSocket(
        WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
}

bool SetExclusive(SOCKET s) {
    BOOL one = TRUE;
    return setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one)) == 0;
}

// A receive buffer that holds a burst; the default (64 KB) is one large datagram.
void SetBuffers(SOCKET s) {
    int bytes = static_cast<int>(kUdpSocketBufferBytes);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&bytes), sizeof(bytes));
}

// SIO_UDP_CONNRESET / SIO_UDP_NETRESET. On (the default, set explicitly here) for a session's
// remote socket: an ICMP error from the destination, or the relay going away, must surface
// as WSAECONNRESET. Off for the listener: an ICMP error caused by a reply to a client that has
// gone away would otherwise make the next receive fail, for every client.
bool SetIcmpResets(SOCKET s, bool on) {
    BOOL v = on ? TRUE : FALSE;
    DWORD bytes = 0;
    return WSAIoctl(s, SIO_UDP_CONNRESET, &v, sizeof(v), nullptr, 0, &bytes, nullptr, nullptr) == 0 &&
           WSAIoctl(s, SIO_UDP_NETRESET, &v, sizeof(v), nullptr, 0, &bytes, nullptr, nullptr) == 0;
}

// Binds `s` to the wildcard (or loopback) address of its family, port 0, exclusively.
bool BindEphemeral(SOCKET s, int family, bool loopback) {
    if (!SetExclusive(s)) return false;
    if (family == AF_INET6) {
        sockaddr_in6 a = {};
        a.sin6_family = AF_INET6;
        a.sin6_addr = loopback ? in6addr_loopback : in6addr_any;
        return bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
    }
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(loopback ? INADDR_LOOPBACK : INADDR_ANY);
    return bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
}

// Two loopback UDP sockets connected to each other, both non-blocking.
bool MakeWakePair(UniqueSocket* recvEnd, UniqueSocket* sendEnd) {
    UniqueSocket r = NewUdpSocket(AF_INET);
    UniqueSocket w = NewUdpSocket(AF_INET);
    if (!r || !w) return false;
    if (!BindEphemeral(r.get(), AF_INET, true) || !BindEphemeral(w.get(), AF_INET, true)) return false;
    sockaddr_in ra = {};
    sockaddr_in wa = {};
    int len = sizeof(ra);
    if (getsockname(r.get(), reinterpret_cast<sockaddr*>(&ra), &len) != 0) return false;
    len = sizeof(wa);
    if (getsockname(w.get(), reinterpret_cast<sockaddr*>(&wa), &len) != 0) return false;
    if (connect(w.get(), reinterpret_cast<sockaddr*>(&ra), sizeof(ra)) != 0 ||
        connect(r.get(), reinterpret_cast<sockaddr*>(&wa), sizeof(wa)) != 0 || !SetNonBlocking(r.get()) ||
        !SetNonBlocking(w.get())) {
        return false;
    }
    *recvEnd = std::move(r);
    *sendEnd = std::move(w);
    return true;
}

// A direct session's remote socket: bound to port 0 exclusively, connected to `a`, resets on,
// a larger receive buffer, non-blocking. Invalid on any failure.
UniqueSocket ConnectUdp(const ResolvedAddr& a) {
    UniqueSocket c = NewUdpSocket(a.family);
    if (!c || !BindEphemeral(c.get(), a.family, false) ||
        connect(c.get(), reinterpret_cast<const sockaddr*>(&a.addr), a.len) != 0 || !SetIcmpResets(c.get(), true) ||
        !SetNonBlocking(c.get())) {
        return UniqueSocket();
    }
    SetBuffers(c.get());
    return c;
}

bool IsLocalhost(const std::string& host) {
    if (host.size() != 9) return false;
    std::string h = host;
    for (char& ch : h) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return h == "localhost";
}

// The order a direct session tries the addresses in: families interleaved (RFC 8305); for
// "localhost", IPv4 first -- local UDP services listen on 127.0.0.1 far more often than on
// ::1, and UDP gives no cheap way to find out; then the rule's sticky address, if it is one
// of them.
void OrderForUdp(UdpShared& s, std::vector<ResolvedAddr>* addrs) {
    InterleaveFamilies(addrs);
    if (g_localhostIpv4First.load() && IsLocalhost(s.rule.remoteHost)) {
        std::stable_partition(addrs->begin(), addrs->end(), [](const ResolvedAddr& a) { return a.family == AF_INET; });
    }
    std::lock_guard<std::mutex> lock(s.stickyMu);
    if (!s.haveSticky) return;
    for (size_t i = 0; i < addrs->size(); ++i) {
        if (SameAddr((*addrs)[i], s.sticky)) {
            std::rotate(addrs->begin(), addrs->begin() + static_cast<std::ptrdiff_t>(i),
                        addrs->begin() + static_cast<std::ptrdiff_t>(i) + 1);
            return;
        }
    }
}

// Resolves remote.host (a stop cancels the lookup: resolve.h) and connects a UDP socket to
// the first address in OrderForUdp's order that takes one. Runs on a worker. A UDP connect
// sends nothing, so a dead address only shows when the destination answers with ICMP: the
// poll thread then fails over to the next address (UdpLoop::HandleReset).
void OpenDirect(UdpShared& s, OpenResult* r) {
    r->code = ResolveHost(s.rule.remoteHost, s.rule.remotePort, SOCK_DGRAM, s.stopEvent, &r->addrs);
    if (!r->code.empty()) return;
    OrderForUdp(s, &r->addrs);
    for (size_t i = 0; i < r->addrs.size(); ++i) {
        UniqueSocket c = ConnectUdp(r->addrs[i]);
        if (!c) continue;
        r->sock = std::move(c);
        r->addrIndex = i;
        return;
    }
    r->code = fwd_err::kConnectFailed;
}

bool TakeListenFault(int* out) {
    int cur = g_listenFaults.load();
    while (cur > 0) {
        if (g_listenFaults.compare_exchange_weak(cur, cur - 1)) {
            *out = g_listenFaultError.load();
            return true;
        }
    }
    return false;
}

struct WorkerExit {
    UdpShared& s;
    ~WorkerExit() {
        std::lock_guard<std::mutex> lock(s.aliveMu);
        --s.alive;
        s.aliveCv.notify_all();
    }
};

void OpenWorker(std::shared_ptr<UdpShared> sp, uint64_t sessionId) {
    UdpShared& s = *sp;
    WorkerExit exitGuard{s};
    OpenResult r;
    r.sessionId = sessionId;
    try {
        if (!s.ViaNode()) {
            OpenDirect(s, &r);
        } else if (!s.ctx.tunnel) {
            r.code = rule_status::kNeedsGhost;
        } else {
            // Fail closed: whatever this answers is the session's fate. Nothing direct is
            // ever tried for a via-node rule.
            TunnelResult t = s.ctx.tunnel->Open(s.rule.egress, s.rule.nodeId, Proto::Udp, s.rule.remoteHost,
                                                s.rule.remotePort);
            r.code = t.code;
            r.sock = std::move(t.sock);
            r.maxPayload = t.maxPayload;
            r.idleTimeoutMs = t.idleTimeoutMs;
            if (r.code.empty() && !r.sock) r.code = fwd_err::kInternal;
        }
    } catch (...) {
        r.code = fwd_err::kInternal;
        r.sock.Reset();
    }
    if (!r.code.empty()) r.sock.Reset();
    if (s.stop.load()) return;  // `r` closes its socket; nobody will read it
    try {
        std::lock_guard<std::mutex> lock(s.resultsMu);
        if (s.loopDone) return;
        s.results.push_back(std::move(r));
    } catch (...) {
        return;
    }
    s.Wake();
}

// A session is one client source address (IPv4 address and port) as seen at one local
// address (the destination the client sent to: different on a 0.0.0.0 listener of a
// multi-homed machine, and the reply must come from it). Local address 0 = not known.
using SessionKey = std::pair<uint64_t, uint32_t>;

SessionKey KeyOf(const sockaddr_in& from, uint32_t localAddr) {
    return SessionKey((static_cast<uint64_t>(ntohl(from.sin_addr.s_addr)) << 16) | ntohs(from.sin_port), localAddr);
}

enum class IoResult { Ok, Reset, Error };

struct Session {
    uint64_t id = 0;
    sockaddr_in client = {};
    bool haveLocal = false;  // `local` is the address the client sent to
    in_addr local = {};
    ULONG ifindex = 0;
    bool pktinfoOk = true;  // replies may name their source address (until that fails once)
    bool relaySlot = false; // holds one of the plugin-wide relay slots
    bool open = false;      // the remote end exists
    UniqueSocket remote;
    std::deque<std::string> queue;  // while the remote end is being opened
    size_t queuedBytes = 0;
    // Direct sessions: every resolved address and the one in use. Until the first reply,
    // what was sent is kept (within the queue's bounds) to be sent again to the next address
    // if this one turns out dead.
    std::vector<ResolvedAddr> addrs;
    size_t addrIndex = 0;
    bool gotReply = false;
    std::deque<std::string> retained;
    size_t retainedBytes = 0;
    uint64_t lastActivity = 0;  // the last datagram actually sent or received
    uint64_t idleMs = 0;
    uint32_t maxPayload = 0;  // 0 = no relay limit
};

struct ClientBackoff {
    uint64_t until = 0;
    uint64_t delay = 0;
};

// The poll thread's state. Only the poll thread touches it.
class UdpLoop {
public:
    UdpLoop(std::shared_ptr<UdpShared> sp, SOCKET listener)
        : sp_(std::move(sp)), s_(*sp_), listener_(listener), buf_(kUdpBufferBytes) {}

    ~UdpLoop() {
        // The rule is stopping (or its listener failed): every session ends with it.
        s_.stats.udpSessions -= sessions_.size();
        for (const auto& kv : sessions_) {
            s_.stats.droppedDatagrams += kv.second.queue.size();
            if (kv.second.relaySlot) --*s_.ctx.udpRelays;
        }
        sessions_.clear();
        std::lock_guard<std::mutex> lock(s_.resultsMu);
        s_.loopDone = true;
        s_.results.clear();
    }

    void Run() {
        std::vector<WSAPOLLFD> fds;
        std::vector<SessionKey> keys;  // per fd from index 2: the session's key
        while (!s_.stop.load()) {
            const std::string avail = s_.NodeAvailability();
            if (!avail.empty()) {
                // Ghost became unusable while we listened (a 401): stop listening, and say why.
                s_.SetStatus(avail, std::string());
                s_.Log(LogLevel::Warn, s_.Who() + " stopped listening: " + avail);
                return;
            }
            fds.clear();
            keys.clear();
            WSAPOLLFD p = {};
            p.events = POLLRDNORM;
            p.fd = listener_.get();
            fds.push_back(p);
            p.fd = s_.wakeRecv.get();
            fds.push_back(p);
            for (const auto& kv : sessions_) {
                if (!kv.second.open) continue;
                p.fd = kv.second.remote.get();
                fds.push_back(p);
                keys.push_back(kv.first);
            }
            const int n = WSAPoll(fds.data(), static_cast<ULONG>(fds.size()), static_cast<INT>(kPollSliceMs));
            if (n == SOCKET_ERROR) {
                Fatal();
                return;
            }
            if (s_.stop.load()) return;
            if (fds[1].revents) DrainWake();
            TakeResults();
            if (fds[0].revents) {
                const int got = DrainListener();
                // An error condition that no receive clears would bring WSAPoll straight back.
                if (got == 0 && (fds[0].revents & (POLLERR | POLLNVAL))) Pause();
            }
            for (size_t i = 2; i < fds.size(); ++i) {
                if (!fds[i].revents) continue;
                const SessionKey key = keys[i - 2];
                auto it = sessions_.find(key);
                // The session may have ended, been replaced or failed over meanwhile.
                if (it == sessions_.end() || !it->second.open || it->second.remote.get() != fds[i].fd) continue;
                const IoResult r = DrainRemote(key, it->second);
                if (r == IoResult::Reset) {
                    HandleReset(key, nullptr);
                } else if (r == IoResult::Error) {
                    EndSession(key, fwd_err::kInternal, false);
                }
            }
            SweepIdle();
        }
    }

private:
    uint64_t Now() const { return s_.clock->NowMs(); }

    void Fatal() {
        s_.Fail(fwd_err::kInternal);
        s_.SetStatus(rule_status::kStopped, fwd_err::kInternal);
    }

    // An error the listener keeps reporting: record it and give the system one slice
    // instead of spinning on it.
    void Pause() {
        s_.Fail(fwd_err::kInternal);
        WaitForSingleObject(s_.stopEvent, kPollSliceMs);
    }

    void DrainWake() {
        char b[64];
        for (int i = 0; i < kUdpBurst; ++i) {
            if (recv(s_.wakeRecv.get(), b, sizeof(b), 0) == SOCKET_ERROR &&
                WSAGetLastError() == WSAEWOULDBLOCK) {
                return;
            }
        }
    }

    void Drop(size_t n = 1) { s_.stats.droppedDatagrams += n; }

    // ---- Per-client backoff --------------------------------------------------------------

    // A session ended before its remote end ever answered (its open failed, or the
    // destination reset it): the same client's next datagram does not open a new session
    // (a thread, a lookup, a tunnel request) before 1 s, doubling to 10 s.
    void BackoffClient(const SessionKey& key) {
        const uint64_t now = Now();
        auto it = backoff_.find(key);
        if (it == backoff_.end()) {
            if (backoff_.size() >= kUdpClientBackoffEntries) TrimBackoff(now);
            it = backoff_.emplace(key, ClientBackoff()).first;
        }
        ClientBackoff& b = it->second;
        b.delay = b.delay == 0 ? kUdpClientBackoffMinMs : (std::min)(b.delay * 2, uint64_t{kUdpClientBackoffMaxMs});
        b.until = now + b.delay;
    }

    void TrimBackoff(uint64_t now) {
        for (auto it = backoff_.begin(); it != backoff_.end();) {
            it = it->second.until <= now ? backoff_.erase(it) : std::next(it);
        }
        if (backoff_.size() < kUdpClientBackoffEntries) return;
        auto oldest = backoff_.begin();
        for (auto it = backoff_.begin(); it != backoff_.end(); ++it) {
            if (it->second.until < oldest->second.until) oldest = it;
        }
        backoff_.erase(oldest);
    }

    bool BackedOff(const SessionKey& key, uint64_t now) const {
        auto it = backoff_.find(key);
        return it != backoff_.end() && now < it->second.until;
    }

    // ---- Sessions ------------------------------------------------------------------------

    void EndSession(const SessionKey& key, const char* code, bool clientBackoff) {
        auto it = sessions_.find(key);
        if (it == sessions_.end()) return;
        Drop(it->second.queue.size());
        if (it->second.relaySlot) --*s_.ctx.udpRelays;
        const bool answered = it->second.gotReply;
        sessions_.erase(it);
        --s_.stats.udpSessions;
        if (clientBackoff && !answered && !s_.stop.load()) BackoffClient(key);
        if (code && *code && !s_.stop.load()) s_.Fail(code);
    }

    void Enqueue(Session& se, const char* data, size_t len) {
        if (se.queue.size() >= kUdpQueueMaxDatagrams || se.queuedBytes + len > kUdpQueueMaxBytes) {
            Drop();
            return;
        }
        se.queue.emplace_back(data, len);
        se.queuedBytes += len;
    }

    bool Retain(Session& se, const char* data, size_t len) {
        if (se.retained.size() >= kUdpQueueMaxDatagrams || se.retainedBytes + len > kUdpQueueMaxBytes) return false;
        se.retained.emplace_back(data, len);
        se.retainedBytes += len;
        return true;
    }

    // Sends one datagram to the remote end. On Reset the datagram was NOT sent and is not
    // counted: the caller decides (HandleReset may send it to the next address).
    IoResult SendToRemote(Session& se, const char* data, size_t len) {
        if (se.maxPayload != 0 && len > se.maxPayload) {
            Drop();  // the relay would drop it too, silently
            return IoResult::Ok;
        }
        const int k = send(se.remote.get(), data, static_cast<int>(len), 0);
        if (k == SOCKET_ERROR) {
            const int e = WSAGetLastError();
            if (e == WSAECONNRESET || e == WSAENETRESET) return IoResult::Reset;
            Drop();  // lost
            if (e == WSAEWOULDBLOCK || e == WSAEMSGSIZE || e == WSAENOBUFS) return IoResult::Ok;
            return IoResult::Error;
        }
        s_.stats.bytesUp += static_cast<uint64_t>(k);
        se.lastActivity = Now();
        if (!se.gotReply && !se.addrs.empty()) Retain(se, data, len);
        return IoResult::Ok;
    }

    // WSAECONNRESET on a session's remote socket. A direct session that has not had a reply
    // yet fails over to its next address and sends again what it had sent; otherwise -- a
    // relay (Ghost tore it down), an address that did answer before, no address left -- the
    // session ends. `unsent` is a datagram whose send reported the reset.
    void HandleReset(const SessionKey& key, const std::string* unsent) {
        auto it = sessions_.find(key);
        if (it == sessions_.end()) return;
        Session& se = it->second;
        if (!se.addrs.empty() && !se.gotReply) {
            if (unsent && !Retain(se, unsent->data(), unsent->size())) Drop();
            unsent = nullptr;
            for (size_t next = se.addrIndex + 1; next < se.addrs.size(); ++next) {
                UniqueSocket c = ConnectUdp(se.addrs[next]);
                if (!c) continue;
                se.remote = std::move(c);
                se.addrIndex = next;
                ++g_failovers;
                bool replayed = true;
                for (const std::string& d : se.retained) {
                    const int k = send(se.remote.get(), d.data(), static_cast<int>(d.size()), 0);
                    if (k == SOCKET_ERROR) {
                        const int e = WSAGetLastError();
                        if (e == WSAECONNRESET || e == WSAENETRESET) {
                            replayed = false;  // this one is dead too: on to the next
                            break;
                        }
                        continue;  // a full buffer: that datagram is lost, the address is not
                    }
                    s_.stats.bytesUp += static_cast<uint64_t>(k);
                }
                if (replayed) return;
            }
        } else if (unsent) {
            Drop();
        }
        EndSession(key, fwd_err::kRemoteReset, true);
    }

    // Sends a reply from the listener to the session's client -- from the address the client
    // sent to, when the listener is 0.0.0.0 and that address is known (IP_PKTINFO). Windows
    // refuses some source addresses (WSAEADDRNOTAVAIL: 127.0.0.2, which it accepts traffic
    // for but will not send from); the session then falls back to letting routing choose.
    int SendToClient(Session& se, const char* data, int len) {
        if (s_.wildcard && se.haveLocal && se.pktinfoOk) {
            alignas(WSACMSGHDR) char ctl[WSA_CMSG_SPACE(sizeof(IN_PKTINFO))] = {};
            WSABUF b = {static_cast<ULONG>(len), const_cast<char*>(data)};
            WSAMSG m = {};
            m.name = reinterpret_cast<sockaddr*>(&se.client);
            m.namelen = sizeof(se.client);
            m.lpBuffers = &b;
            m.dwBufferCount = 1;
            m.Control.buf = ctl;
            m.Control.len = sizeof(ctl);
            WSACMSGHDR* h = WSA_CMSG_FIRSTHDR(&m);
            h->cmsg_level = IPPROTO_IP;
            h->cmsg_type = IP_PKTINFO;
            h->cmsg_len = WSA_CMSG_LEN(sizeof(IN_PKTINFO));
            IN_PKTINFO* pi = reinterpret_cast<IN_PKTINFO*>(WSA_CMSG_DATA(h));
            pi->ipi_addr = se.local;
            pi->ipi_ifindex = se.ifindex;
            DWORD sent = 0;
            if (WSASendMsg(listener_.get(), &m, 0, &sent, nullptr, nullptr) == 0) return static_cast<int>(sent);
            const int e = WSAGetLastError();
            if (e != WSAEADDRNOTAVAIL && e != WSAEINVAL) return SOCKET_ERROR;
            se.pktinfoOk = false;
        }
        return sendto(listener_.get(), data, len, 0, reinterpret_cast<const sockaddr*>(&se.client),
                      sizeof(se.client));
    }

    // Reads what the remote end has and sends it to the client.
    IoResult DrainRemote(const SessionKey& key, Session& se) {
        for (int i = 0; i < kUdpBurst; ++i) {
            const int k = recv(se.remote.get(), buf_.data(), static_cast<int>(buf_.size()), 0);
            if (k == SOCKET_ERROR) {
                const int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) return IoResult::Ok;
                if (e == WSAEMSGSIZE) {
                    Drop();
                    continue;
                }
                if (e == WSAECONNRESET || e == WSAENETRESET) return IoResult::Reset;
                return IoResult::Error;
            }
            if (!se.gotReply) {
                se.gotReply = true;
                se.retained.clear();
                se.retainedBytes = 0;
                backoff_.erase(key);
                if (!se.addrs.empty()) {
                    std::lock_guard<std::mutex> lock(s_.stickyMu);
                    s_.sticky = se.addrs[se.addrIndex];
                    s_.haveSticky = true;
                }
            }
            se.lastActivity = Now();
            const int w = SendToClient(se, buf_.data(), k);
            if (w == SOCKET_ERROR) {
                Drop();
            } else {
                s_.stats.bytesDown += static_cast<uint64_t>(w);
            }
        }
        return IoResult::Ok;
    }

    // One datagram from the listener. Returns its length, or SOCKET_ERROR (WSAGetLastError).
    int ReceiveFromClient(sockaddr_in* from, bool* haveLocal, in_addr* local, ULONG* ifindex) {
        *haveLocal = false;
        int fault = 0;
        if (TakeListenFault(&fault)) {
            WSASetLastError(fault);
            return SOCKET_ERROR;
        }
        if (!s_.recvMsg) {
            int fromLen = sizeof(*from);
            const int k = recvfrom(listener_.get(), buf_.data(), static_cast<int>(buf_.size()), 0,
                                   reinterpret_cast<sockaddr*>(from), &fromLen);
            if (k != SOCKET_ERROR && fromLen != static_cast<int>(sizeof(*from))) from->sin_family = AF_UNSPEC;
            return k;
        }
        alignas(WSACMSGHDR) char ctl[WSA_CMSG_SPACE(sizeof(IN_PKTINFO)) + 64] = {};
        WSABUF b = {static_cast<ULONG>(buf_.size()), buf_.data()};
        WSAMSG m = {};
        m.name = reinterpret_cast<sockaddr*>(from);
        m.namelen = sizeof(*from);
        m.lpBuffers = &b;
        m.dwBufferCount = 1;
        m.Control.buf = ctl;
        m.Control.len = sizeof(ctl);
        DWORD got = 0;
        if (s_.recvMsg(listener_.get(), &m, &got, nullptr, nullptr) != 0) return SOCKET_ERROR;
        if (m.namelen != static_cast<int>(sizeof(*from))) from->sin_family = AF_UNSPEC;
        for (WSACMSGHDR* h = WSA_CMSG_FIRSTHDR(&m); h; h = WSA_CMSG_NXTHDR(&m, h)) {
            if (h->cmsg_level == IPPROTO_IP && h->cmsg_type == IP_PKTINFO) {
                const IN_PKTINFO* pi = reinterpret_cast<const IN_PKTINFO*>(WSA_CMSG_DATA(h));
                *local = pi->ipi_addr;
                *ifindex = pi->ipi_ifindex;
                *haveLocal = true;
            }
        }
        return static_cast<int>(got);
    }

    // Reads the listener. Returns how many datagrams it read; -1 when it paused on an error.
    int DrainListener() {
        int read = 0;
        for (int i = 0; i < kUdpBurst; ++i) {
            sockaddr_in from = {};
            bool haveLocal = false;
            in_addr local = {};
            ULONG ifindex = 0;
            const int k = ReceiveFromClient(&from, &haveLocal, &local, &ifindex);
            if (k == SOCKET_ERROR) {
                const int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) return read;
                if (e == WSAEMSGSIZE) {
                    Drop();
                    ++read;
                    continue;
                }
                // Not expected with SIO_UDP_CONNRESET/NETRESET off, and harmless if it comes.
                if (e == WSAECONNRESET || e == WSAENETRESET) continue;
                // Anything else (out of buffers) would come straight back: the listener stays
                // readable.
                Pause();
                return -1;
            }
            ++read;
            if (from.sin_family != AF_INET) {
                Drop();
                continue;
            }
            FromClient(from, haveLocal, local, ifindex, buf_.data(), static_cast<size_t>(k));
        }
        return read;
    }

    void FromClient(const sockaddr_in& from, bool haveLocal, in_addr local, ULONG ifindex, const char* data,
                    size_t len) {
        const SessionKey key = KeyOf(from, haveLocal ? local.s_addr : 0);
        auto it = sessions_.find(key);
        if (it == sessions_.end()) {
            NewSession(key, from, haveLocal, local, ifindex, data, len);
            return;
        }
        Session& se = it->second;
        if (!se.open) {
            Enqueue(se, data, len);
            return;
        }
        const IoResult r = SendToRemote(se, data, len);
        if (r == IoResult::Reset) {
            const std::string unsent(data, len);
            HandleReset(key, &unsent);
        } else if (r == IoResult::Error) {
            EndSession(key, fwd_err::kInternal, false);
        }
    }

    // Takes one plugin-wide relay slot, or fails when they are all in use.
    bool TakeRelaySlot() {
        std::atomic<int>& n = *s_.ctx.udpRelays;
        int cur = n.load();
        do {
            if (cur >= s_.ctx.udpRelayMax) return false;
        } while (!n.compare_exchange_weak(cur, cur + 1));
        return true;
    }

    void NewSession(const SessionKey& key, const sockaddr_in& from, bool haveLocal, in_addr local, ULONG ifindex,
                    const char* data, size_t len) {
        const uint64_t now = Now();
        if (now < failUntil_) {
            // The node (or the name) failed moments ago: no new request until the cache expires.
            Drop();
            return;
        }
        if (BackedOff(key, now)) {
            Drop();
            return;
        }
        if (sessions_.size() >= kMaxUdpSessionsPerRule) {
            Drop();
            s_.Fail(fwd_err::kSessionLimit);
            return;
        }
        Session se;
        if (s_.ViaNode()) {
            if (!TakeRelaySlot()) {
                // Ghost would answer tunnel_limit: refuse here, without a request.
                Drop();
                s_.Fail(fwd_err::kSessionLimit);
                return;
            }
            se.relaySlot = true;
        }
        se.id = ++nextId_;
        se.client = from;
        se.haveLocal = haveLocal;
        se.local = local;
        se.ifindex = ifindex;
        se.lastActivity = now;
        se.idleMs = static_cast<uint64_t>(s_.rule.udpIdleSec) * 1000u;
        const uint64_t id = se.id;
        Enqueue(se, data, len);
        sessions_.emplace(key, std::move(se));
        ++s_.stats.udpSessions;
        ++s_.stats.totalConnections;
        {
            std::lock_guard<std::mutex> lock(s_.aliveMu);
            ++s_.alive;
        }
        try {
            std::thread([sp = sp_, id] {
                try {
                    OpenWorker(sp, id);
                } catch (...) {
                }
            }).detach();
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(s_.aliveMu);
                --s_.alive;
                s_.aliveCv.notify_all();
            }
            EndSession(key, fwd_err::kInternal, false);
        }
    }

    void TakeResults() {
        std::vector<OpenResult> got;
        {
            std::lock_guard<std::mutex> lock(s_.resultsMu);
            got.swap(s_.results);
        }
        for (OpenResult& r : got) Apply(r);
    }

    void Apply(OpenResult& r) {
        auto it = sessions_.begin();
        for (; it != sessions_.end(); ++it) {
            if (it->second.id == r.sessionId) break;
        }
        if (it == sessions_.end()) return;  // the session is gone; `r` closes its socket
        const SessionKey key = it->first;
        Session& se = it->second;
        const uint64_t now = Now();
        if (!r.code.empty()) {
            if (!s_.stop.load()) {
                s_.Fail(r.code);
                if (IsCacheableOpenFailure(r.code)) {
                    failDelay_ = failDelay_ == 0 ? kUdpFailureCacheMinMs
                                                 : (std::min)(failDelay_ * 2, uint64_t{kUdpFailureCacheMaxMs});
                    failUntil_ = now + failDelay_;
                }
            }
            EndSession(key, nullptr, true);  // its queued datagrams are dropped
            return;
        }
        if (se.addrs.empty() && r.addrs.empty()) {
            // A relay: as Ghost hands it over, blocking and with nothing set.
            if (!SetNonBlocking(r.sock.get()) || !SetIcmpResets(r.sock.get(), true)) {
                EndSession(key, fwd_err::kInternal, false);
                return;
            }
            SetBuffers(r.sock.get());
        }
        se.remote = std::move(r.sock);
        se.addrs = std::move(r.addrs);
        se.addrIndex = r.addrIndex;
        se.open = true;
        failDelay_ = 0;
        s_.stats.NoteSuccess();
        se.maxPayload = r.maxPayload;
        if (r.idleTimeoutMs > kUdpRelayIdleMarginMs) {
            se.idleMs = (std::min)(se.idleMs, static_cast<uint64_t>(r.idleTimeoutMs - kUdpRelayIdleMarginMs));
        }
        se.lastActivity = now;
        std::deque<std::string> queued;
        queued.swap(se.queue);
        se.queuedBytes = 0;
        while (!queued.empty()) {
            const std::string d = std::move(queued.front());
            queued.pop_front();
            auto cur = sessions_.find(key);
            if (cur == sessions_.end()) {
                Drop(1 + queued.size());
                return;
            }
            const IoResult res = SendToRemote(cur->second, d.data(), d.size());
            if (res == IoResult::Reset) {
                HandleReset(key, &d);
            } else if (res == IoResult::Error) {
                Drop(queued.size());
                EndSession(key, fwd_err::kInternal, false);
                return;
            }
        }
    }

    void SweepIdle() {
        const uint64_t now = Now();
        std::vector<SessionKey> idle;
        for (const auto& kv : sessions_) {
            const Session& se = kv.second;
            if (se.open && now >= se.lastActivity && now - se.lastActivity >= se.idleMs) idle.push_back(kv.first);
        }
        for (const SessionKey& key : idle) EndSession(key, nullptr, false);
    }

    std::shared_ptr<UdpShared> sp_;
    UdpShared& s_;
    UniqueSocket listener_;
    std::vector<char> buf_;
    std::map<SessionKey, Session> sessions_;
    std::map<SessionKey, ClientBackoff> backoff_;
    uint64_t nextId_ = 0;
    uint64_t failUntil_ = 0;  // Clock time until which no new session is opened
    uint64_t failDelay_ = 0;  // the current failed-open cache period; 0 = none
};

void PollMain(std::shared_ptr<UdpShared> sp, SOCKET listener) {
    UdpLoop loop(sp, listener);
    loop.Run();
}

}  // namespace

bool IsCacheableOpenFailure(const std::string& code) {
    return code.rfind("upstream_", 0) == 0 || code == "permission_denied" || code == "tunnel_unsupported" ||
           code == fwd_err::kResolveFailed;
}

namespace testing {

void InjectUdpListenErrors(int count, int wsaError) {
    g_listenFaultError.store(wsaError);
    g_listenFaults.store(count);
}

void SetUdpLocalhostIpv4First(bool on) { g_localhostIpv4First.store(on); }

uint64_t UdpFailovers() { return g_failovers.load(); }

}  // namespace testing

UdpForwarder::UdpForwarder(const Rule& rule, ForwardContext ctx)
    : s_(std::make_shared<UdpShared>(rule, std::move(ctx))) {}

UdpForwarder::~UdpForwarder() {
    SignalStop();
    if (poll_.joinable()) poll_.join();
}

const Rule& UdpForwarder::rule() const { return s_->rule; }

void UdpForwarder::Start() {
    UdpShared& s = *s_;
    if (s.rule.proto != Proto::Udp) {
        s.SetStatus(rule_status::kNotSupported, std::string());
        return;
    }
    const std::string avail = s.NodeAvailability();
    if (!avail.empty()) {
        // A via-node rule that cannot get a relay does not listen at all.
        s.SetStatus(avail, std::string());
        s.Log(LogLevel::Warn, s.Who() + " is not listening: " + avail);
        return;
    }
    if (!s.wsaOk) {
        s.SetStatus(rule_status::kBindFailed, fwd_err::kInternal);
        return;
    }
    if (!MakeWakePair(&s.wakeRecv, &s.wakeSend)) {
        s.Fail(fwd_err::kInternal);
        s.SetStatus(rule_status::kStopped, fwd_err::kInternal);
        return;
    }

    UniqueSocket l = NewUdpSocket(AF_INET);
    int err = 0;
    if (!l) {
        err = WSAGetLastError();
    } else {
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_port = htons(static_cast<u_short>(s.rule.listenPort));
        if (!SetExclusive(l.get()) || InetPtonW(AF_INET, Utf8ToWide(s.rule.listenAddr).c_str(), &a.sin_addr) != 1 ||
            bind(l.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || !SetNonBlocking(l.get()) ||
            !SetIcmpResets(l.get(), false)) {
            err = WSAGetLastError();
            if (err == 0) err = WSAEINVAL;
        }
    }
    if (err != 0) {
        const std::string detail = BindFailureDetail(err, Proto::Udp);
        s.SetStatus(rule_status::kBindFailed, detail);
        s.stats.RecordError(fwd_err::kBindFailed);
        s.Log(LogLevel::Warn, s.Who() + " cannot listen on udp " + s.rule.listenAddr + ":" +
                                  std::to_string(s.rule.listenPort) + ": " + detail);
        return;
    }
    SetBuffers(l.get());
    s.wildcard = s.rule.listenAddr == kAnyAddr;
    // The destination address of each datagram (IP_PKTINFO through WSARecvMsg). Without it
    // the rule still works; replies then leave from whatever address routing picks.
    DWORD on = 1;
    if (setsockopt(l.get(), IPPROTO_IP, IP_PKTINFO, reinterpret_cast<const char*>(&on), sizeof(on)) == 0) {
        GUID guid = WSAID_WSARECVMSG;
        LPFN_WSARECVMSG fn = nullptr;
        DWORD bytes = 0;
        if (WSAIoctl(l.get(), SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid), &fn, sizeof(fn), &bytes,
                     nullptr, nullptr) == 0) {
            s.recvMsg = fn;
        }
    }

    s.SetStatus(rule_status::kListening, std::string());
    const SOCKET raw = l.Release();
    try {
        poll_ = std::thread([sp = s_, raw] {
            try {
                PollMain(sp, raw);
            } catch (...) {
            }
        });
    } catch (...) {
        closesocket(raw);
        s.SetStatus(rule_status::kStopped, fwd_err::kInternal);
        return;
    }
    s.Log(LogLevel::Info,
          s.Who() + " listening on udp " + s.rule.listenAddr + ":" + std::to_string(s.rule.listenPort));
}

void UdpForwarder::SignalStop() {
    s_->stop.store(true);
    if (s_->stopEvent) SetEvent(s_->stopEvent);
    {
        std::lock_guard<std::mutex> lock(s_->mu);
        if (s_->status == rule_status::kListening) s_->status = rule_status::kStopped;
    }
    s_->Wake();
}

bool UdpForwarder::WaitStopped(uint64_t deadlineTick) {
    // The poll thread notices the flag at once (woken) or within one slice.
    if (poll_.joinable()) poll_.join();
    std::unique_lock<std::mutex> lock(s_->aliveMu);
    for (;;) {
        if (s_->alive == 0) return true;
        const uint64_t now = GetTickCount64();
        if (now >= deadlineTick) return false;
        s_->aliveCv.wait_for(lock, std::chrono::milliseconds(deadlineTick - now));
    }
}

RuleStatus UdpForwarder::Snapshot() const {
    RuleStatus r;
    r.id = s_->rule.id;
    {
        std::lock_guard<std::mutex> lock(s_->mu);
        r.status = s_->status;
        r.detail = s_->detail;
    }
    r.stats = s_->stats.Snapshot();
    return r;
}

int UdpForwarder::ThreadsAlive() const {
    std::lock_guard<std::mutex> lock(s_->aliveMu);
    return s_->alive;
}

}  // namespace pf
