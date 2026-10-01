#include "forward_udp.h"

#include "resolve.h"
#include "util_str.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
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

// The result of opening a session's remote end, handed from a worker to the poll thread.
struct OpenResult {
    uint64_t sessionId = 0;
    std::string code;  // "" on success
    UniqueSocket sock;
    uint32_t maxPayload = 0;     // relayed: Ghost's limit; 0 = none of ours to apply
    uint32_t idleTimeoutMs = 0;  // relayed: Ghost's idle timeout; 0 = unknown
};

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

    // A connected loopback pair: a worker that posted a result, or SignalStop, sends one
    // byte to wake the poll thread at once instead of after its slice. Created by Start()
    // before any thread exists and never replaced, so reading them needs no lock.
    UniqueSocket wakeRecv;
    UniqueSocket wakeSend;

    UdpShared(const Rule& r, ForwardContext c) : rule(r), ctx(std::move(c)) {
        clock = ctx.clock ? ctx.clock : DefaultClock();
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

// Two loopback UDP sockets connected to each other, both non-blocking.
bool MakeWakePair(UniqueSocket* recvEnd, UniqueSocket* sendEnd) {
    UniqueSocket r = NewUdpSocket(AF_INET);
    UniqueSocket w = NewUdpSocket(AF_INET);
    if (!r || !w) return false;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in ra = a;
    sockaddr_in wa = a;
    int len = sizeof(ra);
    if (bind(r.get(), reinterpret_cast<sockaddr*>(&ra), sizeof(ra)) != 0 ||
        getsockname(r.get(), reinterpret_cast<sockaddr*>(&ra), &len) != 0) {
        return false;
    }
    len = sizeof(wa);
    if (bind(w.get(), reinterpret_cast<sockaddr*>(&wa), sizeof(wa)) != 0 ||
        getsockname(w.get(), reinterpret_cast<sockaddr*>(&wa), &len) != 0) {
        return false;
    }
    if (connect(w.get(), reinterpret_cast<sockaddr*>(&ra), sizeof(ra)) != 0 ||
        connect(r.get(), reinterpret_cast<sockaddr*>(&wa), sizeof(wa)) != 0 || !SetNonBlocking(r.get()) ||
        !SetNonBlocking(w.get())) {
        return false;
    }
    *recvEnd = std::move(r);
    *sendEnd = std::move(w);
    return true;
}

// ICMP errors caused by our own sends must not fail the listener's next receive.
bool DisableIcmpResets(SOCKET s) {
    BOOL off = FALSE;
    DWORD bytes = 0;
    return WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr) == 0 &&
           WSAIoctl(s, SIO_UDP_NETRESET, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr) == 0;
}

// Resolves remote.host (a stop cancels the lookup: resolve.h) and connects a UDP socket to
// the first address a socket can be created for. Runs on a worker. "" and the socket, or a
// code. A UDP connect sends nothing, so there is nothing to stagger: an address that turns
// out dead answers with ICMP, which ends the session (WSAECONNRESET).
std::string OpenDirect(UdpShared& s, UniqueSocket* out) {
    std::vector<ResolvedAddr> addrs;
    const std::string rc = ResolveHost(s.rule.remoteHost, s.rule.remotePort, SOCK_DGRAM, s.stopEvent, &addrs);
    if (!rc.empty()) return rc;
    for (const ResolvedAddr& a : addrs) {
        UniqueSocket c = NewUdpSocket(a.family);
        if (!c) continue;
        if (connect(c.get(), reinterpret_cast<const sockaddr*>(&a.addr), a.len) != 0) continue;
        *out = std::move(c);
        return std::string();
    }
    return fwd_err::kConnectFailed;
}

std::atomic<int> g_listenFaults{0};
std::atomic<int> g_listenFaultError{0};

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
            r.code = OpenDirect(s, &r.sock);
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

uint64_t ClientKey(const sockaddr_in& a) {
    return (static_cast<uint64_t>(ntohl(a.sin_addr.s_addr)) << 16) | ntohs(a.sin_port);
}

enum class IoResult { Ok, Reset, Error };

struct Session {
    uint64_t id = 0;
    sockaddr_in client = {};
    bool open = false;  // the remote end exists
    UniqueSocket remote;
    std::deque<std::string> queue;  // while the remote end is being opened
    size_t queuedBytes = 0;
    uint64_t lastActivity = 0;
    uint64_t idleMs = 0;
    uint32_t maxPayload = 0;  // 0 = no relay limit
};

// The poll thread's state. Only the poll thread touches it.
class UdpLoop {
public:
    UdpLoop(std::shared_ptr<UdpShared> sp, SOCKET listener)
        : sp_(std::move(sp)), s_(*sp_), listener_(listener), buf_(kUdpBufferBytes) {}

    ~UdpLoop() {
        // The rule is stopping (or its listener failed): every session ends with it.
        s_.stats.udpSessions -= sessions_.size();
        for (const auto& kv : sessions_) s_.stats.droppedDatagrams += kv.second.queue.size();
        sessions_.clear();
        std::lock_guard<std::mutex> lock(s_.resultsMu);
        s_.loopDone = true;
        s_.results.clear();
    }

    void Run() {
        std::vector<WSAPOLLFD> fds;
        std::vector<uint64_t> keys;  // per fd from index 2: the session's client key
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
            if (n == SOCKET_ERROR || (fds[0].revents & POLLNVAL)) {
                Fatal();
                return;
            }
            if (s_.stop.load()) return;
            if (fds[1].revents) DrainWake();
            TakeResults();
            if (fds[0].revents) DrainListener();
            for (size_t i = 2; i < fds.size(); ++i) {
                if (!fds[i].revents) continue;
                const uint64_t key = keys[i - 2];
                auto it = sessions_.find(key);
                // The session may have ended (or been replaced) while this round was handled.
                if (it == sessions_.end() || !it->second.open || it->second.remote.get() != fds[i].fd) continue;
                const IoResult r = DrainRemote(it->second);
                if (r != IoResult::Ok) EndSession(key, r == IoResult::Reset ? fwd_err::kRemoteReset : fwd_err::kInternal);
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

    void EndSession(uint64_t key, const char* code) {
        auto it = sessions_.find(key);
        if (it == sessions_.end()) return;
        Drop(it->second.queue.size());
        sessions_.erase(it);
        --s_.stats.udpSessions;
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

    IoResult SendToRemote(Session& se, const char* data, size_t len) {
        if (se.maxPayload != 0 && len > se.maxPayload) {
            Drop();  // the relay would drop it too, silently
            return IoResult::Ok;
        }
        const int k = send(se.remote.get(), data, static_cast<int>(len), 0);
        if (k == SOCKET_ERROR) {
            const int e = WSAGetLastError();
            Drop();  // this datagram is lost whatever the error
            if (e == WSAECONNRESET || e == WSAENETRESET) return IoResult::Reset;
            if (e == WSAEWOULDBLOCK || e == WSAEMSGSIZE || e == WSAENOBUFS) return IoResult::Ok;
            return IoResult::Error;
        }
        s_.stats.bytesUp += static_cast<uint64_t>(k);
        return IoResult::Ok;
    }

    // Reads what the remote end has and sends it to the client from the listener.
    IoResult DrainRemote(Session& se) {
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
            se.lastActivity = Now();
            const int w = sendto(listener_.get(), buf_.data(), k, 0, reinterpret_cast<const sockaddr*>(&se.client),
                                 sizeof(se.client));
            if (w == SOCKET_ERROR) {
                Drop();
            } else {
                s_.stats.bytesDown += static_cast<uint64_t>(w);
            }
        }
        return IoResult::Ok;
    }

    void DrainListener() {
        for (int i = 0; i < kUdpBurst; ++i) {
            sockaddr_in from = {};
            int fromLen = sizeof(from);
            int k = SOCKET_ERROR;
            int fault = 0;
            if (TakeListenFault(&fault)) {
                WSASetLastError(fault);
            } else {
                k = recvfrom(listener_.get(), buf_.data(), static_cast<int>(buf_.size()), 0,
                             reinterpret_cast<sockaddr*>(&from), &fromLen);
            }
            if (k == SOCKET_ERROR) {
                const int e = WSAGetLastError();
                if (e == WSAEWOULDBLOCK) return;
                if (e == WSAEMSGSIZE) {
                    Drop();
                    continue;
                }
                // Not expected with SIO_UDP_CONNRESET/NETRESET off, and harmless if it comes.
                if (e == WSAECONNRESET || e == WSAENETRESET) continue;
                // Anything else (out of buffers) would come straight back: the listener stays
                // readable. Record it and give the system one slice instead of spinning on it.
                s_.Fail(fwd_err::kInternal);
                WaitForSingleObject(s_.stopEvent, kPollSliceMs);
                return;
            }
            if (fromLen != static_cast<int>(sizeof(from)) || from.sin_family != AF_INET) {
                Drop();
                continue;
            }
            FromClient(from, buf_.data(), static_cast<size_t>(k));
        }
    }

    void FromClient(const sockaddr_in& from, const char* data, size_t len) {
        const uint64_t now = Now();
        const uint64_t key = ClientKey(from);
        auto it = sessions_.find(key);
        if (it == sessions_.end()) {
            NewSession(key, from, data, len, now);
            return;
        }
        Session& se = it->second;
        se.lastActivity = now;
        if (!se.open) {
            Enqueue(se, data, len);
            return;
        }
        const IoResult r = SendToRemote(se, data, len);
        if (r != IoResult::Ok) EndSession(key, r == IoResult::Reset ? fwd_err::kRemoteReset : fwd_err::kInternal);
    }

    void NewSession(uint64_t key, const sockaddr_in& from, const char* data, size_t len, uint64_t now) {
        if (now < failUntil_) {
            // An open failed moments ago: no new request until the cache expires.
            Drop();
            return;
        }
        if (sessions_.size() >= kMaxUdpSessionsPerRule) {
            Drop();
            s_.Fail(fwd_err::kSessionLimit);
            return;
        }
        Session se;
        se.id = ++nextId_;
        se.client = from;
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
            EndSession(key, fwd_err::kInternal);
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
        const uint64_t key = it->first;
        Session& se = it->second;
        const uint64_t now = Now();
        if (!r.code.empty()) {
            if (!s_.stop.load()) {
                s_.Fail(r.code);
                failUntil_ = now + kUdpOpenFailureCacheMs;
            }
            EndSession(key, nullptr);  // its queued datagrams are dropped
            return;
        }
        if (!SetNonBlocking(r.sock.get())) {
            EndSession(key, fwd_err::kInternal);
            return;
        }
        se.remote = std::move(r.sock);
        se.open = true;
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
            const IoResult res = SendToRemote(se, queued.front().data(), queued.front().size());
            queued.pop_front();
            if (res != IoResult::Ok) {
                Drop(queued.size());
                EndSession(key, res == IoResult::Reset ? fwd_err::kRemoteReset : fwd_err::kInternal);
                return;
            }
        }
    }

    void SweepIdle() {
        const uint64_t now = Now();
        std::vector<uint64_t> idle;
        for (const auto& kv : sessions_) {
            const Session& se = kv.second;
            if (se.open && now >= se.lastActivity && now - se.lastActivity >= se.idleMs) idle.push_back(kv.first);
        }
        for (uint64_t key : idle) EndSession(key, nullptr);
    }

    std::shared_ptr<UdpShared> sp_;
    UdpShared& s_;
    UniqueSocket listener_;
    std::vector<char> buf_;
    std::map<uint64_t, Session> sessions_;
    uint64_t nextId_ = 0;
    uint64_t failUntil_ = 0;  // Clock time until which no new session is opened
};

void PollMain(std::shared_ptr<UdpShared> sp, SOCKET listener) {
    UdpLoop loop(sp, listener);
    loop.Run();
}

}  // namespace

namespace testing {

void InjectUdpListenErrors(int count, int wsaError) {
    g_listenFaultError.store(wsaError);
    g_listenFaults.store(count);
}

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
        BOOL one = TRUE;
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_port = htons(static_cast<u_short>(s.rule.listenPort));
        if (setsockopt(l.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one),
                       sizeof(one)) != 0 ||
            InetPtonW(AF_INET, Utf8ToWide(s.rule.listenAddr).c_str(), &a.sin_addr) != 1 ||
            bind(l.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || !SetNonBlocking(l.get()) ||
            !DisableIcmpResets(l.get())) {
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
