#include "forward_tcp.h"

#include "resolve.h"
#include "util_str.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <condition_variable>
#include <exception>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

namespace pf {

struct TcpShared {
    Rule rule;
    ForwardContext ctx;
    RuleStats stats;
    std::atomic<bool> stop{false};
    // Signalled with `stop`: what a thread waits on instead of sleeping (an accept error's
    // pause, a name lookup).
    HANDLE stopEvent = nullptr;
    bool wsaOk = false;

    mutable std::mutex mu;
    std::string status = rule_status::kStopped;
    std::string detail;

    std::mutex aliveMu;
    std::condition_variable aliveCv;
    int alive = 0;  // connection threads

    TcpShared(const Rule& r, ForwardContext c) : rule(r), ctx(std::move(c)) {
        if (!ctx.globalConnections) ctx.globalConnections = std::make_shared<std::atomic<int>>(0);
        stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        // A Winsock reference of our own: a straggler thread may outlive every other user.
        WSADATA d;
        wsaOk = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }
    ~TcpShared() {
        if (stopEvent) CloseHandle(stopEvent);
        if (wsaOk) WSACleanup();
    }
    TcpShared(const TcpShared&) = delete;
    TcpShared& operator=(const TcpShared&) = delete;

    void SetStatus(const std::string& st, const std::string& det) {
        std::lock_guard<std::mutex> lock(mu);
        status = st;
        detail = det;
    }
    std::string Status() const {
        std::lock_guard<std::mutex> lock(mu);
        return status;
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
        if (stats.RecordError(code)) Log(LogLevel::Warn, Who() + ": a connection failed: " + code);
    }

    bool ViaNode() const { return rule.egress != EgressKind::Direct; }
    // "" when this rule may listen.
    std::string NodeAvailability() const {
        if (!ViaNode()) return std::string();
        if (!ctx.tunnel) return rule_status::kNeedsGhost;
        return ctx.tunnel->Availability();
    }
};

namespace {

void SetNoInherit(SOCKET s) { SetHandleInformation(reinterpret_cast<HANDLE>(s), HANDLE_FLAG_INHERIT, 0); }

bool SetNonBlocking(SOCKET s) {
    u_long one = 1;
    return ioctlsocket(s, FIONBIO, &one) == 0;
}

void SetNoDelay(SOCKET s) {
    BOOL one = TRUE;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
}

// Test seam (testing::InjectAcceptErrors): takes one injected fault, if any is left.
bool TakeFault(std::atomic<int>& count, const std::atomic<int>& error, int* out) {
    int cur = count.load();
    while (cur > 0) {
        if (count.compare_exchange_weak(cur, cur - 1)) {
            *out = error.load();
            return true;
        }
    }
    return false;
}

// Takes one slot of the global limit, or fails when it is full.
bool TryTakeGlobal(std::atomic<int>& g, int max) {
    int cur = g.load();
    do {
        if (cur >= max) return false;
    } while (!g.compare_exchange_weak(cur, cur + 1));
    return true;
}

std::atomic<int> g_acceptFaults{0};
std::atomic<int> g_acceptFaultError{0};

// Connects to remote.host the RFC 8305 way. The name is resolved first (a stop cancels the
// lookup, see resolve.h). Then one attempt per address, in the resolver's order: the next
// one starts kStaggerDelayMs after the previous, or at once when the previous failed, and
// earlier attempts keep running -- the first to connect wins and the others are closed.
// kDirectConnectTimeoutMs covers the whole set. Without the stagger a dead first address
// costs the whole budget: "localhost" is ::1 first on most machines, and Windows retries a
// refused loopback connect for about 2 s. "" and a connected, non-blocking socket, or a code.
std::string ConnectDirect(TcpShared& s, UniqueSocket* out) {
    std::vector<ResolvedAddr> addrs;
    const std::string rc = ResolveHost(s.rule.remoteHost, s.rule.remotePort, SOCK_STREAM, s.stopEvent, &addrs);
    if (!rc.empty()) return rc;
    InterleaveFamilies(&addrs);

    std::vector<UniqueSocket> pending;
    size_t next = 0;
    const uint64_t deadline = GetTickCount64() + kDirectConnectTimeoutMs;
    uint64_t nextStartAt = 0;  // the first attempt starts at once
    while (!s.stop.load()) {
        const uint64_t now = GetTickCount64();
        if (now >= deadline) break;
        if (next < addrs.size() && now >= nextStartAt && pending.size() < FD_SETSIZE) {
            const ResolvedAddr& a = addrs[next++];
            UniqueSocket c(WSASocketW(a.family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                      WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
            if (c && SetNonBlocking(c.get())) {
                if (connect(c.get(), reinterpret_cast<const sockaddr*>(&a.addr), a.len) == 0) {
                    *out = std::move(c);
                    return std::string();
                }
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
                    pending.push_back(std::move(c));
                    nextStartAt = now + kStaggerDelayMs;
                    continue;
                }
            }
            nextStartAt = now;  // this address failed at once: the next one now
            continue;
        }
        if (pending.empty()) {
            if (next >= addrs.size()) break;  // every address failed
            continue;
        }
        uint64_t until = deadline;
        if (next < addrs.size() && nextStartAt < until) until = nextStartAt;
        uint64_t waitMs = until > now ? until - now : 0;
        if (waitMs > kPollSliceMs) waitMs = kPollSliceMs;
        fd_set w;
        fd_set e;
        FD_ZERO(&w);
        FD_ZERO(&e);
        for (const UniqueSocket& p : pending) {
            FD_SET(p.get(), &w);
            FD_SET(p.get(), &e);
        }
        timeval tv = {0, static_cast<long>(waitMs) * 1000};
        const int n = select(0, nullptr, &w, &e, &tv);
        if (n == SOCKET_ERROR) break;
        for (size_t i = 0; n > 0 && i < pending.size();) {
            const SOCKET ps = pending[i].get();
            const bool writable = FD_ISSET(ps, &w) != 0;
            if (!writable && !FD_ISSET(ps, &e)) {
                ++i;
                continue;
            }
            int err = 0;
            int len = sizeof(err);
            if (writable && getsockopt(ps, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 &&
                err == 0) {
                *out = std::move(pending[i]);
                return std::string();  // the other attempts close with `pending`
            }
            pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(i));
            nextStartAt = 0;  // a failed attempt starts the next one at once
        }
    }
    return fwd_err::kConnectFailed;
}

// One direction of a connection.
struct Direction {
    SOCKET src = INVALID_SOCKET;
    SOCKET dst = INVALID_SOCKET;
    std::unique_ptr<char[]> buf;
    size_t len = 0;  // bytes in buf
    size_t off = 0;  // bytes of buf already sent
    bool srcEof = false;
    bool shut = false;  // dst got shutdown(SD_SEND): this direction is finished
    std::atomic<uint64_t>* counter = nullptr;
};

// Reads what `d.src` has when the buffer is empty. False on a connection error.
bool PumpRead(Direction& d) {
    if (d.srcEof || d.len != 0) return true;
    const int n = recv(d.src, d.buf.get(), static_cast<int>(kPumpBufferBytes), 0);
    if (n > 0) {
        d.len = static_cast<size_t>(n);
        d.off = 0;
        return true;
    }
    if (n == 0) {
        d.srcEof = true;
        return true;
    }
    return WSAGetLastError() == WSAEWOULDBLOCK;
}

// Sends what is buffered; forwards EOF once everything was sent. False on an error.
bool PumpWrite(Direction& d) {
    while (d.off < d.len) {
        const int n = send(d.dst, d.buf.get() + d.off, static_cast<int>(d.len - d.off), 0);
        if (n > 0) {
            d.off += static_cast<size_t>(n);
            *d.counter += static_cast<uint64_t>(n);
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) return true;
        return false;
    }
    d.len = d.off = 0;
    if (d.srcEof && !d.shut) {
        // Half-close: the other side learns that no more is coming, and can still answer.
        if (shutdown(d.dst, SD_SEND) != 0) return false;
        d.shut = true;
    }
    return true;
}

// One side of the connection failed. Best effort, within one slice: hand the healthy side
// (d.dst) what is still buffered for it; then make its close abortive, so that it sees a
// reset -- the stream did not end, it broke. (A direction already shut forwarded a real EOF
// and has nothing buffered; the close is made abortive all the same.)
void FlushToHealthy(TcpShared& s, Direction& d) {
    if (!d.shut && d.off < d.len) {
        size_t sent = 0;
        detail::FlushBuffered(d.dst, d.buf.get() + d.off, d.len - d.off, kPollSliceMs, &s.stop, &sent);
        *d.counter += sent;
        d.off += sent;
    }
    linger abort = {1, 0};
    setsockopt(d.dst, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&abort), sizeof(abort));
}

// Moves bytes both ways until both directions ended (graceful), an error, or a stop.
void Pump(TcpShared& s, SOCKET client, SOCKET remote) {
    if (!SetNonBlocking(client) || !SetNonBlocking(remote)) {
        s.Fail(fwd_err::kInternal);
        return;
    }
    SetNoDelay(client);
    SetNoDelay(remote);
    Direction up;
    up.src = client;
    up.dst = remote;
    up.buf.reset(new char[kPumpBufferBytes]);
    up.counter = &s.stats.bytesUp;
    Direction down;
    down.src = remote;
    down.dst = client;
    down.buf.reset(new char[kPumpBufferBytes]);
    down.counter = &s.stats.bytesDown;
    Direction* dirs[2] = {&up, &down};

    while (!s.stop.load()) {
        if (up.shut && down.shut) return;
        fd_set r;
        fd_set w;
        FD_ZERO(&r);
        FD_ZERO(&w);
        for (Direction* d : dirs) {
            if (!d->srcEof && d->len == 0) FD_SET(d->src, &r);
            if (d->off < d->len) FD_SET(d->dst, &w);
        }
        // Not reachable (a direction that neither reads nor writes has finished), but a
        // select() with no socket at all fails rather than waits.
        if (r.fd_count == 0 && w.fd_count == 0) return;
        timeval tv = {0, static_cast<long>(kPollSliceMs) * 1000};
        const int n = select(0, r.fd_count ? &r : nullptr, w.fd_count ? &w : nullptr, nullptr, &tv);
        if (n == SOCKET_ERROR) return;
        for (Direction* d : dirs) {
            Direction* other = d == &up ? &down : &up;
            if (FD_ISSET(d->src, &r) && !PumpRead(*d)) {
                FlushToHealthy(s, *d);  // d->src failed; d->dst is the healthy side
                return;
            }
            // Written straight after reading (usually possible at once), or when the
            // destination became writable again.
            if (!PumpWrite(*d)) {
                FlushToHealthy(s, *other);  // d->dst failed; other->dst (== d->src) is healthy
                return;
            }
        }
    }
}

struct ConnectionExit {
    TcpShared& s;
    ~ConnectionExit() {
        --s.stats.activeConnections;
        --*s.ctx.globalConnections;
        std::lock_guard<std::mutex> lock(s.aliveMu);
        --s.alive;
        s.aliveCv.notify_all();
    }
};

void ConnectionMain(std::shared_ptr<TcpShared> sp, SOCKET clientSock) {
    TcpShared& s = *sp;
    ConnectionExit exitGuard{s};
    UniqueSocket client(clientSock);
    try {
        UniqueSocket remote;
        std::string code;
        if (!s.ViaNode()) {
            code = ConnectDirect(s, &remote);
        } else if (!s.ctx.tunnel) {
            code = rule_status::kNeedsGhost;
        } else {
            TunnelResult t = s.ctx.tunnel->Open(s.rule.egress, s.rule.nodeId, Proto::Tcp, s.rule.remoteHost,
                                                s.rule.remotePort);
            code = t.code;
            remote = std::move(t.sock);
            if (code.empty() && !remote) code = fwd_err::kInternal;
        }
        if (!code.empty()) {
            // Fail closed: the client connection is closed (by `client` going out of scope)
            // and nothing else is tried. A failure caused by our own stop is not an error.
            if (!s.stop.load()) s.Fail(code);
            return;
        }
        if (s.stop.load()) return;
        s.stats.NoteSuccess();
        Pump(s, client.get(), remote.get());
    } catch (...) {
        if (!s.stop.load()) s.Fail(fwd_err::kInternal);
    }
}

void AcceptLoop(std::shared_ptr<TcpShared> sp, SOCKET listenSock) {
    TcpShared& s = *sp;
    UniqueSocket listener(listenSock);
    while (!s.stop.load()) {
        const std::string avail = s.NodeAvailability();
        if (!avail.empty()) {
            // Ghost became unusable while we listened (a 401): stop listening, and say why.
            s.SetStatus(avail, std::string());
            s.Log(LogLevel::Warn, s.Who() + " stopped listening: " + avail);
            return;
        }
        fd_set r;
        FD_ZERO(&r);
        FD_SET(listener.get(), &r);
        timeval tv = {0, static_cast<long>(kPollSliceMs) * 1000};
        const int n = select(0, &r, nullptr, nullptr, &tv);
        if (n == SOCKET_ERROR) {
            s.Fail(fwd_err::kInternal);
            s.SetStatus(rule_status::kStopped, fwd_err::kInternal);
            return;
        }
        if (n == 0) continue;
        SOCKET accepted = INVALID_SOCKET;
        int fault = 0;
        if (TakeFault(g_acceptFaults, g_acceptFaultError, &fault)) {
            WSASetLastError(fault);
        } else {
            accepted = accept(listener.get(), nullptr, nullptr);
        }
        UniqueSocket c(accepted);
        if (!c) {
            const int e = WSAGetLastError();
            // Nothing to take after all, or a connection reset before we took it.
            if (e == WSAEWOULDBLOCK || e == WSAECONNRESET) continue;
            // Anything else (out of buffers, out of handles) would come straight back: the
            // listener stays readable. Record it and give the system one slice instead of
            // spinning on it.
            s.Fail(fwd_err::kInternal);
            WaitForSingleObject(s.stopEvent, kPollSliceMs);
            continue;
        }
        SetNoInherit(c.get());
        if (s.stop.load()) break;

        // Only this thread increments activeConnections, so check-then-increment is exact;
        // the global counter is shared by every rule and taken with a compare-exchange.
        if (s.stats.activeConnections.load() >= static_cast<uint64_t>(s.rule.maxConnections) ||
            !TryTakeGlobal(*s.ctx.globalConnections, s.ctx.globalMax)) {
            ++s.stats.rejectedConnections;
            s.Fail(fwd_err::kConnectionLimit);
            continue;  // `c` closes
        }
        ++s.stats.activeConnections;
        ++s.stats.totalConnections;
        {
            std::lock_guard<std::mutex> lock(s.aliveMu);
            ++s.alive;
        }
        const SOCKET raw = c.Release();
        try {
            std::thread([sp, raw] {
                try {
                    ConnectionMain(sp, raw);
                } catch (...) {
                }
            }).detach();
        } catch (...) {
            // No thread: undo what ConnectionMain's exit would have undone.
            closesocket(raw);
            --s.stats.activeConnections;
            --*s.ctx.globalConnections;
            {
                std::lock_guard<std::mutex> lock(s.aliveMu);
                --s.alive;
                s.aliveCv.notify_all();
            }
            s.Fail(fwd_err::kInternal);
        }
    }
}

}  // namespace

namespace detail {

bool FlushBuffered(SOCKET dst, const char* data, size_t len, DWORD budgetMs, const std::atomic<bool>* stop,
                   size_t* sent) {
    *sent = 0;
    const uint64_t deadline = GetTickCount64() + budgetMs;
    while (*sent < len) {
        if (stop && stop->load()) return false;
        const uint64_t now = GetTickCount64();
        if (now >= deadline) return false;
        fd_set w;
        FD_ZERO(&w);
        FD_SET(dst, &w);
        const uint64_t left = deadline - now;
        timeval tv = {static_cast<long>(left / 1000), static_cast<long>(left % 1000) * 1000};
        const int ready = select(0, nullptr, &w, nullptr, &tv);
        if (ready == SOCKET_ERROR) return false;
        if (ready == 0) continue;
        const int n = send(dst, data + *sent, static_cast<int>(len - *sent), 0);
        if (n > 0) {
            *sent += static_cast<size_t>(n);
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        return false;
    }
    return true;
}

}  // namespace detail

namespace testing {

void InjectAcceptErrors(int count, int wsaError) {
    g_acceptFaultError.store(wsaError);
    g_acceptFaults.store(count);
}

}  // namespace testing

std::string BindFailureDetail(int wsaError, Proto proto) {
    std::string d = "WSA error " + std::to_string(wsaError);
    switch (wsaError) {
        case WSAEACCES:
            d += std::string(": access denied. Windows may reserve this port (Hyper-V, WSL, Docker): see "
                             "`netsh interface ipv4 show excludedportrange protocol=") +
                 ProtoName(proto) + "`; or another program holds it exclusively";
            break;
        case WSAEADDRINUSE:
            d += ": the address is already in use by another program";
            break;
        case WSAEADDRNOTAVAIL:
            d += ": the address does not belong to this machine (any more)";
            break;
        default:
            break;
    }
    return d;
}

TcpForwarder::TcpForwarder(const Rule& rule, ForwardContext ctx)
    : s_(std::make_shared<TcpShared>(rule, std::move(ctx))) {}

TcpForwarder::~TcpForwarder() {
    // Connection threads are detached and own what they use; only the accept thread is ours.
    SignalStop();
    if (accept_.joinable()) accept_.join();
}

const Rule& TcpForwarder::rule() const { return s_->rule; }

void TcpForwarder::Start() {
    TcpShared& s = *s_;
    if (s.rule.proto != Proto::Tcp) {
        s.SetStatus(rule_status::kNotSupported, std::string());
        return;
    }
    const std::string avail = s.NodeAvailability();
    if (!avail.empty()) {
        // A via-node rule that cannot get a tunnel does not listen: a client must not be
        // accepted only to be closed every time.
        s.SetStatus(avail, std::string());
        s.Log(LogLevel::Warn, s.Who() + " is not listening: " + avail);
        return;
    }
    if (!s.wsaOk) {
        s.SetStatus(rule_status::kBindFailed, fwd_err::kInternal);
        return;
    }

    // Overlapped like every other socket here (accepted sockets inherit it): on a
    // non-overlapped socket handle, blocking calls are serialised against each other.
    UniqueSocket l(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
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
            bind(l.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(l.get(), SOMAXCONN) != 0 ||
            !SetNonBlocking(l.get())) {
            err = WSAGetLastError();
            if (err == 0) err = WSAEINVAL;
        }
    }
    if (err != 0) {
        const std::string detail = BindFailureDetail(err);
        s.SetStatus(rule_status::kBindFailed, detail);
        s.stats.RecordError(fwd_err::kBindFailed);
        s.Log(LogLevel::Warn, s.Who() + " cannot listen on " + s.rule.listenAddr + ":" +
                                  std::to_string(s.rule.listenPort) + ": " + detail);
        return;
    }

    s.SetStatus(rule_status::kListening, std::string());
    const SOCKET raw = l.Release();
    try {
        accept_ = std::thread([sp = s_, raw] {
            try {
                AcceptLoop(sp, raw);
            } catch (...) {
            }
        });
    } catch (...) {
        closesocket(raw);
        s.SetStatus(rule_status::kStopped, fwd_err::kInternal);
        return;
    }
    s.Log(LogLevel::Info,
          s.Who() + " listening on " + s.rule.listenAddr + ":" + std::to_string(s.rule.listenPort));
}

void TcpForwarder::SignalStop() {
    s_->stop.store(true);
    if (s_->stopEvent) SetEvent(s_->stopEvent);
    std::lock_guard<std::mutex> lock(s_->mu);
    if (s_->status == rule_status::kListening) s_->status = rule_status::kStopped;
}

bool TcpForwarder::WaitStopped(uint64_t deadlineTick) {
    // The accept thread notices the flag within one poll slice.
    if (accept_.joinable()) accept_.join();
    std::unique_lock<std::mutex> lock(s_->aliveMu);
    for (;;) {
        if (s_->alive == 0) return true;
        const uint64_t now = GetTickCount64();
        if (now >= deadlineTick) return false;
        s_->aliveCv.wait_for(lock, std::chrono::milliseconds(deadlineTick - now));
    }
}

RuleStatus TcpForwarder::Snapshot() const {
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

int TcpForwarder::ThreadsAlive() const {
    std::lock_guard<std::mutex> lock(s_->aliveMu);
    return s_->alive;
}

}  // namespace pf
