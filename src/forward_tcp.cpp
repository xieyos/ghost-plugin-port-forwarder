#include "forward_tcp.h"

#include "util_str.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <chrono>
#include <condition_variable>
#include <exception>
#include <memory>
#include <mutex>
#include <utility>

namespace pf {

struct TcpShared {
    Rule rule;
    ForwardContext ctx;
    RuleStats stats;
    std::atomic<bool> stop{false};
    bool wsaOk = false;

    mutable std::mutex mu;
    std::string status = rule_status::kStopped;
    std::string detail;

    std::mutex aliveMu;
    std::condition_variable aliveCv;
    int alive = 0;  // connection threads

    TcpShared(const Rule& r, ForwardContext c) : rule(r), ctx(std::move(c)) {
        if (!ctx.globalConnections) ctx.globalConnections = std::make_shared<std::atomic<int>>(0);
        // A Winsock reference of our own: a straggler thread may outlive every other user.
        WSADATA d;
        wsaOk = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }
    ~TcpShared() {
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

// Takes one slot of the global limit, or fails when it is full.
bool TryTakeGlobal(std::atomic<int>& g, int max) {
    int cur = g.load();
    do {
        if (cur >= max) return false;
    } while (!g.compare_exchange_weak(cur, cur + 1));
    return true;
}

// Resolves remote.host and tries each address with a kDirectConnectTimeoutMs timeout,
// checking the stop flag every slice. "" and a connected, non-blocking socket, or a code.
std::string ConnectDirect(TcpShared& s, UniqueSocket* out) {
    ADDRINFOW hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    ADDRINFOW* list = nullptr;
    const std::wstring host = Utf8ToWide(s.rule.remoteHost);
    const std::wstring port = std::to_wstring(s.rule.remotePort);
    if (GetAddrInfoW(host.c_str(), port.c_str(), &hints, &list) != 0 || !list) return fwd_err::kResolveFailed;
    std::unique_ptr<ADDRINFOW, decltype(&FreeAddrInfoW)> guard(list, &FreeAddrInfoW);

    for (ADDRINFOW* ai = list; ai; ai = ai->ai_next) {
        if (s.stop.load()) break;
        UniqueSocket c(WSASocketW(ai->ai_family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                  WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
        if (!c || !SetNonBlocking(c.get())) continue;
        if (connect(c.get(), ai->ai_addr, static_cast<int>(ai->ai_addrlen)) != 0 &&
            WSAGetLastError() != WSAEWOULDBLOCK) {
            continue;
        }
        const uint64_t deadline = GetTickCount64() + kDirectConnectTimeoutMs;
        bool connected = false;
        while (!s.stop.load()) {
            const uint64_t now = GetTickCount64();
            if (now >= deadline) break;
            const uint64_t left = deadline - now;
            const DWORD slice = static_cast<DWORD>(left < kPollSliceMs ? left : kPollSliceMs);
            fd_set w;
            fd_set e;
            FD_ZERO(&w);
            FD_ZERO(&e);
            FD_SET(c.get(), &w);
            FD_SET(c.get(), &e);
            timeval tv = {0, static_cast<long>(slice) * 1000};
            const int n = select(0, nullptr, &w, &e, &tv);
            if (n == SOCKET_ERROR) break;
            if (n == 0) continue;
            int err = 0;
            int len = sizeof(err);
            if (FD_ISSET(c.get(), &w) &&
                getsockopt(c.get(), SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 && err == 0) {
                connected = true;
            }
            break;
        }
        if (connected) {
            *out = std::move(c);
            return std::string();
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
            if (FD_ISSET(d->src, &r) && !PumpRead(*d)) return;
            // Written straight after reading (usually possible at once), or when the
            // destination became writable again.
            if (!PumpWrite(*d)) return;
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
        UniqueSocket c(accept(listener.get(), nullptr, nullptr));
        if (!c) continue;  // WSAEWOULDBLOCK, or a connection reset before we took it
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

std::string BindFailureDetail(int wsaError) {
    std::string d = "WSA error " + std::to_string(wsaError);
    switch (wsaError) {
        case WSAEACCES:
            d += ": access denied. Windows may reserve this port (Hyper-V, WSL, Docker): see "
                 "`netsh interface ipv4 show excludedportrange protocol=tcp`; or another program holds "
                 "it exclusively";
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
