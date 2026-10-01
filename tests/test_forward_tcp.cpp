// Functional: TCP forwarding over real loopback sockets (forward_tcp.h, engine.h).
//
// Direct rules forward to a local echo server; via-node rules go through the fake Ghost,
// which connects to the echo server itself and hands the socket over the way Ghost does.
// Covered: a round trip with half-close (the client shuts down its sending side and still
// receives every echoed byte, then EOF), exact byte counters, the per-rule and the global
// connection limits, the exact tunnel request, fail-closed (a refused tunnel closes the
// client and the destination sees ZERO connections), the via-node statuses that keep a
// rule from listening, bind failures, Stop() within its budget while a tunnel request is
// stuck, and Apply() restarting only the rule that changed.

#include "echo_servers.h"
#include "engine.h"
#include "fake_ghost.h"
#include "forward_tcp.h"
#include "gate_clock.h"
#include "port_reserve.h"
#include "test_support.h"
#include "tunnel_client.h"
#include "tunnel_source.h"

#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

using pf::ClientTunnelSource;
using pf::EgressKind;
using pf::Engine;
using pf::EngineOptions;
using pf::GhostApi;
using pf::GhostApiOptions;
using pf::json;
using pf::LogFields;
using pf::LogLevel;
using pf::Rule;
using pf::RuleStatus;
using pf::TunnelClient;
using pf::TunnelClientOptions;
using pf::UniqueSocket;
using pf_test::FakeGhost;
using pf_test::TcpEchoServer;
namespace S = pf::rule_status;

namespace {

const char* kTunnel = "/api/upstream/tunnel";

// A port held for TCP and UDP until Apply() below lets go of it (port_reserve.h).
int FreePort() { return pf_test::ReservePort(); }

// Engine::Apply, after releasing the rules' reserved listen ports.
void Apply(Engine& e, const std::vector<Rule>& rules) {
    pf_test::ReleasePorts(rules);
    e.Apply(rules);
}

std::string Describe(const RuleStatus& r) {
    const auto& st = r.stats;
    return r.id + " " + r.status + (r.detail.empty() ? "" : "(" + r.detail + ")") +
           " active=" + std::to_string(st.activeConnections) + " total=" + std::to_string(st.totalConnections) +
           " rejected=" + std::to_string(st.rejectedConnections) + " up=" + std::to_string(st.bytesUp) +
           " down=" + std::to_string(st.bytesDown) + " lastError=" + st.lastError.code + "x" +
           std::to_string(st.lastError.count);
}

std::string Describe(const Engine& e) {
    std::string out = "engine: global=" + std::to_string(e.GlobalConnections()) +
                      " stragglers=" + std::to_string(e.StragglerThreads());
    for (const RuleStatus& r : e.Snapshot()) out += "; " + Describe(r);
    return out;
}

Rule MakeRule(const char* id, int listenPort, const std::string& host, int remotePort,
              EgressKind egress = EgressKind::Direct, const std::string& nodeId = std::string(), int maxConn = 128) {
    Rule r;
    r.id = id;
    r.name = std::string("rule ") + id;
    r.enabled = true;
    r.proto = pf::Proto::Tcp;
    r.listenAddr = "127.0.0.1";
    r.listenPort = listenPort;
    r.remoteHost = host;
    r.remotePort = remotePort;
    r.egress = egress;
    r.nodeId = nodeId;
    r.maxConnections = maxConn;
    return r;
}

// Connects to 127.0.0.1:port; a 5 s receive timeout so a test never hangs on a recv.
// WSA_FLAG_OVERLAPPED although nothing here is overlapped: on a socket created without it,
// blocking calls on one handle are serialised, so a send on one thread waits behind a recv
// on another -- and the half-close case does exactly that.
UniqueSocket Connect(int port) {
    UniqueSocket s(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return s;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    if (connect(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return UniqueSocket();
    DWORD tmo = 5000;
    setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    return s;
}

bool SendAll(SOCKET s, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        const int n = send(s, data.data() + off, static_cast<int>(data.size() - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool RecvExactly(SOCKET s, size_t n, std::string* out) {
    out->clear();
    char buf[8192];
    while (out->size() < n) {
        const int want = static_cast<int>(n - out->size() < sizeof(buf) ? n - out->size() : sizeof(buf));
        const int k = recv(s, buf, want, 0);
        if (k <= 0) return false;
        out->append(buf, static_cast<size_t>(k));
    }
    return true;
}

bool RoundTrip(SOCKET s, const std::string& msg) {
    std::string got;
    return SendAll(s, msg) && RecvExactly(s, msg.size(), &got) && got == msg;
}

// Reads until the peer ends the stream. True only for a clean EOF (recv == 0) -- not a
// reset and not the receive timeout.
bool RecvUntilEof(SOCKET s, std::string* out) {
    out->clear();
    char buf[16384];
    for (;;) {
        const int k = recv(s, buf, sizeof(buf), 0);
        if (k == 0) return true;
        if (k < 0) return false;
        out->append(buf, static_cast<size_t>(k));
    }
}

// The connection was closed by the other side: EOF or a reset, NOT the receive timeout.
bool ClosedByPeer(SOCKET s) {
    char buf[64];
    for (;;) {
        const int k = recv(s, buf, sizeof(buf), 0);
        if (k == 0) return true;
        if (k > 0) continue;
        const int e = WSAGetLastError();
        return e == WSAECONNRESET || e == WSAECONNABORTED;
    }
}

// Nothing listens on 127.0.0.1:port. Windows retries a refused connect for about 2 s;
// TCP_MAXRTMS cuts that short (the answer is a RST either way, never a timeout on loopback).
bool Refused(int port) {
    UniqueSocket s(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return false;
    DWORD maxRtMs = 300;
    setsockopt(s.get(), IPPROTO_TCP, TCP_MAXRTMS, reinterpret_cast<const char*>(&maxRtMs), sizeof(maxRtMs));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    return connect(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0;
}

// Nothing holds 127.0.0.1:port for TCP (an exclusive bind succeeds). Unlike Refused(), it
// never connects, so it cannot start a connection on a listener that is still there.
bool CanBindTcp(int port) {
    UniqueSocket t(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!t) return false;
    BOOL one = TRUE;
    setsockopt(t.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    return bind(t.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
}

RuleStatus Find(const Engine& e, const std::string& id) {
    for (const auto& s : e.Snapshot()) {
        if (s.id == id) return s;
    }
    return RuleStatus();
}

std::string Pattern(size_t n) {
    std::string s(n, '\0');
    for (size_t i = 0; i < n; ++i) s[i] = static_cast<char>((i * 131 + i / 7) & 0xff);
    return s;
}

// Collects log lines from any thread.
struct LogSink {
    std::mutex mu;
    std::vector<std::string> lines;
    pf::LogFn Fn() {
        return [this](LogLevel, const std::string& text, const LogFields& fields) {
            std::lock_guard<std::mutex> lock(mu);
            std::string line = text;
            for (const auto& f : fields) line += " " + f.first + "=" + f.second;
            lines.push_back(line);
        };
    }
    bool AnyContains(const std::string& needle) {
        std::lock_guard<std::mutex> lock(mu);
        for (const auto& l : lines) {
            if (l.find(needle) != std::string::npos) return true;
        }
        return false;
    }
};

// A fake Ghost with an echo server behind "echo.test", and the tunnel source over it.
struct GhostRig {
    TcpEchoServer echo;
    FakeGhost fg;
    std::shared_ptr<GhostApi> api;
    std::shared_ptr<TunnelClient> tc;
    std::shared_ptr<pf::TunnelSource> source;

    explicit GhostRig(bool permitted = true, pf::Clock* clock = nullptr) {
        CHECK(echo.Start());
        CHECK(fg.Start());
        fg.MapHost("echo.test", echo.port());
        GhostApiOptions o;
        o.apiBase = fg.apiBase();
        o.token = "tok-forward";
        if (clock) {
            o.clock = clock;
            o.ratePerSec = 1e6;  // a bucket wait would land in the gate
            o.burst = 1e6;
        }
        api = std::make_shared<GhostApi>(o);
        TunnelClientOptions t;
        t.api = api.get();
        t.permitted = permitted;
        tc = std::make_shared<TunnelClient>(t);
        source = std::make_shared<ClientTunnelSource>(api, tc, permitted);
    }
};

// ---------------------------------------------------------------------------------------

void TestDirectHalfCloseAndCounters() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    LogSink log;
    EngineOptions o;
    o.log = log.Fn();
    Engine e(o);
    pf_test::FailureContext ctx_([&] { return Describe(e); });
    const int port = FreePort();
    Apply(e, {MakeRule("r_000000000000000a", port, "127.0.0.1", echo.port())});
    CHECK(Find(e, "r_000000000000000a").status == S::kListening);

    // 1 MB up while reading the echo: the payload is far larger than both 64 KB buffers and
    // the socket buffers, so it only gets through if the pump really streams both ways.
    const std::string payload = Pattern(1024 * 1024 + 17);
    UniqueSocket c = Connect(port);
    CHECK(c.valid());
    std::string clientPort;
    {
        sockaddr_in me = {};
        int len = sizeof(me);
        if (getsockname(c.get(), reinterpret_cast<sockaddr*>(&me), &len) == 0) {
            clientPort = ":" + std::to_string(ntohs(me.sin_port));
        }
    }
    bool sent = false;
    std::thread sender([&] {
        sent = SendAll(c.get(), payload);
        // Half-close: no more from the client, yet it must still receive everything.
        shutdown(c.get(), SD_SEND);
    });
    std::string got;
    const bool eof = RecvUntilEof(c.get(), &got);
    sender.join();
    CHECK(sent);
    CHECK_MSG(eof, "the client sees a clean EOF after its half-close is forwarded and answered");
    CHECK_MSG(got == payload, "every echoed byte arrives after the client's half-close");
    c.Reset();

    CHECK(pf_test::WaitUntil([&] { return Find(e, "r_000000000000000a").stats.activeConnections == 0; }, 5000));
    const auto st = Find(e, "r_000000000000000a").stats;
    CHECK(st.totalConnections == 1);
    CHECK_MSG(st.bytesUp == payload.size(), "bytesUp is exact");
    CHECK_MSG(st.bytesDown == payload.size(), "bytesDown is exact");
    CHECK(st.rejectedConnections == 0);
    CHECK(st.lastError.code.empty());
    CHECK(echo.Connections() == 1);

    // A small exchange the other way round: the reply comes after the half-close.
    UniqueSocket c2 = Connect(port);
    CHECK(c2.valid());
    CHECK(SendAll(c2.get(), "ping"));
    CHECK(shutdown(c2.get(), SD_SEND) == 0);
    CHECK(RecvUntilEof(c2.get(), &got));
    CHECK(got == "ping");
    c2.Reset();
    CHECK(pf_test::WaitUntil(
        [&] {
            const auto s = Find(e, "r_000000000000000a").stats;
            return s.activeConnections == 0 && s.bytesUp == payload.size() + 4 && s.bytesDown == payload.size() + 4;
        },
        5000));
    CHECK(Find(e, "r_000000000000000a").stats.totalConnections == 2);

    CHECK_MSG(!clientPort.empty() && !log.AnyContains(clientPort), "no client address in the log");
    e.Stop();
    CHECK(Refused(port));
}

void TestConnectionLimits() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    {
        Engine e(EngineOptions{});
        pf_test::FailureContext ctx_([&] { return Describe(e); });
        const int port = FreePort();
        Apply(e, {MakeRule("r_000000000000000b", port, "127.0.0.1", echo.port(), EgressKind::Direct, "", 2)});
        UniqueSocket a = Connect(port);
        UniqueSocket b = Connect(port);
        CHECK(a.valid() && b.valid());
        CHECK(RoundTrip(a.get(), "a"));
        CHECK(RoundTrip(b.get(), "b"));
        UniqueSocket over = Connect(port);  // accepted by the backlog, then closed by us
        CHECK(over.valid());
        CHECK_MSG(ClosedByPeer(over.get()), "the third connection over maxConnections=2 is closed");
        auto st = Find(e, "r_000000000000000b").stats;
        CHECK(st.rejectedConnections == 1);
        CHECK(st.lastError.code == pf::fwd_err::kConnectionLimit);
        CHECK(st.totalConnections == 2);
        CHECK(echo.Connections() == 2);

        // A slot frees when a connection ends.
        a.Reset();
        CHECK(pf_test::WaitUntil([&] { return Find(e, "r_000000000000000b").stats.activeConnections == 1; }, 5000));
        UniqueSocket again = Connect(port);
        CHECK(again.valid());
        CHECK_MSG(RoundTrip(again.get(), "again"), "a connection is accepted again below the limit");
    }
    {
        // The global limit is shared by every rule.
        EngineOptions o;
        o.globalMaxConnections = 1;
        Engine e(o);
        pf_test::FailureContext ctx_([&] { return Describe(e); });
        const int p1 = FreePort();
        const int p2 = FreePort();
        Apply(e, {MakeRule("r_000000000000000c", p1, "127.0.0.1", echo.port()),
                 MakeRule("r_000000000000000d", p2, "127.0.0.1", echo.port())});
        UniqueSocket a = Connect(p1);
        CHECK(a.valid() && RoundTrip(a.get(), "one"));
        UniqueSocket b = Connect(p2);
        CHECK(b.valid());
        CHECK_MSG(ClosedByPeer(b.get()), "a second rule's connection over the global limit is closed");
        CHECK(Find(e, "r_000000000000000d").stats.rejectedConnections == 1);
        CHECK(e.GlobalConnections() == 1);
    }
}

void TestViaNode() {
    GhostRig rig;
    Engine e([&] {
        EngineOptions o;
        o.tunnel = rig.source;
        return o;
    }());
    pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int pNode = FreePort();
    const int pActive = FreePort();
    Apply(e, {MakeRule("r_0000000000000010", pNode, "echo.test", 7, EgressKind::Node, "n1"),
             MakeRule("r_0000000000000011", pActive, "echo.test", 8443, EgressKind::Active)});
    CHECK(Find(e, "r_0000000000000010").status == S::kListening);
    CHECK(Find(e, "r_0000000000000011").status == S::kListening);

    UniqueSocket c = Connect(pNode);
    CHECK(c.valid());
    CHECK_MSG(RoundTrip(c.get(), "through the node"), "round trip through Ghost's tunnel");
    CHECK(shutdown(c.get(), SD_SEND) == 0);
    std::string rest;
    CHECK_MSG(RecvUntilEof(c.get(), &rest) && rest.empty(), "half-close through the tunnel");
    c.Reset();

    auto reqs = rig.fg.Requests();
    int tunnels = 0;
    json body;
    for (const auto& r : reqs) {
        if (r.path == kTunnel) {
            ++tunnels;
            body = pf::ParseJsonNoThrow(r.body);
        }
    }
    CHECK(tunnels == 1);
    CHECK_MSG(body == json({{"via", "node"}, {"nodeId", "n1"}, {"proto", "tcp"}, {"host", "echo.test"}, {"port", 7}}),
              "the tunnel request carries exactly via/nodeId/proto/host/port");
    CHECK(rig.echo.Connections() == 1);

    UniqueSocket d = Connect(pActive);
    CHECK(d.valid() && RoundTrip(d.get(), "active"));
    d.Reset();
    reqs = rig.fg.Requests();
    CHECK(reqs.size() >= 2 && pf::ParseJsonNoThrow(reqs.back().body) ==
                                  json({{"via", "active"}, {"proto", "tcp"}, {"host", "echo.test"}, {"port", 8443}}));
    CHECK(pf_test::WaitUntil(
        [&] {
            const auto s = Find(e, "r_0000000000000010").stats;
            return s.activeConnections == 0 && s.bytesUp == 16 && s.bytesDown == 16;
        },
        5000));
    e.Stop();
}

void TestFailClosed() {
    GhostRig rig;
    LogSink log;
    EngineOptions o;
    o.tunnel = rig.source;
    o.log = log.Fn();
    Engine e(o);
    pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    rig.fg.SetTunnelError("upstream_unreachable");
    const int port = FreePort();
    // The remote is the echo server's own address: a direct fallback would reach it.
    const std::string remote = "127.0.0.1";
    Apply(e, {MakeRule("r_0000000000000020", port, remote, rig.echo.port(), EgressKind::Node, "n1")});
    CHECK(Find(e, "r_0000000000000020").status == S::kListening);

    for (int i = 1; i <= 2; ++i) {
        UniqueSocket c = Connect(port);
        CHECK(c.valid());
        if (c.valid()) {
            send(c.get(), "x", 1, 0);
            CHECK_MSG(ClosedByPeer(c.get()), "a refused tunnel closes the client connection");
        }
        CHECK(pf_test::WaitUntil(
            [&] {
                const auto s = Find(e, "r_0000000000000020").stats;
                return s.totalConnections == static_cast<uint64_t>(i) && s.activeConnections == 0;
            },
            5000));
        const auto st = Find(e, "r_0000000000000020").stats;
        CHECK(st.lastError.code == "upstream_unreachable");
        CHECK(st.lastError.count == static_cast<uint64_t>(i));
        CHECK(st.lastError.atUnixMs > 0);
        CHECK(st.bytesUp == 0 && st.bytesDown == 0);
    }
    CHECK_MSG(rig.echo.Connections() == 0, "fail closed: the destination saw ZERO connections");
    CHECK(rig.fg.CountPath(kTunnel) == 2);
    CHECK(Find(e, "r_0000000000000020").status == S::kListening);
    CHECK(log.AnyContains("upstream_unreachable"));
    e.Stop();
}

void TestNodeStatuses() {
    // Standalone: no Ghost at all.
    {
        Engine e(EngineOptions{});
        pf_test::FailureContext ctx_([&] { return Describe(e); });
        const int port = FreePort();
        Rule disabled = MakeRule("r_0000000000000031", FreePort(), "127.0.0.1", 9);
        disabled.enabled = false;
        Apply(e, {MakeRule("r_0000000000000030", port, "echo.test", 7, EgressKind::Node, "n1"), disabled});
        CHECK(Find(e, "r_0000000000000030").status == S::kNeedsGhost);
        CHECK_MSG(Refused(port), "needs_ghost: the port is not listening");
        CHECK(Find(e, "r_0000000000000031").status == S::kDisabled);
    }
    // upstream.connect not granted.
    {
        GhostRig rig(/*permitted=*/false);
        EngineOptions o;
        o.tunnel = rig.source;
        Engine e(o);
        pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
        const int port = FreePort();
        Apply(e, {MakeRule("r_0000000000000032", port, "echo.test", 7, EgressKind::Active)});
        CHECK(Find(e, "r_0000000000000032").status == S::kPermissionMissing);
        CHECK(Refused(port));
        CHECK(rig.fg.CountPath(kTunnel) == 0);
    }
    // Ghost answers 401: the connection is closed and the rule stops listening.
    {
        GhostRig rig;
        EngineOptions o;
        o.tunnel = rig.source;
        Engine e(o);
        pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
        const int port = FreePort();
        const int directPort = FreePort();
        Apply(e, {MakeRule("r_0000000000000033", port, "echo.test", 7, EgressKind::Node, "n1"),
                 MakeRule("r_0000000000000034", directPort, "127.0.0.1", rig.echo.port())});
        CHECK(Find(e, "r_0000000000000033").status == S::kListening);
        rig.fg.SetUnauthorized(true);
        UniqueSocket c = Connect(port);
        CHECK(c.valid() && ClosedByPeer(c.get()));
        CHECK(pf_test::WaitUntil([&] { return Find(e, "r_0000000000000033").status == S::kGhostUnavailable; },
                                 5000));
        CHECK(Find(e, "r_0000000000000033").stats.lastError.code == pf::api_err::kGhostUnavailable);
        CHECK(pf_test::WaitUntil([&] { return Refused(port); }, 5000));
        // A direct rule does not depend on Ghost.
        UniqueSocket d = Connect(directPort);
        CHECK(d.valid() && RoundTrip(d.get(), "direct still works"));
        // And a via-node rule applied now does not listen at all.
        const int later = FreePort();
        Apply(e, {MakeRule("r_0000000000000033", port, "echo.test", 7, EgressKind::Node, "n1"),
                 MakeRule("r_0000000000000034", directPort, "127.0.0.1", rig.echo.port()),
                 MakeRule("r_0000000000000035", later, "echo.test", 7, EgressKind::Active)});
        CHECK(Find(e, "r_0000000000000035").status == S::kGhostUnavailable);
        CHECK(Refused(later));
    }
}

void TestBindFailure() {
    pf_test::LoopbackListener holder;
    CHECK(pf_test::ListenLoopback(&holder));
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx_([&] { return Describe(e); });
    Apply(e, {MakeRule("r_0000000000000040", holder.port, "127.0.0.1", 9)});
    const auto s = Find(e, "r_0000000000000040");
    CHECK(s.status == S::kBindFailed);
    CHECK_MSG(s.detail.rfind("WSA error 10048", 0) == 0, s.detail.c_str());
    CHECK(s.stats.lastError.code == pf::fwd_err::kBindFailed);
    CHECK(pf::BindFailureDetail(10013).find("netsh interface ipv4 show excludedportrange protocol=tcp") !=
          std::string::npos);
}

// Stop() aborts a tunnel request Ghost has not answered (TunnelSource::Shutdown), so its
// thread is done well within the budget. Ghost's answer is 60 s away and the budget is 5 s:
// returning before the budget proves the abort, whatever the machine's load.
void TestStopIsBounded() {
    GhostRig rig;
    rig.fg.SetTunnelDelayMs(60000);
    EngineOptions o;
    o.tunnel = rig.source;
    o.stopBudgetMs = 5000;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int pDirect = FreePort();
    const int pNode = FreePort();
    Apply(e, {MakeRule("r_0000000000000050", pDirect, "127.0.0.1", rig.echo.port()),
              MakeRule("r_0000000000000051", pNode, "echo.test", 7, EgressKind::Node, "n1")});
    UniqueSocket live = Connect(pDirect);
    CHECK(live.valid() && RoundTrip(live.get(), "live"));
    UniqueSocket waiting = Connect(pNode);
    CHECK(waiting.valid());
    CHECK_UNTIL(rig.fg.TunnelsInProgress() == 1, 5000, rig.fg.Describe());

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    std::printf("   Stop() took %llu ms\n", took);
    CHECK_MSG(took < 5000, "Stop() returns before its budget while a tunnel request is stuck");
    CHECK_EQ(e.StragglerThreads(), 0);
    CHECK_MSG(ClosedByPeer(live.get()), "Stop closes the open connection");
    CHECK_MSG(ClosedByPeer(waiting.get()), "and the one whose tunnel never came");
    CHECK_UNTIL(rig.fg.ClientClosedDuringDelay() == 1, 5000, rig.fg.Describe());
    CHECK(Refused(pDirect));
    CHECK(e.Snapshot().empty());
    CHECK_EQ(rig.echo.Connections(), 1);  // only the direct one
}

// A thread the engine cannot reach still does not hold Stop() past its budget, and it
// finishes on its own later. Name resolution is the real case; here it is a 429 backoff
// inside the API client, which nothing but GhostApi::Shutdown wakes. The gate clock keeps
// the thread in that backoff until the test lets it go, and says when it is there.
void TestStopLeavesStragglerBehind() {
    pf_test::GateClock gate;
    GhostRig rig(true, &gate);
    rig.fg.Set429Count(1);
    EngineOptions o;
    o.tunnel = rig.source;
    o.stopBudgetMs = 500;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int pNode = FreePort();
    Apply(e, {MakeRule("r_0000000000000052", pNode, "echo.test", 7, EgressKind::Node, "n1")});
    UniqueSocket waiting = Connect(pNode);
    CHECK(waiting.valid());
    CHECK_UNTIL(gate.InWait() == 1, 10000, "threads in the backoff: " + std::to_string(gate.InWait()));

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    CHECK_MSG(took < 5000, "Stop() keeps to its budget");
    CHECK_EQ(e.StragglerThreads(), 1);
    rig.api->Shutdown();  // what the app does after the log's last batch
    CHECK_UNTIL(e.StragglerThreads() == 0, 5000, "stragglers: " + std::to_string(e.StragglerThreads()));
    CHECK(ClosedByPeer(waiting.get()));
    CHECK_EQ(rig.echo.Connections(), 0);
}

void TestApplyRestartsOnlyChanged() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx_([&] { return Describe(e); });
    const int pa = FreePort();
    const int pb = FreePort();
    Rule a = MakeRule("r_0000000000000060", pa, "127.0.0.1", echo.port());
    Rule b = MakeRule("r_0000000000000061", pb, "127.0.0.1", echo.port());
    Apply(e, {a, b});
    UniqueSocket ca = Connect(pa);
    UniqueSocket cb = Connect(pb);
    CHECK(ca.valid() && RoundTrip(ca.get(), "a1"));
    CHECK(cb.valid() && RoundTrip(cb.get(), "b1"));

    b.name = "renamed";  // a change in any field restarts that rule
    Apply(e, {a, b});
    CHECK_MSG(ClosedByPeer(cb.get()), "the changed rule's connection is closed");
    CHECK_MSG(RoundTrip(ca.get(), "a2"), "the unchanged rule's long connection survives");
    CHECK(Find(e, "r_0000000000000060").stats.totalConnections == 1);
    CHECK(Find(e, "r_0000000000000060").stats.bytesUp == 4);
    CHECK(Find(e, "r_0000000000000061").stats.totalConnections == 0);  // fresh counters
    UniqueSocket cb2 = Connect(pb);
    CHECK(cb2.valid() && RoundTrip(cb2.get(), "b2"));

    // Removing a rule stops it; the other is untouched again.
    Apply(e, {a});
    CHECK(ClosedByPeer(cb2.get()));
    CHECK(pf_test::WaitUntil([&] { return Refused(pb); }, 5000));
    CHECK(RoundTrip(ca.get(), "a3"));
    CHECK(e.Snapshot().size() == 1);
    e.Stop();
}


// "localhost" resolves to ::1 first on most machines, while the destination listens on
// 127.0.0.1 only; [::1]:<port> is held by a socket that is bound but not listening, so a
// connect there is refused for certain -- and Windows retries a refused loopback connect for
// about 2 s, the whole connect budget. Tried one after another the addresses therefore fail
// (the IPv4 attempt never starts in time); staggered (RFC 8305), the IPv4 attempt starts
// 250 ms later and wins. Success itself is the proof; no timing bound.
void TestDirectStaggeredConnect() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    bool v6First = false;
    {
        ADDRINFOW hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        ADDRINFOW* list = nullptr;
        if (GetAddrInfoW(L"localhost", L"80", &hints, &list) == 0 && list) {
            v6First = list->ai_family == AF_INET6;
            FreeAddrInfoW(list);
        }
    }
    std::printf("   localhost resolves %s first\n", v6First ? "::1" : "127.0.0.1");
    CHECK_MSG(v6First, "this machine resolves localhost to ::1 first (otherwise the case proves nothing)");
    UniqueSocket v6(WSASocketW(AF_INET6, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    sockaddr_in6 a6 = {};
    a6.sin6_family = AF_INET6;
    a6.sin6_addr = in6addr_loopback;
    a6.sin6_port = htons(echo.port());
    CHECK_MSG(v6.valid() && bind(v6.get(), reinterpret_cast<sockaddr*>(&a6), sizeof(a6)) == 0,
              "[::1]:<echo port> is held (bound, not listening)");

    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreePort();
    Apply(e, {MakeRule("r_0000000000000070", port, "localhost", echo.port())});
    const ULONGLONG t0 = GetTickCount64();
    UniqueSocket c = Connect(port);
    CHECK_MSG(c.valid() && RoundTrip(c.get(), "staggered"), "connected through localhost despite a dead ::1");
    std::printf("   connected through localhost in %llu ms\n", GetTickCount64() - t0);
    CHECK_EQ(echo.Connections(), 1);
    e.Stop();
}

// Every way a tunnel can fail closes the client and never reaches the destination.
void TestFailClosedRows() {
    // The remote is the echo server's own address: a direct fallback would reach it.
    struct Row {
        const char* name;
        std::function<void(FakeGhost&)> setup;
        std::string code;
    };
    const std::vector<Row> rows = {
        {"answer dropped", [](FakeGhost& fg) { fg.SetTunnelDrop(true); }, pf::api_err::kGhostUnreachable},
        {"malformed protocolInfo",
         [](FakeGhost& fg) {
             fg.SetTunnelFixedBody(R"({"status":"ok","proto":"tcp","protocolInfo":"!!not base64!!",)"
                                   R"("protocolInfoBytes":628,"node":{"id":"n1","name":"N","type":"socks5"}})");
         },
         pf::api_err::kBadResponse},
    };
    for (const Row& row : rows) {
        GhostRig rig;
        row.setup(rig.fg);
        EngineOptions o;
        o.tunnel = rig.source;
        Engine e(o);
        pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
        const int port = FreePort();
        Apply(e, {MakeRule("r_0000000000000071", port, "127.0.0.1", rig.echo.port(), EgressKind::Node, "n1")});
        UniqueSocket c = Connect(port);
        CHECK_MSG(c.valid() && ClosedByPeer(c.get()), row.name);
        CHECK(pf_test::WaitUntil([&] { return Find(e, "r_0000000000000071").stats.lastError.code == row.code; },
                                 5000));
        CHECK_MSG(Find(e, "r_0000000000000071").stats.lastError.code == row.code, row.name);
        CHECK_MSG(rig.echo.Connections() == 0, row.name);
        CHECK(rig.fg.CountPath(kTunnel) == 1);
        e.Stop();
    }
    // Stop while the tunnel request is on the wire.
    {
        GhostRig rig;
        rig.fg.SetTunnelDelayMs(8000);
        EngineOptions o;
        o.tunnel = rig.source;
        Engine e(o);
        pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
        const int port = FreePort();
        Apply(e, {MakeRule("r_0000000000000072", port, "127.0.0.1", rig.echo.port(), EgressKind::Node, "n1")});
        UniqueSocket c = Connect(port);
        CHECK(c.valid());
        CHECK(pf_test::WaitUntil([&] { return rig.fg.TunnelsInProgress() == 1; }, 5000));
        e.Stop();
        CHECK(ClosedByPeer(c.get()));
        CHECK_MSG(rig.echo.Connections() == 0, "stop during the request: the destination saw ZERO connections");
    }
}

// lastError.count is the number of failures in a row: a connection that works ends the run.
void TestSuccessEndsErrorRun() {
    GhostRig rig;
    rig.fg.QueueTunnelErrors({"upstream_unreachable", "upstream_unreachable"});
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    pf_test::FailureContext ctx_([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreePort();
    const std::string id = "r_0000000000000073";
    Apply(e, {MakeRule(id.c_str(), port, "echo.test", 7, EgressKind::Node, "n1")});
    for (int i = 0; i < 2; ++i) {
        UniqueSocket c = Connect(port);
        CHECK(c.valid() && ClosedByPeer(c.get()));
    }
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.lastError.count == 2; }, 5000));
    UniqueSocket ok = Connect(port);
    CHECK(ok.valid() && RoundTrip(ok.get(), "works"));
    ok.Reset();
    rig.fg.SetTunnelError("upstream_unreachable");
    UniqueSocket c = Connect(port);
    CHECK(c.valid() && ClosedByPeer(c.get()));
    CHECK(pf_test::WaitUntil(
        [&] {
            const auto st = Find(e, id).stats;
            return st.totalConnections == 4 && st.activeConnections == 0;
        },
        5000));
    const auto st = Find(e, id).stats;
    CHECK(st.lastError.code == "upstream_unreachable");
    CHECK_MSG(st.lastError.count == 1, "a success between failures starts a new run");
    e.Stop();
}

// A rule that is not listening (here: its port was taken) is started again when the same
// rule set is applied again, instead of being kept as it is.
void TestReapplyRetriesBind() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    auto holder = std::make_unique<pf_test::LoopbackListener>();
    CHECK(pf_test::ListenLoopback(holder.get()));
    const int port = holder->port;
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx_([&] { return Describe(e); });
    const Rule r = MakeRule("r_0000000000000074", port, "127.0.0.1", echo.port());
    Apply(e, {r});
    CHECK(Find(e, r.id).status == S::kBindFailed);
    holder.reset();
    Apply(e, {r});
    CHECK_MSG(Find(e, r.id).status == S::kListening, "re-applying an unchanged bind_failed rule retries the bind");
    UniqueSocket c = Connect(port);
    CHECK(c.valid() && RoundTrip(c.get(), "bound now"));
    e.Stop();
}

// Stop() called while Apply() is stopping a rule whose connection thread cannot be woken
// (a 429 backoff inside the API client, held there by the gate clock) keeps to its own
// budget. Apply's own budget is 60 s here, so its wait can only end because Stop() asked:
// without that, Stop() would wait for the lock about a minute. A second, unchanged rule has
// a stuck connection too, so Stop() has its own budget to wait out.
void TestStopDuringApply() {
    pf_test::GateClock gate;
    GhostRig rig(true, &gate);
    rig.fg.Set429Always(true);
    LogSink log;
    EngineOptions o;
    o.tunnel = rig.source;
    o.log = log.Fn();
    o.stopBudgetMs = 2000;
    o.applyStopBudgetMs = 60000;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int p1 = FreePort();
    const int p2 = FreePort();
    const int p3 = FreePort();
    Rule r = MakeRule("r_0000000000000075", p1, "echo.test", 7, EgressKind::Node, "n1");
    const Rule kept = MakeRule("r_0000000000000076", p3, "echo.test", 7, EgressKind::Node, "n1");
    Apply(e, {r, kept});
    UniqueSocket waiting = Connect(p1);
    UniqueSocket waiting2 = Connect(p3);
    CHECK(waiting.valid() && waiting2.valid());
    CHECK_UNTIL(gate.InWait() == 2, 10000, "threads in the backoff: " + std::to_string(gate.InWait()));

    r.listenPort = p2;  // changed: Apply stops the old forwarder and waits for its thread
    std::thread applier([&] { Apply(e, {r, kept}); });
    // Apply is in its wait once the old listener is gone. (Probed by binding, not by
    // connecting: a connect could still be accepted and start one more thread.)
    CHECK_UNTIL(CanBindTcp(p1), 5000, Describe(e));
    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    applier.join();
    std::printf("   Stop() during Apply() took %llu ms\n", took);
    CHECK_MSG(took < 10000, "Stop() during Apply() does not wait out Apply's own budget");
    CHECK_MSG(Refused(p2), "the changed rule is not listening after Stop()");
    CHECK_MSG(!log.AnyContains("listening on 127.0.0.1:" + std::to_string(p2)),
              "Apply() started nothing once Stop() was requested");
    CHECK(e.Snapshot().empty());
    CHECK_EQ(e.StragglerThreads(), 2);
    rig.api->Shutdown();
    CHECK_UNTIL(e.StragglerThreads() == 0, 5000, "stragglers: " + std::to_string(e.StragglerThreads()));
    CHECK_EQ(rig.echo.Connections(), 0);
}


// An accept error that is neither "nothing to take" nor "reset" (out of buffers) is recorded
// and followed by a one-slice pause, not retried at once: the listener stays readable, so an
// immediate retry spins. Four injected failures therefore delay the connection by about
// four slices, and the rule keeps listening.
void TestAcceptErrorsDoNotSpin() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx_([&] { return Describe(e); });
    const int port = FreePort();
    const std::string id = "r_0000000000000077";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", echo.port())});
    pf::testing::InjectAcceptErrors(4, WSAENOBUFS);
    const ULONGLONG t0 = GetTickCount64();
    UniqueSocket c = Connect(port);
    CHECK(c.valid() && RoundTrip(c.get(), "after the errors"));
    const ULONGLONG took = GetTickCount64() - t0;
    pf::testing::InjectAcceptErrors(0, 0);
    std::printf("   accepted after four errors in %llu ms\n", took);
    CHECK_MSG(took >= 4 * pf::kPollSliceMs - 100, "each accept error is followed by a pause of one slice");
    const auto s = Find(e, id);
    CHECK(s.status == S::kListening);
    CHECK(s.stats.lastError.code == pf::fwd_err::kInternal);
    CHECK(s.stats.lastError.count == 4);
    e.Stop();
}

// A connected loopback pair: `server` is the accepted end, non-blocking.
struct Pair {
    pf_test::LoopbackListener listener;
    UniqueSocket client;
    UniqueSocket server;
    explicit Pair(int clientRcvBuf = 0) {
        CHECK(pf_test::ListenLoopback(&listener));
        client.Reset(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
        if (clientRcvBuf > 0) {
            setsockopt(client.get(), SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&clientRcvBuf),
                       sizeof(clientRcvBuf));
        }
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(listener.port);
        CHECK(connect(client.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
        server.Reset(accept(listener.sock, nullptr, nullptr));
        u_long one = 1;
        CHECK(server.valid() && ioctlsocket(server.get(), FIONBIO, &one) == 0);
        if (clientRcvBuf > 0) {
            // Loopback otherwise buffers tens of megabytes on the sending side.
            setsockopt(server.get(), SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char*>(&clientRcvBuf),
                       sizeof(clientRcvBuf));
        }
    }
};

// What the pump does for the healthy side when the other side fails: hand it what is
// buffered, within a budget -- and, without a reader, stop when the budget runs out.
void TestFlushBuffered() {
    {
        Pair p;
        const std::string data = Pattern(1024 * 1024 + 3);
        std::string got;
        bool eof = false;
        std::thread reader([&] { eof = RecvUntilEof(p.client.get(), &got); });
        size_t sent = 0;
        const bool all = pf::detail::FlushBuffered(p.server.get(), data.data(), data.size(), 10000, nullptr, &sent);
        shutdown(p.server.get(), SD_SEND);  // the test's own end of the stream
        reader.join();
        CHECK(all);
        CHECK_EQ(sent, data.size());
        CHECK_MSG(eof && got == data, "the reader gets every buffered byte");
    }
    {
        // Nobody reads, and the server's send backlog is already full: the budget runs out.
        // (Windows accepts a whole non-blocking send of any size while the backlog is below
        // its limit, so the backlog is filled first with small sends until WSAEWOULDBLOCK.)
        Pair p(8 * 1024);
        const std::string chunk = Pattern(16 * 1024);
        std::string prefilled;
        for (int i = 0; i < 64 * 1024; ++i) {
            const int n = send(p.server.get(), chunk.data(), static_cast<int>(chunk.size()), 0);
            if (n <= 0) break;
            prefilled.append(chunk.data(), static_cast<size_t>(n));
        }
        CHECK_EQ(WSAGetLastError(), WSAEWOULDBLOCK);
        const std::string data = Pattern(1024 * 1024);
        size_t sent = 0;
        const ULONGLONG t0 = GetTickCount64();
        const bool all = pf::detail::FlushBuffered(p.server.get(), data.data(), data.size(), 200, nullptr, &sent);
        const ULONGLONG took = GetTickCount64() - t0;
        CHECK(!all && sent < data.size());
        CHECK_MSG(took >= 150, "the flush waits for its budget");
        DWORD tmo = 1500;
        setsockopt(p.client.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
        std::string got;
        CHECK_MSG(!RecvUntilEof(p.client.get(), &got), "the flush itself sends no EOF");
        CHECK_EQ(got.size(), prefilled.size() + sent);
        CHECK(got.substr(prefilled.size()) == data.substr(0, sent));
    }
}

// A connection that breaks (here: the destination resets it) is not passed on as a clean
// EOF: the client's side is closed abortively and sees a reset. A real EOF still arrives as
// an EOF (TestDirectHalfCloseAndCounters).
void TestErrorReachesClientAsReset() {
    pf_test::LoopbackListener dest;
    CHECK(pf_test::ListenLoopback(&dest));
    std::thread server([&] {
        SOCKET c = accept(dest.sock, nullptr, nullptr);
        if (c == INVALID_SOCKET) return;
        char b[16];
        recv(c, b, sizeof(b), 0);  // the client's first bytes arrived through the pump
        linger abort = {1, 0};
        setsockopt(c, SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&abort), sizeof(abort));
        closesocket(c);  // RST
    });
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreePort();
    Apply(e, {MakeRule("r_0000000000000078", port, "127.0.0.1", dest.port)});
    UniqueSocket c = Connect(port);
    CHECK(c.valid() && SendAll(c.get(), "hello"));
    server.join();
    char buf[16];
    int n = 0;
    int err = 0;
    for (;;) {
        n = recv(c.get(), buf, sizeof(buf), 0);
        if (n <= 0) {
            err = n < 0 ? WSAGetLastError() : 0;
            break;
        }
    }
    CHECK_MSG(n < 0 && (err == WSAECONNRESET || err == WSAECONNABORTED),
              ("the client sees a reset, not a clean EOF (recv " + std::to_string(n) + ", error " +
               std::to_string(err) + ")")
                  .c_str());
    e.Stop();
}

}  // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    // A line per case, flushed: when a case hangs, the CTest log says which.
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("== %s\n", name);
        std::fflush(stdout);
        const ULONGLONG t0 = GetTickCount64();
        fn();
        std::printf("   (%llu ms)\n", GetTickCount64() - t0);
    };
    run("direct, half-close, counters", TestDirectHalfCloseAndCounters);
    run("connection limits", TestConnectionLimits);
    run("via a node", TestViaNode);
    run("fail closed", TestFailClosed);
    run("via-node statuses", TestNodeStatuses);
    run("bind failure", TestBindFailure);
    run("stop is bounded", TestStopIsBounded);
    run("stop leaves a straggler behind", TestStopLeavesStragglerBehind);
    run("apply restarts only the changed rule", TestApplyRestartsOnlyChanged);
    run("direct: staggered connect", TestDirectStaggeredConnect);
    run("fail closed rows", TestFailClosedRows);
    run("a success ends the error run", TestSuccessEndsErrorRun);
    run("re-apply retries a failed bind", TestReapplyRetriesBind);
    run("stop during apply", TestStopDuringApply);
    run("accept errors do not spin", TestAcceptErrorsDoNotSpin);
    run("flush buffered", TestFlushBuffered);
    run("an error reaches the client as a reset", TestErrorReachesClientAsReset);
    return pf_test::TestExitCode();
}
