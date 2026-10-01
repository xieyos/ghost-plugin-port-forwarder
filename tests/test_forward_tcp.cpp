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
#include "test_support.h"
#include "tunnel_client.h"
#include "tunnel_source.h"

#include <memory>
#include <mutex>
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

// A port that was free a moment ago (bound to 127.0.0.1:0, then released).
int FreePort() {
    pf_test::LoopbackListener l;
    if (!pf_test::ListenLoopback(&l)) return 0;
    return l.port;
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

    explicit GhostRig(bool permitted = true) {
        CHECK(echo.Start());
        CHECK(fg.Start());
        fg.MapHost("echo.test", echo.port());
        GhostApiOptions o;
        o.apiBase = fg.apiBase();
        o.token = "tok-forward";
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
    const int port = FreePort();
    e.Apply({MakeRule("r_000000000000000a", port, "127.0.0.1", echo.port())});
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
        const int port = FreePort();
        e.Apply({MakeRule("r_000000000000000b", port, "127.0.0.1", echo.port(), EgressKind::Direct, "", 2)});
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
        const int p1 = FreePort();
        const int p2 = FreePort();
        e.Apply({MakeRule("r_000000000000000c", p1, "127.0.0.1", echo.port()),
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
    const int pNode = FreePort();
    const int pActive = FreePort();
    e.Apply({MakeRule("r_0000000000000010", pNode, "echo.test", 7, EgressKind::Node, "n1"),
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
    rig.fg.SetTunnelError("upstream_unreachable");
    const int port = FreePort();
    // The remote is the echo server's own address: a direct fallback would reach it.
    const std::string remote = "127.0.0.1";
    e.Apply({MakeRule("r_0000000000000020", port, remote, rig.echo.port(), EgressKind::Node, "n1")});
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
        const int port = FreePort();
        Rule disabled = MakeRule("r_0000000000000031", FreePort(), "127.0.0.1", 9);
        disabled.enabled = false;
        e.Apply({MakeRule("r_0000000000000030", port, "echo.test", 7, EgressKind::Node, "n1"), disabled});
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
        const int port = FreePort();
        e.Apply({MakeRule("r_0000000000000032", port, "echo.test", 7, EgressKind::Active)});
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
        const int port = FreePort();
        const int directPort = FreePort();
        e.Apply({MakeRule("r_0000000000000033", port, "echo.test", 7, EgressKind::Node, "n1"),
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
        e.Apply({MakeRule("r_0000000000000033", port, "echo.test", 7, EgressKind::Node, "n1"),
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
    e.Apply({MakeRule("r_0000000000000040", holder.port, "127.0.0.1", 9)});
    const auto s = Find(e, "r_0000000000000040");
    CHECK(s.status == S::kBindFailed);
    CHECK_MSG(s.detail.rfind("WSA error 10048", 0) == 0, s.detail.c_str());
    CHECK(s.stats.lastError.code == pf::fwd_err::kBindFailed);
    CHECK(pf::BindFailureDetail(10013).find("netsh interface ipv4 show excludedportrange protocol=tcp") !=
          std::string::npos);
}

void TestStopIsBounded() {
    GhostRig rig;
    rig.fg.SetTunnelDelayMs(8000);  // a tunnel request that Ghost answers slowly
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    const int pDirect = FreePort();
    const int pNode = FreePort();
    e.Apply({MakeRule("r_0000000000000050", pDirect, "127.0.0.1", rig.echo.port()),
             MakeRule("r_0000000000000051", pNode, "echo.test", 7, EgressKind::Node, "n1")});
    UniqueSocket live = Connect(pDirect);
    CHECK(live.valid() && RoundTrip(live.get(), "live"));
    UniqueSocket waiting = Connect(pNode);
    CHECK(waiting.valid());
    CHECK(pf_test::WaitUntil([&] { return rig.fg.TunnelsInProgress() == 1; }, 5000));

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    std::printf("Stop() took %llu ms\n", took);
    // Not the 2 s budget: the tunnel request Ghost has not answered is aborted
    // (TunnelSource::Shutdown), so its thread is done well before that.
    CHECK_MSG(took < 1000, "Stop() returns within 1 s while a tunnel request is stuck");
    CHECK_MSG(e.StragglerThreads() == 0, "no thread is left behind");
    CHECK_MSG(ClosedByPeer(live.get()), "Stop closes the open connection");
    CHECK_MSG(ClosedByPeer(waiting.get()), "and the one whose tunnel never came");
    CHECK(Refused(pDirect));
    CHECK(e.Snapshot().empty());
    CHECK(rig.echo.Connections() == 1);  // only the direct one
}

// A thread the engine cannot reach still does not hold Stop() past its budget, and it
// finishes on its own later. Name resolution is the real case; here it is a 429 backoff
// inside the API client, which nothing but GhostApi::Shutdown wakes.
void TestStopLeavesStragglerBehind() {
    GhostRig rig;
    rig.fg.Set429Always(true);
    EngineOptions o;
    o.tunnel = rig.source;
    o.stopBudgetMs = 500;
    Engine e(o);
    const int pNode = FreePort();
    e.Apply({MakeRule("r_0000000000000052", pNode, "echo.test", 7, EgressKind::Node, "n1")});
    UniqueSocket waiting = Connect(pNode);
    CHECK(waiting.valid());
    // After the fourth 429 the client backs off for at least 2 s (250 ms doubling), far
    // past the 500 ms budget.
    CHECK(pf_test::WaitUntil([&] { return rig.fg.CountPath(kTunnel) >= 4; }, 10000));

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    CHECK_MSG(took < 1500, "Stop() keeps to its budget");
    CHECK_MSG(e.StragglerThreads() == 1, "the thread in the backoff is left running");
    rig.api->Shutdown();  // what the app does after the log's last batch
    CHECK(pf_test::WaitUntil([&] { return e.StragglerThreads() == 0; }, 5000));
    CHECK(ClosedByPeer(waiting.get()));
    CHECK(rig.echo.Connections() == 0);
}

void TestApplyRestartsOnlyChanged() {
    TcpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    const int pa = FreePort();
    const int pb = FreePort();
    Rule a = MakeRule("r_0000000000000060", pa, "127.0.0.1", echo.port());
    Rule b = MakeRule("r_0000000000000061", pb, "127.0.0.1", echo.port());
    e.Apply({a, b});
    UniqueSocket ca = Connect(pa);
    UniqueSocket cb = Connect(pb);
    CHECK(ca.valid() && RoundTrip(ca.get(), "a1"));
    CHECK(cb.valid() && RoundTrip(cb.get(), "b1"));

    b.name = "renamed";  // a change in any field restarts that rule
    e.Apply({a, b});
    CHECK_MSG(ClosedByPeer(cb.get()), "the changed rule's connection is closed");
    CHECK_MSG(RoundTrip(ca.get(), "a2"), "the unchanged rule's long connection survives");
    CHECK(Find(e, "r_0000000000000060").stats.totalConnections == 1);
    CHECK(Find(e, "r_0000000000000060").stats.bytesUp == 4);
    CHECK(Find(e, "r_0000000000000061").stats.totalConnections == 0);  // fresh counters
    UniqueSocket cb2 = Connect(pb);
    CHECK(cb2.valid() && RoundTrip(cb2.get(), "b2"));

    // Removing a rule stops it; the other is untouched again.
    e.Apply({a});
    CHECK(ClosedByPeer(cb2.get()));
    CHECK(pf_test::WaitUntil([&] { return Refused(pb); }, 5000));
    CHECK(RoundTrip(ca.get(), "a3"));
    CHECK(e.Snapshot().size() == 1);
    e.Stop();
}

}  // namespace

int main() {
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
    return pf_test::TestExitCode();
}
