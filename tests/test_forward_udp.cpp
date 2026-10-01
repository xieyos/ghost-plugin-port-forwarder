// Functional: UDP forwarding over real loopback sockets (forward_udp.h, engine.h).
//
// Direct rules forward to a local UDP echo server; via-node rules go through the fake Ghost,
// which hands over one end of a connected loopback UDP pair and echoes on the other (no
// proxy protocol anywhere). Covered:
//   * sessions: two clients of one rule without crosstalk (a session is the full source
//     address, not the IP); on a 0.0.0.0 listener the local address is part of the key;
//     idle reclaim, counting only datagrams actually forwarded; the per-rule session cap;
//   * relays: the exact tunnel request, one association per session, datagrams queued
//     while the relay is opened (both bounds, made deterministic with a gate on the fake's
//     answer), Ghost's maxPayload, the plugin-wide relay cap refused locally;
//   * fail closed: the destination sees ZERO datagrams for every way a relay can fail;
//     the failed-open cache only for node-level codes, 1 s doubling, never for capacity or
//     transport answers; a reset from a torn-down relay ends the session;
//   * direct addresses: "localhost" IPv4 first; failover from a dead ::1 with the sent
//     datagrams replayed, then sticky; per-client backoff after a reset before any reply;
//   * statuses, bind failures and retries, listener errors that do not spin;
//   * Stop() within its budget while a relay request is stuck; a straggler left behind.
//
// Time-driven behaviour (idleness, the caches, backoff) runs on a FakeClock that the test
// advances; the forwarder's poll thread reads it every slice. Threads stuck in a 429 backoff
// are held by a GateClock (gate_clock.h).

#include "echo_servers.h"
#include "engine.h"
#include "fake_clock.h"
#include "fake_ghost.h"
#include "forward_udp.h"
#include "gate_clock.h"
#include "port_reserve.h"
#include "resolve.h"
#include "test_support.h"
#include "tunnel_client.h"
#include "tunnel_source.h"

#include <mswsock.h>

#include <functional>
#include <memory>
#include <mutex>
#include <string>
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
using pf_test::FakeClock;
using pf_test::FakeGhost;
using pf_test::UdpEchoServer;
namespace S = pf::rule_status;

namespace {

const char* kTunnel = "/api/upstream/tunnel";

// A port held for TCP and UDP until Apply() below lets go of it (port_reserve.h).
int FreeUdpPort() { return pf_test::ReservePort(); }

// Engine::Apply, after releasing the rules' reserved listen ports.
void Apply(Engine& e, const std::vector<Rule>& rules) {
    pf_test::ReleasePorts(rules);
    e.Apply(rules);
}

// Nothing holds 127.0.0.1:port for UDP (an exclusive bind succeeds).
bool CanBindUdp(int port, int family = AF_INET) {
    UniqueSocket s(WSASocketW(family, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return false;
    BOOL one = TRUE;
    setsockopt(s.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
    if (family == AF_INET6) {
        sockaddr_in6 a = {};
        a.sin6_family = AF_INET6;
        a.sin6_addr = in6addr_loopback;
        a.sin6_port = htons(static_cast<u_short>(port));
        return bind(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
    }
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    return bind(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
}

Rule MakeRule(const char* id, int listenPort, const std::string& host, int remotePort,
              EgressKind egress = EgressKind::Direct, const std::string& nodeId = std::string(), int idleSec = 60) {
    Rule r;
    r.id = id;
    r.name = std::string("rule ") + id;
    r.enabled = true;
    r.proto = pf::Proto::Udp;
    r.listenAddr = "127.0.0.1";
    r.listenPort = listenPort;
    r.remoteHost = host;
    r.remotePort = remotePort;
    r.egress = egress;
    r.nodeId = nodeId;
    r.udpIdleSec = idleSec;
    return r;
}

// A client: an unconnected UDP socket on 127.0.0.1:<ephemeral>.
class UdpClient {
public:
    // WSA_FLAG_OVERLAPPED although nothing here is overlapped: without it SO_RCVTIMEO is
    // ignored on a WSASocketW socket and a receive that gets nothing blocks forever.
    UdpClient() {
        s_.Reset(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0,
                            WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
        if (!s_) return;
        BOOL off = FALSE;
        DWORD bytes = 0;
        WSAIoctl(s_.get(), SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr);
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int len = sizeof(a);
        if (bind(s_.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
            getsockname(s_.get(), reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            s_.Reset();
            return;
        }
        port_ = ntohs(a.sin_port);
    }
    bool ok() const { return s_.valid(); }
    unsigned short port() const { return port_; }

    bool SendTo(const char* ip, int toPort, const std::string& msg) {
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        InetPtonA(AF_INET, ip, &a.sin_addr);
        a.sin_port = htons(static_cast<u_short>(toPort));
        return sendto(s_.get(), msg.data(), static_cast<int>(msg.size()), 0, reinterpret_cast<sockaddr*>(&a),
                      sizeof(a)) == static_cast<int>(msg.size());
    }
    bool Send(int toPort, const std::string& msg) { return SendTo("127.0.0.1", toPort, msg); }
    // One datagram within `ms`; `fromPort`/`fromIp` (if given) receive its source.
    bool Recv(std::string* out, DWORD ms, int* fromPort = nullptr, std::string* fromIp = nullptr) {
        setsockopt(s_.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
        std::vector<char> buf(65536);
        sockaddr_in from = {};
        int len = sizeof(from);
        const int n =
            recvfrom(s_.get(), buf.data(), static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&from), &len);
        if (n < 0) return false;
        out->assign(buf.data(), static_cast<size_t>(n));
        if (fromPort) *fromPort = ntohs(from.sin_port);
        if (fromIp) {
            char text[32] = {};
            InetNtopA(AF_INET, &from.sin_addr, text, sizeof(text));
            *fromIp = text;
        }
        return true;
    }
    // Sends `msg` to `toPort` and expects exactly it back, from `toPort`.
    bool RoundTrip(int toPort, const std::string& msg) {
        std::string got;
        int from = 0;
        return Send(toPort, msg) && Recv(&got, 3000, &from) && got == msg && from == toPort;
    }
    // Nothing arrives within `ms`.
    bool Silent(DWORD ms) {
        std::string got;
        return !Recv(&got, ms);
    }

private:
    UniqueSocket s_;
    unsigned short port_ = 0;
};

RuleStatus Find(const Engine& e, const std::string& id) {
    for (const auto& s : e.Snapshot()) {
        if (s.id == id) return s;
    }
    return RuleStatus();
}

std::string Describe(const RuleStatus& r) {
    const auto& st = r.stats;
    return r.id + " " + r.status + (r.detail.empty() ? "" : "(" + r.detail + ")") +
           " sessions=" + std::to_string(st.udpSessions) + " total=" + std::to_string(st.totalConnections) +
           " dropped=" + std::to_string(st.droppedDatagrams) + " up=" + std::to_string(st.bytesUp) +
           " down=" + std::to_string(st.bytesDown) + " lastError=" + st.lastError.code + "x" +
           std::to_string(st.lastError.count);
}

std::string Describe(const Engine& e) {
    std::string out = "engine: stragglers=" + std::to_string(e.StragglerThreads()) +
                      " failovers=" + std::to_string(pf::testing::UdpFailovers());
    for (const RuleStatus& r : e.Snapshot()) out += "; " + Describe(r);
    return out;
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

// A fake Ghost and the tunnel source over it. With a clock (the gate clock), the API client
// uses it and its token bucket never waits.
struct GhostRig {
    FakeGhost fg;
    std::shared_ptr<GhostApi> api;
    std::shared_ptr<TunnelClient> tc;
    std::shared_ptr<pf::TunnelSource> source;

    explicit GhostRig(pf::Clock* clock = nullptr) {
        CHECK(fg.Start());
        GhostApiOptions o;
        o.apiBase = fg.apiBase();
        o.token = "tok-forward-udp";
        if (clock) {
            o.clock = clock;
            o.ratePerSec = 1e6;  // a bucket wait would land in the gate
            o.burst = 1e6;
        }
        api = std::make_shared<GhostApi>(o);
        TunnelClientOptions t;
        t.api = api.get();
        t.permitted = true;
        tc = std::make_shared<TunnelClient>(t);
        source = std::make_shared<ClientTunnelSource>(api, tc, true);
    }
};

std::vector<json> TunnelBodies(const FakeGhost& fg) {
    std::vector<json> out;
    for (const auto& r : fg.Requests()) {
        if (r.path == kTunnel) out.push_back(pf::ParseJsonNoThrow(r.body));
    }
    return out;
}

// A manual-reset event, closed with the scope.
struct Event {
    HANDLE h = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ~Event() {
        if (h) CloseHandle(h);
    }
};

// ---------------------------------------------------------------------------------------

void TestCacheableCodes() {
    for (const char* c : {"upstream_udp_unavailable", "upstream_unreachable", "upstream_not_found", "upstream_invalid",
                          "upstream_timeout", "upstream_auth_failed", "upstream_refused", "permission_denied",
                          "tunnel_unsupported", "resolve_failed"}) {
        CHECK_MSG(pf::IsCacheableOpenFailure(c), c);
    }
    for (const char* c : {"tunnel_limit", "rate_limited", "session_limit", "ghost_unreachable", "bad_response",
                          "tunnel_failed", "tunnel_unavailable", "plugin_not_running", "cancelled", "connect_failed",
                          "internal_error", ""}) {
        CHECK_MSG(!pf::IsCacheableOpenFailure(c), c);
    }
}

// RFC 8305 family interleaving (resolve.h), on families alone.
void TestInterleaveFamilies() {
    auto order = [](std::vector<int> families) {
        std::vector<pf::ResolvedAddr> v;
        for (size_t i = 0; i < families.size(); ++i) {
            pf::ResolvedAddr a;
            a.family = families[i];
            a.len = static_cast<int>(i);  // marks the original position
            v.push_back(a);
        }
        pf::InterleaveFamilies(&v);
        std::string out;
        for (const auto& a : v) out += (a.family == AF_INET6 ? "6" : "4") + std::to_string(a.len) + " ";
        return out;
    };
    CHECK_EQ(order({AF_INET6, AF_INET6, AF_INET, AF_INET}), std::string("60 42 61 43 "));
    CHECK_EQ(order({AF_INET, AF_INET6, AF_INET6, AF_INET6}), std::string("40 61 62 63 "));
    CHECK_EQ(order({AF_INET6, AF_INET6, AF_INET6}), std::string("60 61 62 "));
    CHECK_EQ(order({AF_INET6, AF_INET}), std::string("60 41 "));
}

void TestDirectTwoClients() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    LogSink log;
    EngineOptions o;
    o.log = log.Fn();
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000070";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", echo.port())});
    CHECK_EQ(Find(e, id).status, std::string(S::kListening));

    UdpClient a;
    UdpClient b;
    CHECK(a.ok() && b.ok());
    uint64_t bytes = 0;
    for (int i = 0; i < 5; ++i) {
        // Both send before either reads: replies must still go to the right client.
        const std::string ma = "from a #" + std::to_string(i);
        const std::string mb = "from b, a longer one #" + std::to_string(i);
        CHECK(a.Send(port, ma));
        CHECK(b.Send(port, mb));
        std::string ga;
        std::string gb;
        int fa = 0;
        int fb = 0;
        CHECK_MSG(a.Recv(&ga, 3000, &fa) && ga == ma, "client a gets its own echo");
        CHECK_MSG(b.Recv(&gb, 3000, &fb) && gb == mb, "client b gets its own echo");
        CHECK_MSG(fa == port && fb == port, "replies come from the rule's listening port");
        bytes += ma.size() + mb.size();
    }
    CHECK_MSG(a.Silent(300) && b.Silent(300), "no crosstalk: nothing else arrives for either client");

    const auto st = Find(e, id).stats;
    CHECK_EQ(st.udpSessions, uint64_t{2});
    CHECK_EQ(st.totalConnections, uint64_t{2});
    CHECK_EQ(echo.DistinctSources(), size_t{2});  // each session has its own remote socket
    CHECK_EQ(echo.Datagrams(), 10);
    CHECK_EQ(st.bytesUp, bytes);
    CHECK_EQ(st.bytesDown, bytes);
    CHECK_EQ(st.droppedDatagrams, uint64_t{0});
    CHECK_EQ(st.lastError.code, std::string());
    CHECK_MSG(!log.AnyContains(std::to_string(a.port())) && !log.AnyContains(std::to_string(b.port())),
              "no client address in the log");
    CHECK_MSG(!log.AnyContains(std::to_string(echo.port())), "no destination in the log");

    e.Stop();
    CHECK_MSG(CanBindUdp(port), "Stop closes the listening socket");
}

void TestIdleReclaim() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    FakeClock clock;
    EngineOptions o;
    o.clock = &clock;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000071";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", echo.port(), EgressKind::Direct, "", 5)});
    UdpClient a;
    CHECK(a.RoundTrip(port, "one"));
    CHECK_EQ(Find(e, id).stats.udpSessions, uint64_t{1});

    clock.Advance(4000);
    CHECK_MSG(!pf_test::WaitUntil([&] { return Find(e, id).stats.udpSessions == 0; }, 600),
              "a session is not reclaimed before udpIdleSec");
    CHECK(a.RoundTrip(port, "still"));  // activity: the idle time starts again
    CHECK_EQ(Find(e, id).stats.totalConnections, uint64_t{1});

    clock.Advance(4999);
    CHECK(!pf_test::WaitUntil([&] { return Find(e, id).stats.udpSessions == 0; }, 600));
    clock.Advance(1);
    CHECK_UNTIL(Find(e, id).stats.udpSessions == 0, 3000, Describe(e));
    CHECK_EQ(Find(e, id).stats.droppedDatagrams, uint64_t{0});

    CHECK_MSG(a.RoundTrip(port, "again"), "the client's next datagram opens a new session");
    CHECK_EQ(Find(e, id).stats.totalConnections, uint64_t{2});
    e.Stop();
}

// Idleness counts datagrams actually forwarded: one dropped (over maxPayload) does not
// keep a session alive.
void TestIdleCountsOnlyForwarded() {
    GhostRig rig;
    rig.fg.SetUdpMaxPayload(100);
    FakeClock clock;
    EngineOptions o;
    o.tunnel = rig.source;
    o.clock = &clock;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000072";
    Apply(e, {MakeRule(id.c_str(), port, "198.51.100.1", 53, EgressKind::Node, "n1", 60)});
    UdpClient a;
    CHECK(a.RoundTrip(port, "x"));
    clock.Advance(50000);
    CHECK(a.Send(port, std::string(101, 'z')));
    CHECK_UNTIL(Find(e, id).stats.droppedDatagrams == 1, 3000, Describe(e));
    clock.Advance(10000);
    CHECK_UNTIL(Find(e, id).stats.udpSessions == 0, 3000, Describe(e));
    e.Stop();
}

void TestSessionCap() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    FakeClock clock;
    EngineOptions o;
    o.clock = &clock;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000073";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", echo.port())});

    std::vector<std::unique_ptr<UdpClient>> clients;
    bool all = true;
    for (size_t i = 0; i < pf::kMaxUdpSessionsPerRule; ++i) {
        clients.push_back(std::make_unique<UdpClient>());
        all = all && clients.back()->RoundTrip(port, "c" + std::to_string(i));
    }
    CHECK_MSG(all, "64 clients each round-trip");
    CHECK_EQ(Find(e, id).stats.udpSessions, uint64_t{pf::kMaxUdpSessionsPerRule});

    UdpClient over;
    CHECK(over.Send(port, "one too many"));
    CHECK_MSG(over.Silent(500), "the 65th client gets no session and no reply");
    CHECK_UNTIL(Find(e, id).stats.droppedDatagrams == 1, 3000, Describe(e));
    auto st = Find(e, id).stats;
    CHECK_EQ(st.lastError.code, std::string(pf::fwd_err::kSessionLimit));
    CHECK_EQ(st.totalConnections, uint64_t{pf::kMaxUdpSessionsPerRule});
    CHECK_MSG(clients[0]->RoundTrip(port, "existing"), "existing sessions are unaffected");
    CHECK_EQ(echo.Datagrams(), static_cast<int>(pf::kMaxUdpSessionsPerRule) + 1);

    // Once sessions go idle there is room again.
    clock.Advance(60000);
    CHECK_UNTIL(Find(e, id).stats.udpSessions == 0, 3000, Describe(e));
    CHECK_MSG(over.RoundTrip(port, "room now"), "below the cap a new client is served");
    e.Stop();
}

void TestViaNode() {
    GhostRig rig;
    Event gate;
    rig.fg.SetUdpMaxPayload(100);
    rig.fg.SetTunnelGate(gate.h);  // the relay is opened only when the test says so
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000074";
    Apply(e, {MakeRule(id.c_str(), port, "198.51.100.7", 5353, EgressKind::Node, "n1")});
    CHECK_EQ(Find(e, id).status, std::string(S::kListening));
    auto dropped = [&] { return Find(e, id).stats.droppedDatagrams; };

    UdpClient a;
    CHECK(a.Send(port, "q1") && a.Send(port, "q2") && a.Send(port, "q3"));
    CHECK_UNTIL(rig.fg.TunnelsInProgress() == 1, 5000, rig.fg.Describe());
    SetEvent(gate.h);
    std::string got;
    std::string seq;
    for (int i = 0; i < 3; ++i) {
        if (a.Recv(&got, 5000)) seq += got + ",";
    }
    CHECK_EQ(seq, std::string("q1,q2,q3,"));  // queued while the relay opened, in order
    auto bodies = TunnelBodies(rig.fg);
    CHECK_EQ(bodies.size(), size_t{1});  // one relay request for one session
    CHECK_MSG(bodies.size() == 1 && bodies[0] == json({{"via", "node"},
                                                       {"nodeId", "n1"},
                                                       {"proto", "udp"},
                                                       {"host", "198.51.100.7"},
                                                       {"port", 5353}}),
              "the relay request carries exactly via/nodeId/proto/host/port");

    // Ghost's maxPayload (100 for this session).
    const int echoedBefore = rig.fg.UdpEchoed();
    CHECK(a.Send(port, std::string(101, 'x')));
    CHECK_UNTIL(dropped() == 1, 3000, Describe(e));
    CHECK_MSG(a.Silent(200), "a datagram over maxPayload is not forwarded");
    CHECK_EQ(rig.fg.UdpEchoed(), echoedBefore);
    CHECK_MSG(a.RoundTrip(port, std::string(100, 'y')), "a datagram of exactly maxPayload is");

    // One association per session: a second client is a second request.
    rig.fg.SetUdpMaxPayload(65000);
    UdpClient b;
    CHECK(b.RoundTrip(port, "b1"));
    CHECK(b.RoundTrip(port, "b2"));
    CHECK_EQ(rig.fg.CountPath(kTunnel), 2);

    // The queue's datagram bound: 40 sent while the relay is held back, 32 forwarded.
    ResetEvent(gate.h);
    UdpClient c;
    for (int i = 0; i < 40; ++i) CHECK(c.Send(port, "c" + std::to_string(i)));
    CHECK_UNTIL(dropped() == 1 + 8, 5000, Describe(e));
    SetEvent(gate.h);
    int received = 0;
    std::string firstAndLast;
    while (c.Recv(&got, 1500)) {
        if (received == 0 || got == "c31") firstAndLast += got + ";";
        ++received;
    }
    CHECK_EQ(received, static_cast<int>(pf::kUdpQueueMaxDatagrams));
    CHECK_EQ(firstAndLast, std::string("c0;c31;"));

    // The queue's byte bound: two 40000-byte datagrams, the second over 64 KB.
    ResetEvent(gate.h);
    UdpClient d;
    CHECK(d.Send(port, std::string(40000, 'd')) && d.Send(port, std::string(40000, 'D')));
    CHECK_UNTIL(dropped() == 1 + 8 + 1, 5000, Describe(e));
    SetEvent(gate.h);
    CHECK(d.Recv(&got, 5000) && got == std::string(40000, 'd'));
    CHECK_MSG(d.Silent(500), "the datagram that would take the queue past 64 KB was dropped");

    const auto st = Find(e, id).stats;
    CHECK_EQ(st.totalConnections, uint64_t{4});
    CHECK_EQ(st.udpSessions, uint64_t{4});
    CHECK_EQ(rig.fg.CountPath(kTunnel), 4);
    CHECK_EQ(st.lastError.code, std::string());
    rig.fg.SetTunnelGate(nullptr);
    e.Stop();
}

// A node-level failure (upstream_udp_unavailable) is cached for the rule: 1 s, then 2 s
// after the next failure. Meanwhile no request at all, and the destination -- the rule's
// remote, where a direct fallback would go -- sees nothing, ever.
void TestFailClosedAndFailureCache() {
    UdpEchoServer dest;
    CHECK(dest.Start());
    GhostRig rig;
    rig.fg.SetTunnelError("upstream_udp_unavailable");
    FakeClock clock;
    LogSink log;
    EngineOptions o;
    o.tunnel = rig.source;
    o.clock = &clock;
    o.log = log.Fn();
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000075";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", dest.port(), EgressKind::Node, "n1")});
    CHECK_EQ(Find(e, id).status, std::string(S::kListening));
    auto dropped = [&] { return Find(e, id).stats.droppedDatagrams; };
    // A new client every time: per-client backoff is not what is tested here.
    std::vector<std::unique_ptr<UdpClient>> cl;
    auto fresh = [&]() -> UdpClient& {
        cl.push_back(std::make_unique<UdpClient>());
        return *cl.back();
    };

    CHECK(fresh().Send(port, "first"));
    CHECK_UNTIL(Find(e, id).stats.lastError.code == "upstream_udp_unavailable" && dropped() == 1 &&
                    Find(e, id).stats.udpSessions == 0,
                5000, Describe(e));
    CHECK_EQ(rig.fg.CountPath(kTunnel), 1);
    CHECK(log.AnyContains("upstream_udp_unavailable"));

    // Cached for 1 s: other clients' datagrams are dropped and counted, without a request.
    CHECK(fresh().Send(port, "b") && fresh().Send(port, "c"));
    CHECK_UNTIL(dropped() == 3, 5000, Describe(e));
    clock.Advance(pf::kUdpFailureCacheMinMs - 1);
    CHECK(fresh().Send(port, "d"));
    CHECK_UNTIL(dropped() == 4, 5000, Describe(e));
    CHECK_EQ(rig.fg.CountPath(kTunnel), 1);

    // Expired: one request, which fails again -- cached for 2 s now.
    clock.Advance(1);
    CHECK(fresh().Send(port, "e"));
    CHECK_UNTIL(rig.fg.CountPath(kTunnel) == 2 && dropped() == 5 && Find(e, id).stats.udpSessions == 0, 5000,
                Describe(e));
    clock.Advance(2 * pf::kUdpFailureCacheMinMs - 1);
    CHECK(fresh().Send(port, "f"));
    CHECK_UNTIL(dropped() == 6, 5000, Describe(e));
    CHECK_EQ(rig.fg.CountPath(kTunnel), 2);

    // Expired again, and Ghost relays now.
    rig.fg.SetTunnelError("");
    clock.Advance(1);
    CHECK_MSG(fresh().RoundTrip(port, "back"), "after the cache expires a new relay is requested");
    CHECK_EQ(rig.fg.CountPath(kTunnel), 3);
    CHECK_EQ(dest.Datagrams(), 0);  // fail closed: the destination saw ZERO datagrams
    e.Stop();
}

// A capacity answer (tunnel_limit) is not cached: the next client's request goes out.
void TestTransientFailuresNotCached() {
    GhostRig rig;
    rig.fg.QueueTunnelErrors({"tunnel_limit"});
    FakeClock clock;
    EngineOptions o;
    o.tunnel = rig.source;
    o.clock = &clock;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000076";
    Apply(e, {MakeRule(id.c_str(), port, "198.51.100.2", 53, EgressKind::Node, "n1")});
    UdpClient a;
    CHECK(a.Send(port, "a"));
    CHECK_UNTIL(Find(e, id).stats.lastError.code == "tunnel_limit" && Find(e, id).stats.udpSessions == 0, 5000,
                Describe(e));
    UdpClient b;
    CHECK_MSG(b.RoundTrip(port, "b"), "a tunnel_limit answer does not hold back the next client");
    CHECK_EQ(rig.fg.CountPath(kTunnel), 2);
    e.Stop();
}

// The plugin holds at most maxUdpRelays relays across all its rules; a new client over that
// is refused locally (session_limit) without a request, and served once one is free.
void TestRelayCap() {
    GhostRig rig;
    FakeClock clock;
    EngineOptions o;
    o.tunnel = rig.source;
    o.clock = &clock;
    o.maxUdpRelays = 2;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int pa = FreeUdpPort();
    const int pb = FreeUdpPort();
    const std::string ida = "r_0000000000000077";
    const std::string idb = "r_0000000000000078";
    Apply(e, {MakeRule(ida.c_str(), pa, "198.51.100.3", 53, EgressKind::Node, "n1"),
              MakeRule(idb.c_str(), pb, "198.51.100.4", 53, EgressKind::Node, "n1")});
    UdpClient c1;
    UdpClient c2;
    UdpClient c3;
    CHECK(c1.RoundTrip(pa, "1"));
    CHECK(c2.RoundTrip(pb, "2"));  // the other rule: the cap is plugin-wide
    CHECK(c3.Send(pa, "3"));
    CHECK_UNTIL(Find(e, ida).stats.droppedDatagrams == 1, 3000, Describe(e));
    CHECK_EQ(Find(e, ida).stats.lastError.code, std::string(pf::fwd_err::kSessionLimit));
    CHECK_EQ(rig.fg.CountPath(kTunnel), 2);
    CHECK(c3.Silent(200));

    clock.Advance(60000);  // both sessions go idle and give their relays back
    CHECK_UNTIL(Find(e, ida).stats.udpSessions == 0 && Find(e, idb).stats.udpSessions == 0, 3000, Describe(e));
    CHECK_MSG(c3.RoundTrip(pa, "3 again"), "with a relay free the client is served");
    CHECK_EQ(rig.fg.CountPath(kTunnel), 3);
    e.Stop();
}

void TestRelayResetEndsSession() {
    GhostRig rig;
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000079";
    Apply(e, {MakeRule(id.c_str(), port, "198.51.100.8", 53, EgressKind::Active)});
    UdpClient a;
    CHECK(a.RoundTrip(port, "one"));
    CHECK_EQ(rig.fg.CountPath(kTunnel), 1);

    rig.fg.CloseUdpRelays();  // Ghost tears the relay down
    CHECK(a.Send(port, "into the void"));
    CHECK_UNTIL(Find(e, id).stats.udpSessions == 0 && Find(e, id).stats.lastError.code == pf::fwd_err::kRemoteReset,
                5000, Describe(e) + " | " + rig.fg.Describe());
    CHECK(a.Silent(200));
    CHECK_MSG(a.RoundTrip(port, "two"), "the next datagram opens a new session (no backoff: it had answered)");
    CHECK_EQ(rig.fg.CountPath(kTunnel), 2);
    CHECK_EQ(Find(e, id).stats.totalConnections, uint64_t{2});
    e.Stop();
}

// "localhost" is tried IPv4 first, so an IPv4-only destination answers at once.
void TestLocalhostIpv4First() {
    UdpEchoServer echo;  // 127.0.0.1 only
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_000000000000007a";
    Apply(e, {MakeRule(id.c_str(), port, "localhost", echo.port())});
    const uint64_t before = pf::testing::UdpFailovers();
    UdpClient a;
    CHECK_MSG(a.RoundTrip(port, "local"), "localhost reaches an IPv4-only service");
    CHECK_EQ(pf::testing::UdpFailovers() - before, uint64_t{0});
    e.Stop();
}

// With the resolver's order (::1 first) and nothing on [::1]:<port>, the session's first
// datagram draws an ICMP "port unreachable": the session moves to 127.0.0.1 and sends that
// datagram again, so the client gets its answer. The next session of the rule starts at the
// address that answered (no second failover).
void TestDirectFailover() {
    UdpEchoServer echo;  // 127.0.0.1 only
    CHECK(echo.Start());
    CHECK_MSG(CanBindUdp(echo.port(), AF_INET6), "nothing on [::1]:<echo port>");
    pf::testing::SetUdpLocalhostIpv4First(false);
    {
        Engine e(EngineOptions{});
        pf_test::FailureContext ctx([&] { return Describe(e); });
        const int port = FreeUdpPort();
        const std::string id = "r_000000000000007b";
        Apply(e, {MakeRule(id.c_str(), port, "localhost", echo.port())});
        const uint64_t before = pf::testing::UdpFailovers();
        UdpClient a;
        CHECK_MSG(a.RoundTrip(port, "after a failover"), "the datagram sent to the dead ::1 is sent again");
        CHECK_EQ(pf::testing::UdpFailovers() - before, uint64_t{1});
        UdpClient b;
        CHECK(b.RoundTrip(port, "sticky"));
        CHECK_EQ(pf::testing::UdpFailovers() - before, uint64_t{1});
        CHECK_EQ(Find(e, id).stats.lastError.code, std::string());
        CHECK_EQ(echo.Datagrams(), 2);
        e.Stop();
    }
    pf::testing::SetUdpLocalhostIpv4First(true);
}

// A destination that resets every session before answering (nothing listens there) holds
// its client back: 1 s, then 2 s, without a new session meanwhile. Another client is not
// held back.
void TestResetBackoff() {
    const int dead = pf_test::ReservePort();
    pf_test::ReleasePort(dead);  // nothing listens there now
    FakeClock clock;
    EngineOptions o;
    o.clock = &clock;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_000000000000007c";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", dead)});
    auto st = [&] { return Find(e, id).stats; };
    UdpClient a;
    CHECK(a.Send(port, "x"));
    CHECK_UNTIL(st().udpSessions == 0 && st().lastError.code == pf::fwd_err::kRemoteReset, 5000, Describe(e));
    CHECK_EQ(st().totalConnections, uint64_t{1});

    for (int i = 0; i < 3; ++i) CHECK(a.Send(port, "held"));
    CHECK_UNTIL(st().droppedDatagrams == 3, 5000, Describe(e));
    CHECK_EQ(st().totalConnections, uint64_t{1});

    UdpClient b;
    CHECK(b.Send(port, "another client"));
    CHECK_UNTIL(st().totalConnections == 2 && st().udpSessions == 0, 5000, Describe(e));

    clock.Advance(pf::kUdpClientBackoffMinMs);
    CHECK(a.Send(port, "after 1 s"));
    CHECK_UNTIL(st().totalConnections == 3 && st().udpSessions == 0, 5000, Describe(e));
    clock.Advance(pf::kUdpClientBackoffMinMs);  // the second backoff is 2 s
    CHECK(a.Send(port, "still held"));
    CHECK_UNTIL(st().droppedDatagrams == 4, 5000, Describe(e));
    CHECK_EQ(st().totalConnections, uint64_t{3});
    clock.Advance(pf::kUdpClientBackoffMinMs);
    CHECK(a.Send(port, "after 2 s"));
    CHECK_UNTIL(st().totalConnections == 4, 5000, Describe(e));
    e.Stop();
}

// On a 0.0.0.0 listener the address a client sent to is part of the session: datagrams to
// 127.0.0.1 and to 127.0.0.2 from one client socket are two sessions. The reply to the
// first comes from 127.0.0.1. (Windows will not send FROM 127.0.0.2 although it accepts
// traffic to it, so the second reply falls back to the address routing picks; a reply
// source across two real interfaces cannot be shown on one machine -- the strong host model
// keeps a socket bound to one local address from reaching another.)
void TestWildcardLocalAddress() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_000000000000007d";
    Rule r = MakeRule(id.c_str(), port, "127.0.0.1", echo.port());
    r.listenAddr = "0.0.0.0";
    r.lanAck = true;
    Apply(e, {r});
    CHECK_EQ(Find(e, id).status, std::string(S::kListening));
    UdpClient a;
    std::string got;
    std::string fromIp;
    int fromPort = 0;
    CHECK(a.SendTo("127.0.0.1", port, "to .1"));
    CHECK(a.Recv(&got, 3000, &fromPort, &fromIp) && got == "to .1");
    CHECK_EQ(fromIp, std::string("127.0.0.1"));
    CHECK_EQ(fromPort, port);
    CHECK(a.SendTo("127.0.0.2", port, "to .2"));
    CHECK(a.Recv(&got, 3000, &fromPort, &fromIp) && got == "to .2");
    std::printf("   the reply to 127.0.0.2 came from %s\n", fromIp.c_str());
    CHECK_EQ(Find(e, id).stats.totalConnections, uint64_t{2});
    CHECK_EQ(Find(e, id).stats.udpSessions, uint64_t{2});
    e.Stop();
}

void TestStatuses() {
    // Standalone: a via-node rule does not listen.
    {
        Engine e(EngineOptions{});
        pf_test::FailureContext ctx([&] { return Describe(e); });
        const int port = FreeUdpPort();
        Apply(e, {MakeRule("r_0000000000000080", port, "198.51.100.9", 53, EgressKind::Node, "n1")});
        CHECK_EQ(Find(e, "r_0000000000000080").status, std::string(S::kNeedsGhost));
        CHECK_MSG(CanBindUdp(port), "needs_ghost: the port is not bound");
    }
    // A port another program holds.
    {
        UniqueSocket holder(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int len = sizeof(a);
        CHECK(bind(holder.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
        CHECK(getsockname(holder.get(), reinterpret_cast<sockaddr*>(&a), &len) == 0);
        Engine e(EngineOptions{});
        pf_test::FailureContext ctx([&] { return Describe(e); });
        e.Apply({MakeRule("r_0000000000000081", ntohs(a.sin_port), "127.0.0.1", 9)});
        const auto s = Find(e, "r_0000000000000081");
        CHECK_EQ(s.status, std::string(S::kBindFailed));
        CHECK_MSG(s.detail.rfind("WSA error 10048", 0) == 0, s.detail.c_str());
        CHECK_EQ(s.stats.lastError.code, std::string(pf::fwd_err::kBindFailed));
        CHECK(pf::BindFailureDetail(10013, pf::Proto::Udp).find("protocol=udp") != std::string::npos);
        CHECK(pf::BindFailureDetail(10013).find("protocol=tcp") != std::string::npos);
    }
    // A TCP and a UDP rule on the same port number are two listeners.
    {
        UdpEchoServer uecho;
        pf_test::TcpEchoServer techo;
        CHECK(uecho.Start() && techo.Start());
        Engine e(EngineOptions{});
        pf_test::FailureContext ctx([&] { return Describe(e); });
        const int port = FreeUdpPort();  // held for both protocols until Apply
        Rule t = MakeRule("r_0000000000000082", port, "127.0.0.1", techo.port());
        t.proto = pf::Proto::Tcp;
        Apply(e, {t, MakeRule("r_0000000000000083", port, "127.0.0.1", uecho.port())});
        CHECK_EQ(Find(e, "r_0000000000000082").status, std::string(S::kListening));
        CHECK_EQ(Find(e, "r_0000000000000083").status, std::string(S::kListening));
        UdpClient c;
        CHECK(c.RoundTrip(port, "udp beside tcp"));
    }
}

// Stop() aborts a relay request Ghost has not answered. Ghost's answer is 60 s away and the
// budget 5 s: returning before the budget proves the abort.
void TestStopIsBounded() {
    UdpEchoServer dest;
    CHECK(dest.Start());
    GhostRig rig;
    rig.fg.SetTunnelDelayMs(60000);
    EngineOptions o;
    o.tunnel = rig.source;
    o.stopBudgetMs = 5000;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int pDirect = FreeUdpPort();
    const int pNode = FreeUdpPort();
    Apply(e, {MakeRule("r_0000000000000084", pDirect, "127.0.0.1", dest.port()),
              MakeRule("r_0000000000000085", pNode, "198.51.100.10", 53, EgressKind::Node, "n1")});
    UdpClient live;
    CHECK(live.RoundTrip(pDirect, "live"));
    UdpClient waiting;
    CHECK(waiting.Send(pNode, "waiting"));
    CHECK_UNTIL(rig.fg.TunnelsInProgress() == 1, 5000, rig.fg.Describe());

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    std::printf("   Stop() took %llu ms\n", took);
    CHECK_MSG(took < 5000, "Stop() returns before its budget while a relay request is stuck");
    CHECK_EQ(e.StragglerThreads(), 0);
    CHECK_UNTIL(rig.fg.ClientClosedDuringDelay() == 1, 5000, rig.fg.Describe());
    CHECK_MSG(CanBindUdp(pDirect) && CanBindUdp(pNode), "both listening sockets are closed");
    CHECK(e.Snapshot().empty());
    CHECK_EQ(rig.fg.UdpEchoed(), 0);
    CHECK_EQ(dest.Datagrams(), 1);  // only the direct one
}

// An open worker the engine cannot reach (a 429 backoff inside the API client, held there
// by the gate clock) does not hold Stop() past its budget, and finishes once let go.
void TestStopLeavesStragglerBehind() {
    pf_test::GateClock gate;
    GhostRig rig(&gate);
    rig.fg.Set429Count(1);
    EngineOptions o;
    o.tunnel = rig.source;
    o.stopBudgetMs = 500;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int pNode = FreeUdpPort();
    Apply(e, {MakeRule("r_0000000000000086", pNode, "198.51.100.11", 53, EgressKind::Node, "n1")});
    UdpClient waiting;
    CHECK(waiting.Send(pNode, "waiting"));
    CHECK_UNTIL(gate.InWait() == 1, 10000, "threads in the backoff: " + std::to_string(gate.InWait()));

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    CHECK_MSG(took < 5000, "Stop() keeps to its budget");
    CHECK_EQ(e.StragglerThreads(), 1);
    CHECK(CanBindUdp(pNode));
    rig.api->Shutdown();
    CHECK_UNTIL(e.StragglerThreads() == 0, 5000, "stragglers: " + std::to_string(e.StragglerThreads()));
    CHECK_EQ(rig.fg.UdpEchoed(), 0);
}

void TestApplyRestartsOnlyChanged() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int pa = FreeUdpPort();
    const int pb = FreeUdpPort();
    Rule a = MakeRule("r_0000000000000087", pa, "127.0.0.1", echo.port());
    Rule b = MakeRule("r_0000000000000088", pb, "127.0.0.1", echo.port());
    Apply(e, {a, b});
    UdpClient ca;
    UdpClient cb;
    CHECK(ca.RoundTrip(pa, "a1") && cb.RoundTrip(pb, "b1"));

    b.udpIdleSec = 30;  // a change in any field restarts that rule
    e.Apply({a, b});
    CHECK_MSG(ca.RoundTrip(pa, "a2"), "the unchanged rule keeps serving");
    CHECK_EQ(Find(e, a.id).stats.totalConnections, uint64_t{1});  // and keeps its session
    CHECK_EQ(Find(e, a.id).stats.udpSessions, uint64_t{1});
    CHECK_EQ(Find(e, b.id).stats.totalConnections, uint64_t{0});  // fresh counters
    CHECK(cb.RoundTrip(pb, "b2"));
    CHECK_EQ(Find(e, b.id).stats.totalConnections, uint64_t{1});  // a new session

    e.Apply({a});
    CHECK_UNTIL(CanBindUdp(pb), 5000, Describe(e));
    CHECK(ca.RoundTrip(pa, "a3"));
    CHECK_EQ(e.Snapshot().size(), size_t{1});
    e.Stop();
}

// A receive error on the listener other than the ICMP kind (out of buffers) is recorded and
// followed by a one-slice pause, not retried at once (the listener stays readable), and the
// rule keeps listening: four injected failures delay the datagram by about four slices.
void TestListenErrorsDoNotSpin() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000089";
    Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", echo.port())});
    pf::testing::InjectUdpListenErrors(4, WSAENOBUFS);
    UdpClient a;
    const ULONGLONG t0 = GetTickCount64();
    CHECK(a.RoundTrip(port, "after the errors"));
    const ULONGLONG took = GetTickCount64() - t0;
    pf::testing::InjectUdpListenErrors(0, 0);
    std::printf("   forwarded after four errors in %llu ms\n", took);
    CHECK_MSG(took >= 4 * pf::kPollSliceMs - 100, "each receive error is followed by a pause of one slice");
    const auto s = Find(e, id);
    CHECK_EQ(s.status, std::string(S::kListening));
    CHECK_EQ(s.stats.lastError.code, std::string(pf::fwd_err::kInternal));
    CHECK_EQ(s.stats.lastError.count, uint64_t{4});
    CHECK(a.RoundTrip(port, "and again"));
    e.Stop();
}

// Re-applying an unchanged rule whose bind failed retries the bind.
void TestReapplyRetriesBind() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    UniqueSocket holder(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int len = sizeof(a);
    CHECK(bind(holder.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    CHECK(getsockname(holder.get(), reinterpret_cast<sockaddr*>(&a), &len) == 0);
    const int port = ntohs(a.sin_port);
    Engine e(EngineOptions{});
    pf_test::FailureContext ctx([&] { return Describe(e); });
    const Rule r = MakeRule("r_000000000000008a", port, "127.0.0.1", echo.port());
    e.Apply({r});
    CHECK_EQ(Find(e, r.id).status, std::string(S::kBindFailed));
    holder.Reset();
    e.Apply({r});
    CHECK_EQ(Find(e, r.id).status, std::string(S::kListening));  // the bind was retried
    UdpClient c;
    CHECK(c.RoundTrip(port, "bound now"));
    e.Stop();
}

// Every way a relay can fail drops the datagrams and never reaches the destination.
void TestFailClosedRows() {
    struct Row {
        const char* name;
        std::function<void(FakeGhost&)> setup;
        std::string code;
    };
    const std::vector<Row> rows = {
        {"answer dropped", [](FakeGhost& fg) { fg.SetTunnelDrop(true); }, pf::api_err::kGhostUnreachable},
        {"malformed protocolInfo",
         [](FakeGhost& fg) {
             fg.SetTunnelFixedBody(R"({"status":"ok","proto":"udp","protocolInfo":"!!not base64!!",)"
                                   R"("protocolInfoBytes":628,"node":{"id":"n1","name":"N","type":"socks5"},)"
                                   R"("maxPayload":65000,"idleTimeoutMs":120000})");
         },
         pf::api_err::kBadResponse},
    };
    for (const Row& row : rows) {
        UdpEchoServer dest;
        CHECK(dest.Start());
        GhostRig rig;
        row.setup(rig.fg);
        EngineOptions o;
        o.tunnel = rig.source;
        Engine e(o);
        pf_test::FailureContext ctx([&] { return std::string(row.name) + ": " + Describe(e) + " | " + rig.fg.Describe(); });
        const int port = FreeUdpPort();
        const std::string id = "r_000000000000008b";
        Apply(e, {MakeRule(id.c_str(), port, "127.0.0.1", dest.port(), EgressKind::Node, "n1")});
        UdpClient c;
        CHECK(c.Send(port, "x"));
        CHECK_UNTIL(Find(e, id).stats.lastError.code == row.code && Find(e, id).stats.droppedDatagrams == 1 &&
                        Find(e, id).stats.udpSessions == 0,
                    5000, Describe(e));
        CHECK(c.Silent(200));
        CHECK_EQ(dest.Datagrams(), 0);
        CHECK_EQ(rig.fg.CountPath(kTunnel), 1);
        e.Stop();
    }
    // Stop while the request is on the wire.
    {
        UdpEchoServer dest;
        CHECK(dest.Start());
        GhostRig rig;
        rig.fg.SetTunnelDelayMs(60000);
        EngineOptions o;
        o.tunnel = rig.source;
        Engine e(o);
        pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
        const int port = FreeUdpPort();
        Apply(e, {MakeRule("r_000000000000008c", port, "127.0.0.1", dest.port(), EgressKind::Node, "n1")});
        UdpClient c;
        CHECK(c.Send(port, "x"));
        CHECK_UNTIL(rig.fg.TunnelsInProgress() == 1, 5000, rig.fg.Describe());
        e.Stop();
        CHECK_EQ(dest.Datagrams(), 0);  // stop during the request: ZERO datagrams
    }
}

// lastError.count is the number of failures in a row: a session that opens ends the run.
void TestSuccessEndsErrorRun() {
    GhostRig rig;
    rig.fg.QueueTunnelErrors({"upstream_unreachable", "upstream_unreachable"});
    FakeClock clock;
    EngineOptions o;
    o.tunnel = rig.source;
    o.clock = &clock;
    Engine e(o);
    pf_test::FailureContext ctx([&] { return Describe(e) + " | " + rig.fg.Describe(); });
    const int port = FreeUdpPort();
    const std::string id = "r_000000000000008d";
    Apply(e, {MakeRule(id.c_str(), port, "198.51.100.12", 53, EgressKind::Node, "n1")});
    UdpClient a;
    CHECK(a.Send(port, "fails"));
    CHECK_UNTIL(Find(e, id).stats.lastError.count == 1, 5000, Describe(e));
    clock.Advance(pf::kUdpFailureCacheMinMs);  // the cache (and a's backoff): 1 s
    CHECK(a.Send(port, "fails"));
    CHECK_UNTIL(Find(e, id).stats.lastError.count == 2, 5000, Describe(e));
    clock.Advance(2 * pf::kUdpFailureCacheMinMs);  // now 2 s
    CHECK(a.RoundTrip(port, "works"));
    rig.fg.SetTunnelError("upstream_unreachable");
    UdpClient b;
    CHECK(b.Send(port, "fails again"));
    CHECK_UNTIL(rig.fg.CountPath(kTunnel) == 4 && Find(e, id).stats.udpSessions == 1, 5000, Describe(e));
    const auto st = Find(e, id).stats;
    CHECK_EQ(st.lastError.code, std::string("upstream_unreachable"));
    CHECK_EQ(st.lastError.count, uint64_t{1});  // a session that opened started a new run
    e.Stop();
}

}  // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("== %s\n", name);
        const ULONGLONG t0 = GetTickCount64();
        fn();
        std::printf("   (%llu ms)\n", GetTickCount64() - t0);
    };
    run("cacheable codes", TestCacheableCodes);
    run("interleave families", TestInterleaveFamilies);
    run("direct, two clients, no crosstalk", TestDirectTwoClients);
    run("idle reclaim", TestIdleReclaim);
    run("idleness counts only forwarded datagrams", TestIdleCountsOnlyForwarded);
    run("session cap", TestSessionCap);
    run("via a node", TestViaNode);
    run("fail closed, failed-open cache", TestFailClosedAndFailureCache);
    run("transient failures are not cached", TestTransientFailuresNotCached);
    run("plugin-wide relay cap", TestRelayCap);
    run("relay reset ends the session", TestRelayResetEndsSession);
    run("localhost: IPv4 first", TestLocalhostIpv4First);
    run("direct failover", TestDirectFailover);
    run("reset backoff per client", TestResetBackoff);
    run("0.0.0.0: local address in the session", TestWildcardLocalAddress);
    run("statuses", TestStatuses);
    run("stop is bounded", TestStopIsBounded);
    run("stop leaves a straggler behind", TestStopLeavesStragglerBehind);
    run("apply restarts only the changed rule", TestApplyRestartsOnlyChanged);
    run("listener errors do not spin", TestListenErrorsDoNotSpin);
    run("re-apply retries a failed bind", TestReapplyRetriesBind);
    run("fail closed rows", TestFailClosedRows);
    run("a success ends the error run", TestSuccessEndsErrorRun);
    return pf_test::TestExitCode();
}
