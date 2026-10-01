// Functional: UDP forwarding over real loopback sockets (forward_udp.h, engine.h).
//
// Direct rules forward to a local UDP echo server; via-node rules go through the fake
// Ghost, which hands over one end of a connected loopback UDP pair and echoes on the other
// (no proxy protocol anywhere). Covered: two clients of one rule round-trip without
// crosstalk (a session is the full source address, not the IP); idle reclaim and the
// session after it; the per-rule session cap; a relayed round trip with the exact tunnel
// request, one association per session, datagrams queued while the relay is opened (and
// the queue's two bounds), Ghost's maxPayload; fail closed with the failed-open cache (no
// request per datagram, the destination sees ZERO datagrams, recovery once the cache
// expires); WSAECONNRESET from a torn-down relay ending the session and the next datagram
// opening a new one; statuses and bind failures; Stop() within its budget while a relay
// request is stuck, and a straggler left behind; Apply() restarting only the changed rule.
//
// Time-driven behaviour (idleness, the failed-open cache) runs on a FakeClock that the
// test advances; the forwarder's poll thread reads it every slice.

#include "echo_servers.h"
#include "engine.h"
#include "fake_clock.h"
#include "fake_ghost.h"
#include "forward_udp.h"
#include "test_support.h"
#include "tunnel_client.h"
#include "tunnel_source.h"

#include <mswsock.h>

#include <memory>
#include <mutex>
#include <set>
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

// A UDP port that was free a moment ago, never the same one twice in this process.
int FreeUdpPort() {
    static std::set<int> handed;
    for (int attempt = 0; attempt < 100; ++attempt) {
        UniqueSocket s(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
        if (!s) return 0;
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int len = sizeof(a);
        if (bind(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
            getsockname(s.get(), reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            return 0;
        }
        const int port = ntohs(a.sin_port);
        if (handed.insert(port).second) return port;
    }
    return 0;
}

// Nothing holds 127.0.0.1:port for UDP (an exclusive bind succeeds).
bool CanBindUdp(int port) {
    UniqueSocket s(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return false;
    BOOL one = TRUE;
    setsockopt(s.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
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

    bool Send(int toPort, const std::string& msg) {
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<u_short>(toPort));
        return sendto(s_.get(), msg.data(), static_cast<int>(msg.size()), 0, reinterpret_cast<sockaddr*>(&a),
                      sizeof(a)) == static_cast<int>(msg.size());
    }
    // One datagram within `ms`; `fromPort` (if given) receives its source port.
    bool Recv(std::string* out, DWORD ms, int* fromPort = nullptr) {
        setsockopt(s_.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof(ms));
        std::vector<char> buf(65536);
        sockaddr_in from = {};
        int len = sizeof(from);
        const int n =
            recvfrom(s_.get(), buf.data(), static_cast<int>(buf.size()), 0, reinterpret_cast<sockaddr*>(&from), &len);
        if (n < 0) return false;
        out->assign(buf.data(), static_cast<size_t>(n));
        if (fromPort) *fromPort = ntohs(from.sin_port);
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

// A fake Ghost and the tunnel source over it.
struct GhostRig {
    FakeGhost fg;
    std::shared_ptr<GhostApi> api;
    std::shared_ptr<TunnelClient> tc;
    std::shared_ptr<pf::TunnelSource> source;

    GhostRig() {
        CHECK(fg.Start());
        GhostApiOptions o;
        o.apiBase = fg.apiBase();
        o.token = "tok-forward-udp";
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

// ---------------------------------------------------------------------------------------

void TestDirectTwoClients() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    LogSink log;
    EngineOptions o;
    o.log = log.Fn();
    Engine e(o);
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000070";
    e.Apply({MakeRule(id.c_str(), port, "127.0.0.1", echo.port())});
    CHECK(Find(e, id).status == S::kListening);

    UdpClient a;
    UdpClient b;
    CHECK(a.ok() && b.ok());
    size_t bytes = 0;
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
    CHECK_MSG(st.udpSessions == 2, "two clients from one IP are two sessions");
    CHECK(st.totalConnections == 2);
    CHECK_MSG(echo.DistinctSources() == 2, "each session has its own remote socket");
    CHECK(echo.Datagrams() == 10);
    CHECK_MSG(st.bytesUp == bytes && st.bytesDown == bytes, "byte counters are exact");
    CHECK(st.droppedDatagrams == 0);
    CHECK(st.lastError.code.empty());
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
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000071";
    e.Apply({MakeRule(id.c_str(), port, "127.0.0.1", echo.port(), EgressKind::Direct, "", 5)});
    UdpClient a;
    CHECK(a.RoundTrip(port, "one"));
    CHECK(Find(e, id).stats.udpSessions == 1);

    clock.Advance(4000);
    CHECK_MSG(!pf_test::WaitUntil([&] { return Find(e, id).stats.udpSessions == 0; }, 600),
              "a session is not reclaimed before udpIdleSec");
    CHECK(a.RoundTrip(port, "still"));  // activity: the idle time starts again
    CHECK(Find(e, id).stats.totalConnections == 1);
    CHECK(echo.DistinctSources() == 1);

    clock.Advance(4999);
    CHECK(!pf_test::WaitUntil([&] { return Find(e, id).stats.udpSessions == 0; }, 600));
    clock.Advance(1);
    CHECK_MSG(pf_test::WaitUntil([&] { return Find(e, id).stats.udpSessions == 0; }, 3000),
              "a session idle for udpIdleSec is reclaimed");
    CHECK(Find(e, id).stats.droppedDatagrams == 0);

    CHECK_MSG(a.RoundTrip(port, "again"), "the client's next datagram opens a new session");
    CHECK(Find(e, id).stats.totalConnections == 2);
    CHECK_MSG(echo.DistinctSources() == 2, "with a new remote socket");
    e.Stop();
}

void TestSessionCap() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    FakeClock clock;
    EngineOptions o;
    o.clock = &clock;
    Engine e(o);
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000072";
    e.Apply({MakeRule(id.c_str(), port, "127.0.0.1", echo.port())});

    std::vector<std::unique_ptr<UdpClient>> clients;
    bool all = true;
    for (size_t i = 0; i < pf::kMaxUdpSessionsPerRule; ++i) {
        clients.push_back(std::make_unique<UdpClient>());
        all = all && clients.back()->RoundTrip(port, "c" + std::to_string(i));
    }
    CHECK_MSG(all, "64 clients each round-trip");
    CHECK(Find(e, id).stats.udpSessions == pf::kMaxUdpSessionsPerRule);

    UdpClient over;
    CHECK(over.Send(port, "one too many"));
    CHECK_MSG(over.Silent(500), "the 65th client gets no session and no reply");
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.droppedDatagrams == 1; }, 3000));
    auto st = Find(e, id).stats;
    CHECK(st.lastError.code == pf::fwd_err::kSessionLimit);
    CHECK(st.totalConnections == pf::kMaxUdpSessionsPerRule);
    CHECK(st.udpSessions == pf::kMaxUdpSessionsPerRule);
    CHECK_MSG(clients[0]->RoundTrip(port, "existing"), "existing sessions are unaffected");
    CHECK(echo.Datagrams() == static_cast<int>(pf::kMaxUdpSessionsPerRule) + 1);

    // Once sessions go idle there is room again.
    clock.Advance(60000);
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.udpSessions == 0; }, 3000));
    CHECK_MSG(over.RoundTrip(port, "room now"), "below the cap a new client is served");
    e.Stop();
}

void TestViaNode() {
    GhostRig rig;
    rig.fg.SetUdpMaxPayload(100);
    rig.fg.SetTunnelDelayMs(300);  // datagrams arrive while the relay is being opened
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000073";
    e.Apply({MakeRule(id.c_str(), port, "198.51.100.7", 5353, EgressKind::Node, "n1")});
    CHECK(Find(e, id).status == S::kListening);

    UdpClient a;
    CHECK(a.Send(port, "q1") && a.Send(port, "q2") && a.Send(port, "q3"));
    std::string got;
    std::string seq;
    for (int i = 0; i < 3; ++i) {
        if (a.Recv(&got, 5000)) seq += got + ",";
    }
    CHECK_MSG(seq == "q1,q2,q3,", "datagrams queued while the relay opened arrive, in order");
    auto bodies = TunnelBodies(rig.fg);
    CHECK_MSG(bodies.size() == 1, "one relay request for one session");
    CHECK_MSG(bodies.size() == 1 && bodies[0] == json({{"via", "node"},
                                                       {"nodeId", "n1"},
                                                       {"proto", "udp"},
                                                       {"host", "198.51.100.7"},
                                                       {"port", 5353}}),
              "the relay request carries exactly via/nodeId/proto/host/port");

    // Ghost's maxPayload (100 for this session).
    const int echoedBefore = rig.fg.UdpEchoed();
    CHECK(a.Send(port, std::string(101, 'x')));
    CHECK_MSG(a.Silent(300), "a datagram over maxPayload is not forwarded");
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.droppedDatagrams == 1; }, 3000));
    CHECK(rig.fg.UdpEchoed() == echoedBefore);
    CHECK_MSG(a.RoundTrip(port, std::string(100, 'y')), "a datagram of exactly maxPayload is");

    // One association per session: a second client is a second request.
    rig.fg.SetUdpMaxPayload(65000);
    rig.fg.SetTunnelDelayMs(0);
    UdpClient b;
    CHECK(b.RoundTrip(port, "b1"));
    CHECK(b.RoundTrip(port, "b2"));
    CHECK(rig.fg.CountPath(kTunnel) == 2);

    // The queue's datagram bound: 40 sent while opening, 32 forwarded.
    rig.fg.SetTunnelDelayMs(500);
    UdpClient c;
    for (int i = 0; i < 40; ++i) CHECK(c.Send(port, "c" + std::to_string(i)));
    int received = 0;
    std::string firstAndLast;
    while (c.Recv(&got, 1500)) {
        if (received == 0 || got == "c31") firstAndLast += got + ";";
        ++received;
    }
    CHECK_MSG(received == static_cast<int>(pf::kUdpQueueMaxDatagrams), "at most 32 datagrams are queued");
    CHECK(firstAndLast == "c0;c31;");

    // The queue's byte bound: two 40000-byte datagrams, the second over 64 KB.
    UdpClient d;
    CHECK(d.Send(port, std::string(40000, 'd')) && d.Send(port, std::string(40000, 'D')));
    CHECK(d.Recv(&got, 5000) && got == std::string(40000, 'd'));
    CHECK_MSG(d.Silent(500), "a datagram that would take the queue past 64 KB is dropped");
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.droppedDatagrams == 1 + 8 + 1; }, 3000));

    const auto st = Find(e, id).stats;
    CHECK(st.totalConnections == 4);
    CHECK(st.udpSessions == 4);
    CHECK(rig.fg.CountPath(kTunnel) == 4);
    CHECK(st.lastError.code.empty());
    e.Stop();
}

void TestFailClosedAndFailureCache() {
    UdpEchoServer dest;  // the rule's remote: a direct fallback would reach it
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
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000074";
    e.Apply({MakeRule(id.c_str(), port, "127.0.0.1", dest.port(), EgressKind::Node, "n1")});
    CHECK(Find(e, id).status == S::kListening);

    UdpClient a;
    UdpClient b;
    CHECK(a.Send(port, "first"));
    CHECK(pf_test::WaitUntil(
        [&] {
            const auto s = Find(e, id).stats;
            return s.lastError.code == "upstream_udp_unavailable" && s.droppedDatagrams == 1 && s.udpSessions == 0;
        },
        5000));
    CHECK(rig.fg.CountPath(kTunnel) == 1);
    CHECK(log.AnyContains("upstream_udp_unavailable"));

    // While the failure is cached: dropped and counted, no request.
    for (int i = 0; i < 3; ++i) CHECK(a.Send(port, "a" + std::to_string(i)));
    for (int i = 0; i < 2; ++i) CHECK(b.Send(port, "b" + std::to_string(i)));
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.droppedDatagrams == 6; }, 5000));
    CHECK_MSG(!pf_test::WaitUntil([&] { return rig.fg.CountPath(kTunnel) > 1; }, 300),
              "no relay request per datagram while a failed open is cached");
    CHECK(a.Silent(200) && b.Silent(200));
    CHECK(Find(e, id).stats.udpSessions == 0);

    // The cache expires; Ghost relays again.
    rig.fg.SetTunnelError("");
    clock.Advance(pf::kUdpOpenFailureCacheMs - 1);
    CHECK(a.Send(port, "still cached"));
    CHECK(pf_test::WaitUntil([&] { return Find(e, id).stats.droppedDatagrams == 7; }, 5000));
    CHECK(rig.fg.CountPath(kTunnel) == 1);
    clock.Advance(1);
    CHECK_MSG(a.RoundTrip(port, "back"), "after the cache expires a new relay is requested");
    CHECK(rig.fg.CountPath(kTunnel) == 2);

    CHECK_MSG(dest.Datagrams() == 0, "fail closed: the destination saw ZERO datagrams");
    e.Stop();
}

void TestRelayResetEndsSession() {
    GhostRig rig;
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    const int port = FreeUdpPort();
    const std::string id = "r_0000000000000075";
    e.Apply({MakeRule(id.c_str(), port, "198.51.100.8", 53, EgressKind::Active)});
    UdpClient a;
    CHECK(a.RoundTrip(port, "one"));
    CHECK(rig.fg.CountPath(kTunnel) == 1);

    rig.fg.CloseUdpRelays();  // Ghost tears the relay down
    CHECK(a.Send(port, "into the void"));
    CHECK_MSG(pf_test::WaitUntil(
                  [&] {
                      const auto s = Find(e, id).stats;
                      return s.udpSessions == 0 && s.lastError.code == pf::fwd_err::kRemoteReset;
                  },
                  5000),
              "WSAECONNRESET from the relay ends the session");
    CHECK(a.Silent(200));
    CHECK_MSG(a.RoundTrip(port, "two"), "the next datagram opens a new session");
    CHECK(rig.fg.CountPath(kTunnel) == 2);
    CHECK(Find(e, id).stats.totalConnections == 2);
    e.Stop();
}

void TestStatuses() {
    // Standalone: a via-node rule does not listen.
    {
        Engine e(EngineOptions{});
        const int port = FreeUdpPort();
        e.Apply({MakeRule("r_0000000000000076", port, "198.51.100.9", 53, EgressKind::Node, "n1")});
        CHECK(Find(e, "r_0000000000000076").status == S::kNeedsGhost);
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
        e.Apply({MakeRule("r_0000000000000077", ntohs(a.sin_port), "127.0.0.1", 9)});
        const auto s = Find(e, "r_0000000000000077");
        CHECK(s.status == S::kBindFailed);
        CHECK_MSG(s.detail.rfind("WSA error 10048", 0) == 0, s.detail.c_str());
        CHECK(s.stats.lastError.code == pf::fwd_err::kBindFailed);
        CHECK(pf::BindFailureDetail(10013, pf::Proto::Udp).find("protocol=udp") != std::string::npos);
        CHECK(pf::BindFailureDetail(10013).find("protocol=tcp") != std::string::npos);
    }
    // A TCP and a UDP rule on the same port number are two listeners.
    {
        UdpEchoServer uecho;
        pf_test::TcpEchoServer techo;
        CHECK(uecho.Start() && techo.Start());
        Engine e(EngineOptions{});
        pf_test::LoopbackListener probe;
        CHECK(pf_test::ListenLoopback(&probe));
        const int port = probe.port;
        probe.Close();
        Rule t = MakeRule("r_0000000000000078", port, "127.0.0.1", techo.port());
        t.proto = pf::Proto::Tcp;
        e.Apply({t, MakeRule("r_0000000000000079", port, "127.0.0.1", uecho.port())});
        CHECK(Find(e, "r_0000000000000078").status == S::kListening);
        CHECK(Find(e, "r_0000000000000079").status == S::kListening);
        UdpClient c;
        CHECK(c.RoundTrip(port, "udp beside tcp"));
    }
}

void TestStopIsBounded() {
    UdpEchoServer dest;
    CHECK(dest.Start());
    GhostRig rig;
    rig.fg.SetTunnelDelayMs(8000);  // a relay request Ghost answers slowly
    EngineOptions o;
    o.tunnel = rig.source;
    Engine e(o);
    const int pDirect = FreeUdpPort();
    const int pNode = FreeUdpPort();
    e.Apply({MakeRule("r_000000000000007a", pDirect, "127.0.0.1", dest.port()),
             MakeRule("r_000000000000007b", pNode, "198.51.100.10", 53, EgressKind::Node, "n1")});
    UdpClient live;
    CHECK(live.RoundTrip(pDirect, "live"));
    UdpClient waiting;
    CHECK(waiting.Send(pNode, "waiting"));
    CHECK(pf_test::WaitUntil([&] { return rig.fg.TunnelsInProgress() == 1; }, 5000));

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    std::printf("Stop() took %llu ms\n", took);
    CHECK_MSG(took < 1000, "Stop() returns within 1 s while a relay request is stuck");
    CHECK_MSG(e.StragglerThreads() == 0, "no thread is left behind");
    CHECK_MSG(CanBindUdp(pDirect) && CanBindUdp(pNode), "both listening sockets are closed");
    CHECK(e.Snapshot().empty());
    CHECK(rig.fg.UdpEchoed() == 0);
    CHECK(dest.Datagrams() == 1);  // only the direct one
}

// An open worker the engine cannot reach (a 429 backoff inside the API client) does not
// hold Stop() past its budget, and it finishes on its own later.
void TestStopLeavesStragglerBehind() {
    GhostRig rig;
    rig.fg.Set429Always(true);
    EngineOptions o;
    o.tunnel = rig.source;
    o.stopBudgetMs = 500;
    Engine e(o);
    const int pNode = FreeUdpPort();
    e.Apply({MakeRule("r_000000000000007c", pNode, "198.51.100.11", 53, EgressKind::Node, "n1")});
    UdpClient waiting;
    CHECK(waiting.Send(pNode, "waiting"));
    CHECK(pf_test::WaitUntil([&] { return rig.fg.CountPath(kTunnel) >= 4; }, 10000));

    const ULONGLONG t0 = GetTickCount64();
    e.Stop();
    const ULONGLONG took = GetTickCount64() - t0;
    CHECK_MSG(took < 1500, "Stop() keeps to its budget");
    CHECK_MSG(e.StragglerThreads() == 1, "the worker in the backoff is left running");
    CHECK(CanBindUdp(pNode));
    rig.api->Shutdown();
    CHECK(pf_test::WaitUntil([&] { return e.StragglerThreads() == 0; }, 5000));
    CHECK(rig.fg.UdpEchoed() == 0);
}

void TestApplyRestartsOnlyChanged() {
    UdpEchoServer echo;
    CHECK(echo.Start());
    Engine e(EngineOptions{});
    const int pa = FreeUdpPort();
    const int pb = FreeUdpPort();
    Rule a = MakeRule("r_000000000000007d", pa, "127.0.0.1", echo.port());
    Rule b = MakeRule("r_000000000000007e", pb, "127.0.0.1", echo.port());
    e.Apply({a, b});
    UdpClient ca;
    UdpClient cb;
    CHECK(ca.RoundTrip(pa, "a1") && cb.RoundTrip(pb, "b1"));
    CHECK(echo.DistinctSources() == 2);

    b.udpIdleSec = 30;  // a change in any field restarts that rule
    e.Apply({a, b});
    CHECK_MSG(ca.RoundTrip(pa, "a2"), "the unchanged rule keeps serving");
    CHECK_MSG(Find(e, a.id).stats.totalConnections == 1 && Find(e, a.id).stats.udpSessions == 1,
              "and keeps its session");
    CHECK(Find(e, b.id).stats.totalConnections == 0);  // fresh counters
    CHECK(cb.RoundTrip(pb, "b2"));
    CHECK_MSG(echo.DistinctSources() == 3, "the changed rule's session was closed and reopened");

    e.Apply({a});
    CHECK(pf_test::WaitUntil([&] { return CanBindUdp(pb); }, 5000));
    CHECK(ca.RoundTrip(pa, "a3"));
    CHECK(e.Snapshot().size() == 1);
    e.Stop();
}

}  // namespace

int main() {
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    const auto run = [](const char* name, void (*fn)()) {
        std::printf("== %s\n", name);
        std::fflush(stdout);
        const ULONGLONG t0 = GetTickCount64();
        fn();
        std::printf("   (%llu ms)\n", GetTickCount64() - t0);
        std::fflush(stdout);
    };
    run("direct, two clients, no crosstalk", TestDirectTwoClients);
    run("idle reclaim", TestIdleReclaim);
    run("session cap", TestSessionCap);
    run("via a node", TestViaNode);
    run("fail closed, failed-open cache", TestFailClosedAndFailureCache);
    run("relay reset ends the session", TestRelayResetEndsSession);
    run("statuses", TestStatuses);
    run("stop is bounded", TestStopIsBounded);
    run("stop leaves a straggler behind", TestStopLeavesStragglerBehind);
    run("apply restarts only the changed rule", TestApplyRestartsOnlyChanged);
    return pf_test::TestExitCode();
}
