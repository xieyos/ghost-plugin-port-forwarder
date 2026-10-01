// Functional: upstream.list and upstream.tunnel from the plugin's side (tunnel_client.h)
// against the fake Ghost -- which hands over sockets it connected DIRECTLY to a local echo
// server, exactly as Ghost hands over sockets it connected through a node. Adoption and a
// round trip for TCP and UDP; every way an answer can be wrong; the one retried code; a
// lost answer sent once; the in-flight limit; the node list and its cache.

#include "echo_servers.h"
#include "fake_clock.h"
#include "fake_ghost.h"
#include "test_support.h"
#include "tunnel_client.h"

#include <mstcpip.h>

#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using pf::EgressKind;
using pf::GhostApi;
using pf::GhostApiOptions;
using pf::json;
using pf::Proto;
using pf::TunnelClient;
using pf::TunnelClientOptions;
using pf::TunnelResult;
using pf_test::FakeClock;
using pf_test::FakeGhost;
using pf_test::TcpEchoServer;
namespace A = pf::api_err;
namespace T = pf::tunnel_err;

namespace {

const char* kToken = "tok-123";
const char* kTunnel = "/api/upstream/tunnel";
const char* kList = "/api/upstream/list";

// One fake Ghost, an echo server behind "echo.test", an API client and a tunnel client.
struct Rig {
    TcpEchoServer echo;
    FakeGhost fg;
    FakeClock clock;
    std::unique_ptr<GhostApi> api;
    std::unique_ptr<TunnelClient> tc;

    explicit Rig(TunnelClientOptions extra = TunnelClientOptions(), bool fakeClock = true) {
        CHECK(echo.Start());
        CHECK(fg.Start());
        fg.MapHost("echo.test", echo.port());
        GhostApiOptions o;
        o.apiBase = fg.apiBase();
        o.token = kToken;
        o.clock = fakeClock ? &clock : nullptr;
        api = std::make_unique<GhostApi>(o);
        extra.api = api.get();
        extra.permitted = true;
        if (fakeClock) extra.clock = &clock;
        tc = std::make_unique<TunnelClient>(extra);
    }
};

bool RoundTripTcp(SOCKET s, const std::string& msg) {
    if (send(s, msg.data(), static_cast<int>(msg.size()), 0) != static_cast<int>(msg.size())) return false;
    std::string got;
    char buf[1024];
    DWORD tmo = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    while (got.size() < msg.size()) {
        const int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) return false;
        got.append(buf, static_cast<size_t>(n));
    }
    return got == msg;
}

bool RoundTripUdp(SOCKET s, const std::string& msg) {
    DWORD tmo = 5000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    if (send(s, msg.data(), static_cast<int>(msg.size()), 0) != static_cast<int>(msg.size())) return false;
    char buf[2048];
    const int n = recv(s, buf, sizeof(buf), 0);
    return n == static_cast<int>(msg.size()) && std::string(buf, static_cast<size_t>(n)) == msg;
}

int SockType(SOCKET s) {
    int type = 0;
    int len = sizeof(type);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &len) != 0) return -1;
    return type;
}

json LastTunnelBody(const FakeGhost& fg) {
    const auto reqs = fg.Requests();
    for (auto it = reqs.rbegin(); it != reqs.rend(); ++it) {
        if (it->path == kTunnel) return pf::ParseJsonNoThrow(it->body);
    }
    return json();
}

void TestTcpAdoption() {
    Rig rig;
    TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
    CHECK_MSG(r.ok(), r.code.c_str());
    CHECK(r.sock.valid());
    CHECK(r.node.id == "n1" && r.node.name == "Node One" && r.node.type == "socks5");
    CHECK(r.requests == 1);
    CHECK(rig.echo.Connections() == 1);
    if (r.sock.valid()) {
        CHECK(SockType(r.sock.get()) == SOCK_STREAM);
        CHECK_MSG(RoundTripTcp(r.sock.get(), "hello through the tunnel"), "TCP round trip on the adopted socket");
        DWORD flags = 0;
        CHECK(GetHandleInformation(reinterpret_cast<HANDLE>(r.sock.get()), &flags));
        CHECK_MSG((flags & HANDLE_FLAG_INHERIT) == 0, "adopted with WSA_FLAG_NO_HANDLE_INHERIT");
        BOOL nodelay = FALSE;
        int len = sizeof(nodelay);
        CHECK(getsockopt(r.sock.get(), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&nodelay), &len) == 0);
        CHECK_MSG(nodelay, "TCP_NODELAY on");
        DWORD ka = 0;
        len = sizeof(ka);
        CHECK(getsockopt(r.sock.get(), SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<char*>(&ka), &len) == 0);
        CHECK_MSG(ka != 0, "keepalive on");
    }
    CHECK(LastTunnelBody(rig.fg) ==
          json({{"via", "node"}, {"nodeId", "n1"}, {"proto", "tcp"}, {"host", "echo.test"}, {"port", 80}}));

    // Active: via "active", and no nodeId key at all.
    TunnelResult a = rig.tc->OpenTunnel(EgressKind::Active, "ignored", Proto::Tcp, "echo.test", 443);
    CHECK_MSG(a.ok(), a.code.c_str());
    CHECK(a.node.id == "n1");
    CHECK(LastTunnelBody(rig.fg) == json({{"via", "active"}, {"proto", "tcp"}, {"host", "echo.test"}, {"port", 443}}));
    if (a.sock.valid()) CHECK(RoundTripTcp(a.sock.get(), "second"));
}

void TestUdpAdoption() {
    Rig rig;
    TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Udp, "echo.test", 53);
    CHECK_MSG(r.ok(), r.code.c_str());
    CHECK(r.maxPayload == 65497 && r.idleTimeoutMs == 120000);
    if (r.sock.valid()) {
        CHECK(SockType(r.sock.get()) == SOCK_DGRAM);
        DWORD flags = 0;
        CHECK(GetHandleInformation(reinterpret_cast<HANDLE>(r.sock.get()), &flags));
        CHECK_MSG((flags & HANDLE_FLAG_INHERIT) == 0, "UDP: not inheritable either");
        CHECK_MSG(RoundTripUdp(r.sock.get(), "datagram one"), "UDP round trip on the adopted socket");
        CHECK(RoundTripUdp(r.sock.get(), "datagram two"));
    }
    CHECK(LastTunnelBody(rig.fg) ==
          json({{"via", "node"}, {"nodeId", "n1"}, {"proto", "udp"}, {"host", "echo.test"}, {"port", 53}}));
    CHECK(rig.fg.UdpEchoed() == 2);
}

// Every answer whose socket bytes cannot be trusted fails without a socket, after one
// request.
void TestBadAnswers() {
    struct Case {
        const char* label;
        std::function<void(json&)> mutate;
    };
    const std::vector<Case> cases = {
        {"protocolInfoBytes one short", [](json& j) { j["protocolInfoBytes"] = pf::kProtocolInfoBytes - 1; }},
        {"protocolInfoBytes one long", [](json& j) { j["protocolInfoBytes"] = pf::kProtocolInfoBytes + 1; }},
        {"protocolInfoBytes a string", [](json& j) { j["protocolInfoBytes"] = "628"; }},
        {"protocolInfoBytes a float", [](json& j) { j["protocolInfoBytes"] = 628.0; }},
        {"protocolInfoBytes missing", [](json& j) { j.erase("protocolInfoBytes"); }},
        // 628 bytes are 840 characters ending in "=="; four fewer decode to exactly 627.
        {"627 decoded bytes, size field agrees (627)",
         [](json& j) {
             std::string b = j["protocolInfo"].get<std::string>();
             j["protocolInfo"] = b.substr(0, b.size() - 4);
             j["protocolInfoBytes"] = pf::kProtocolInfoBytes - 1;
         }},
        {"627 decoded bytes, size field says 628",
         [](json& j) {
             std::string b = j["protocolInfo"].get<std::string>();
             j["protocolInfo"] = b.substr(0, b.size() - 4);
         }},
        {"bad base64 character", [](json& j) { j["protocolInfo"] = "!" + j["protocolInfo"].get<std::string>().substr(1); }},
        {"url-safe base64", [](json& j) { j["protocolInfo"] = std::string(840, '-'); }},
        {"base64 with a line break",
         [](json& j) {
             std::string b = j["protocolInfo"].get<std::string>();
             j["protocolInfo"] = b.substr(0, 76) + "\n" + b.substr(76);
         }},
        {"protocolInfo missing", [](json& j) { j.erase("protocolInfo"); }},
        {"protocolInfo a number", [](json& j) { j["protocolInfo"] = 1; }},
        {"status not ok", [](json& j) { j["status"] = "okay"; }},
        // The socket bytes are fine but the rest is not: adopted, then closed.
        {"proto in the answer differs", [](json& j) { j["proto"] = "udp"; }},
        {"node missing", [](json& j) { j.erase("node"); }},
        {"node.id not a string", [](json& j) { j["node"]["id"] = 1; }},
    };
    for (const auto& c : cases) {
        Rig rig;
        rig.fg.SetTunnelMutator(c.mutate);
        TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
        CHECK_MSG(r.code == A::kBadResponse, c.label);
        CHECK_MSG(!r.sock.valid(), c.label);
        CHECK_MSG(rig.fg.CountPath(kTunnel) == 1, c.label);
    }

    // A UDP answer without its UDP fields.
    for (const char* key : {"maxPayload", "idleTimeoutMs"}) {
        Rig rig;
        rig.fg.SetTunnelMutator([key](json& j) { j.erase(key); });
        TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Udp, "echo.test", 53);
        CHECK_MSG(r.code == A::kBadResponse && !r.sock.valid(), key);
    }

    // Real WSAPROTOCOL_INFOW bytes of a TCP socket, never adopted before: asked for as
    // UDP they are refused (and the adopted handle closed); one byte short, nothing is
    // called at all.
    {
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        CHECK(s != INVALID_SOCKET);
        WSAPROTOCOL_INFOW info = {};
        CHECK(WSADuplicateSocketW(s, GetCurrentProcessId(), &info) == 0);
        closesocket(s);
        const std::string bytes(reinterpret_cast<const char*>(&info), sizeof(info));
        pf::UniqueSocket out;
        CHECK_MSG(pf::AdoptProtocolInfo(bytes.substr(1), Proto::Tcp, &out) == A::kBadResponse, "627 bytes");
        CHECK(!out.valid());
        CHECK_MSG(pf::AdoptProtocolInfo(bytes, Proto::Udp, &out) == T::kAdoptFailed, "TCP bytes for a UDP tunnel");
        CHECK(!out.valid());
    }
}

void TestPluginNotRunningRetried() {
    {
        Rig rig;
        rig.fg.QueueTunnelErrors({"plugin_not_running", "plugin_not_running", "plugin_not_running"});
        TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
        CHECK_MSG(r.ok(), r.code.c_str());
        CHECK(r.requests == 4);
        CHECK(rig.fg.CountPath(kTunnel) == 4);
        CHECK((rig.clock.Waits() == std::vector<uint32_t>{200, 200, 200}));
        if (r.sock.valid()) CHECK(RoundTripTcp(r.sock.get(), "after retries"));
    }
    {
        Rig rig;
        rig.fg.SetTunnelError("plugin_not_running");
        TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
        CHECK(r.code == "plugin_not_running" && !r.sock.valid());
        // Requests at 0, 200, ..., 5000 ms on the fake clock: 26, then it gives up.
        CHECK_MSG(rig.fg.CountPath(kTunnel) == 26, "retries end after 5 s");
        CHECK(r.requests == 26);
    }
    // Every other code is final after one request.
    const char* finals[] = {"upstream_unreachable", "upstream_timeout", "upstream_auth_failed", "upstream_refused",
                            "upstream_not_found",   "tunnel_limit",     "tunnel_failed",       "tunnel_unavailable",
                            "tunnel_unsupported",   "bad_target"};
    for (const char* code : finals) {
        Rig rig;
        rig.fg.SetTunnelError(code);
        TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
        CHECK_MSG(r.code == code && !r.sock.valid(), code);
        CHECK_MSG(rig.fg.CountPath(kTunnel) == 1, code);
        CHECK_MSG(rig.echo.Connections() == 0, code);
    }
}

void TestLostAnswerSentOnce() {
    Rig rig;
    // A pooled connection first, so that a client which kept connections alive would be
    // tempted to resend on a fresh one when this one is cut.
    CHECK(rig.tc->ListNodes().ok());
    rig.fg.SetTunnelDrop(true);
    TunnelResult r = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
    CHECK(r.code == A::kGhostUnreachable && !r.sock.valid());
    CHECK(r.requests == 1);
    CHECK_MSG(rig.fg.CountPath(kTunnel) == 1, "an answer that never came is never asked for again");

    // The same over a fresh client (no pooled connection).
    Rig rig2;
    rig2.fg.SetTunnelDrop(true);
    TunnelResult r2 = rig2.tc->OpenTunnel(EgressKind::Active, "", Proto::Udp, "echo.test", 53);
    CHECK(r2.code == A::kGhostUnreachable);
    CHECK(rig2.fg.CountPath(kTunnel) == 1);
}

void TestInFlightLimit() {
    TunnelClientOptions o;
    o.slotWaitMs = 300;
    Rig rig(o, /*fakeClock=*/false);
    rig.fg.SetTunnelDelayMs(2000);
    constexpr int kThreads = pf::kMaxTunnelsInFlight + 1;
    std::vector<TunnelResult> results(kThreads);
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            results[static_cast<size_t>(i)] = rig.tc->OpenTunnel(EgressKind::Node, "n1", Proto::Tcp, "echo.test", 80);
        });
    }
    CHECK(pf_test::WaitUntil([&] { return rig.fg.TunnelsInProgress() == pf::kMaxTunnelsInFlight; }, 10000));
    CHECK_MSG(rig.tc->InFlight() == pf::kMaxTunnelsInFlight, "eight slots taken");
    for (auto& t : threads) t.join();
    int ok = 0;
    int limited = 0;
    for (const auto& r : results) {
        if (r.ok()) ++ok;
        if (r.code == T::kTunnelLimit) {
            ++limited;
            CHECK(r.requests == 0);
        }
    }
    CHECK(ok == pf::kMaxTunnelsInFlight);
    CHECK_MSG(limited == 1, "the ninth caller gives up locally");
    CHECK_MSG(rig.fg.CountPath(kTunnel) == pf::kMaxTunnelsInFlight, "and never sends its request");
    CHECK(rig.tc->InFlight() == 0);
}

void TestPreconditions() {
    // Standalone: no API at all.
    TunnelClient standalone{TunnelClientOptions()};
    CHECK(standalone.OpenTunnel(EgressKind::Active, "", Proto::Tcp, "echo.test", 80).code == T::kNeedsGhost);
    CHECK(standalone.ListNodes().code == T::kNeedsGhost);

    Rig rig;
    TunnelClientOptions o;
    o.api = rig.api.get();
    o.permitted = false;
    TunnelClient noPerm(o);
    CHECK(noPerm.OpenTunnel(EgressKind::Active, "", Proto::Tcp, "echo.test", 80).code == T::kPermissionMissing);
    CHECK(noPerm.ListNodes().code == T::kPermissionMissing);
    CHECK(rig.tc->OpenTunnel(EgressKind::Direct, "", Proto::Tcp, "echo.test", 80).code == T::kBadEgress);
    CHECK(rig.tc->OpenTunnel(EgressKind::Node, "a b", Proto::Tcp, "echo.test", 80).code == T::kBadEgress);
    CHECK(rig.tc->OpenTunnel(EgressKind::Node, "", Proto::Tcp, "echo.test", 80).code == T::kBadEgress);
    CHECK_MSG(rig.fg.Requests().empty(), "none of these sent anything");

    // After a 401: ghost_unavailable, and nothing more is sent.
    rig.fg.SetUnauthorized(true);
    CHECK(rig.tc->OpenTunnel(EgressKind::Active, "", Proto::Tcp, "echo.test", 80).code == A::kGhostUnavailable);
    CHECK(rig.fg.CountPath(kTunnel) == 1);
    rig.fg.SetUnauthorized(false);
    CHECK(rig.tc->OpenTunnel(EgressKind::Active, "", Proto::Tcp, "echo.test", 80).code == A::kGhostUnavailable);
    CHECK(rig.tc->ListNodes().code == A::kGhostUnavailable);
    CHECK(rig.fg.Requests().size() == 1);

    // Shutdown ends the retry wait.
    Rig rig3;
    rig3.tc->Shutdown();
    CHECK(rig3.tc->OpenTunnel(EgressKind::Active, "", Proto::Tcp, "echo.test", 80).code == A::kCancelled);
    CHECK(rig3.fg.Requests().empty());
}

void TestListNodes() {
    Rig rig;
    pf::NodeList l = rig.tc->ListNodes();
    CHECK_MSG(l.ok(), l.code.c_str());
    CHECK(l.hasActive && l.active == "n1");
    CHECK(l.nodes.size() == 2);
    if (l.nodes.size() == 2) {
        CHECK(l.nodes[0].id == "n1" && l.nodes[0].name == "Node One" && l.nodes[0].type == "socks5" &&
              l.nodes[0].active && l.nodes[0].valid && l.nodes[0].udp);
        CHECK(l.nodes[1].id == "n2" && l.nodes[1].type == "http" && !l.nodes[1].active && !l.nodes[1].udp);
    }
    CHECK(rig.fg.CountPath(kList) == 1);
    CHECK(rig.tc->ListNodes().ok());
    CHECK_MSG(rig.fg.CountPath(kList) == 1, "cached");
    rig.clock.Advance(pf::kNodeListCacheMs - 1);
    CHECK(rig.tc->ListNodes().ok());
    CHECK_MSG(rig.fg.CountPath(kList) == 1, "still cached at 9.999 s");
    rig.clock.Advance(1);
    CHECK(rig.tc->ListNodes().ok());
    CHECK_MSG(rig.fg.CountPath(kList) == 2, "fetched again at 10 s");
    CHECK(rig.tc->ListNodes(/*forceRefresh=*/true).ok());
    CHECK(rig.fg.CountPath(kList) == 3);

    // Failures are not cached.
    rig.fg.SetListBody(R"({"status":"ok","active":null,"nodes":{}})");
    CHECK(rig.tc->ListNodes(true).code == A::kBadResponse);
    rig.fg.SetListBody(R"({"status":"ok","active":null,"nodes":[{"id":"n1","name":"x","type":"socks5","active":true,"valid":true,"udp":"yes"},{"id":"n7","name":"y","type":"http","active":false,"valid":false,"udp":false}]})");
    l = rig.tc->ListNodes(true);
    CHECK(l.ok() && !l.hasActive && l.nodes.size() == 1 && l.nodes[0].id == "n7" && !l.nodes[0].valid);
}

}  // namespace

int main() {
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    TestTcpAdoption();
    TestUdpAdoption();
    TestBadAnswers();
    TestPluginNotRunningRetried();
    TestLostAnswerSentOnce();
    TestInFlightLimit();
    TestPreconditions();
    TestListNodes();
    return pf_test::TestExitCode();
}
