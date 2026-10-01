// Integration, end to end: the real port-forwarder.exe, hosted the way the Ghost plugin host
// runs it (plugin_child.h) against a fake Ghost (fake_ghost.h), driven only through its
// management page's API -- what the user's clicks send.
//
//   1. Hosted: the receipt carries a valid uiUrl. Three rules are added through the page
//      API -- direct TCP, TCP through node n1, UDP through Ghost's active node -- and each
//      carries a round trip to an echo destination. The tunnel requests Ghost saw name exactly
//      what the rules say.
//   2. Ghost refuses the next tunnel: the client connection is closed, the destination sees
//      ZERO connections (fail closed, never a direct fallback) and the rule reports the code.
//   3. A rule is disabled and enabled again; log.write carries the start line and the rule
//      lines, and no line anywhere carries a client's port or a per-connection destination.
//   4. The stop event ends the process with code 0 within 3 s.
//   5. Restarted on the same data directory: the three rules are back, with the same ids, and
//      forward again.
//   6. Standalone on the same data directory (--no-browser --data-dir): stdin is not read, the
//      page answers, the direct rule forwards, and the two rules that need Ghost report
//      needs_ghost and hold neither port.
//
// argv[1] = path of port-forwarder.exe.

#include "echo_servers.h"
#include "fake_ghost.h"
#include "http_client.h"
#include "json_util.h"
#include "plugin_child.h"
#include "port_reserve.h"
#include "tcp_client.h"
#include "test_support.h"
#include "util_str.h"

#include <cstdio>
#include <set>
#include <string>
#include <vector>

using pf::json;
using pf_test::Child;
using pf_test::FakeGhost;
using pf_test::HttpReply;

namespace {

std::wstring g_exe;

// ---- The page API, as the page calls it ------------------------------------------------

struct Page {
    unsigned short port = 0;
    std::string prefix;

    std::string Path(const std::string& rel) const { return "/" + prefix + "/" + rel; }
    std::string Origin() const { return "http://127.0.0.1:" + std::to_string(port); }

    HttpReply Get(const std::string& rel) const {
        return pf_test::RawHttp(port, pf_test::BuildRequest("GET", Path(rel), port));
    }
    HttpReply Post(const std::string& rel, const json& body) const {
        return pf_test::RawHttp(
            port, pf_test::BuildRequest("POST", Path(rel), port, pf::DumpSafe(body), Origin(), "application/json"));
    }
    json State() const {
        const HttpReply r = Get("api/state");
        return r.status == 200 ? pf::ParseJsonNoThrow(r.body) : json();
    }
    // The rule with this id in api/state, or null.
    json Rule(const std::string& id) const {
        const json s = State();
        if (!s.is_object() || !s.contains("rules") || !s["rules"].is_array()) return json();
        for (const json& r : s["rules"]) {
            std::string rid;
            if (pf::JsonGetString(r, "id", &rid) && rid == id) return r;
        }
        return json();
    }
    std::string Status(const std::string& id) const {
        std::string st;
        pf::JsonGetString(Rule(id), "status", &st);
        return st;
    }
    std::string LastError(const std::string& id) const {
        const json r = Rule(id);
        if (!r.is_object() || !r.contains("stats") || !r["stats"].is_object()) return std::string();
        const json& st = r["stats"];
        if (!st.contains("lastError") || !st["lastError"].is_object()) return std::string();
        std::string code;
        pf::JsonGetString(st["lastError"], "code", &code);
        return code;
    }
    std::string Describe() const {
        const json s = State();
        if (!s.is_object() || !s.contains("rules") || !s["rules"].is_array()) return "api/state unavailable";
        std::string out = "ghost=" + pf::DumpSafe(s.value("ghost", json()));
        for (const json& r : s["rules"]) {
            out += "; " + pf::DumpSafe(r.value("name", json())) + " " + pf::DumpSafe(r.value("status", json())) + " " +
                   pf::DumpSafe(r.value("detail", json())) + " " + pf::DumpSafe(r.value("stats", json()));
        }
        return out;
    }
};

bool PageOf(const std::string& url, Page* page) { return pf_test::SplitUiUrl(url, &page->port, &page->prefix); }

json RuleBody(const std::string& name, const char* proto, int listenPort, const std::string& host, int remotePort,
              const json& egress) {
    json r = json::object();
    r["name"] = name;
    r["enabled"] = true;
    r["proto"] = proto;
    r["listen"] = json{{"addr", "127.0.0.1"}, {"port", listenPort}};
    r["remote"] = json{{"host", host}, {"port", remotePort}};
    r["egress"] = egress;
    return r;
}

// Adds a rule through the page; its id, or "" (the answer is printed).
std::string AddRule(const Page& page, const json& body) {
    long long port = 0;
    if (body.contains("listen") && body["listen"].is_object()) pf::JsonGetInt64(body["listen"], "port", &port);
    pf_test::ReleasePort(static_cast<int>(port));  // held until the plugin binds it
    const HttpReply r = page.Post("api/rules", body);
    std::string id;
    pf::JsonGetString(pf::ParseJsonNoThrow(r.body), "id", &id);
    CHECK_MSG(r.status == 200 && !id.empty(), (std::to_string(r.status) + " " + r.body).c_str());
    return id;
}

// ---- Clients -------------------------------------------------------------------------

unsigned short LocalPort(SOCKET s) {
    sockaddr_in a = {};
    int len = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) return 0;
    return ntohs(a.sin_port);
}

// One TCP round trip through 127.0.0.1:port; the client's own port goes to `clientPorts`.
bool TcpRoundTrip(int port, const std::string& msg, std::set<unsigned short>* clientPorts) {
    pf::UniqueSocket s = pf_test::Connect(port);
    if (!s) return false;
    clientPorts->insert(LocalPort(s.get()));
    return pf_test::RoundTrip(s.get(), msg);
}

// One UDP datagram to 127.0.0.1:port and its echo back from that port, within 5 s.
bool UdpRoundTrip(int port, const std::string& msg, std::set<unsigned short>* clientPorts) {
    pf::UniqueSocket s(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return false;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return false;
    clientPorts->insert(LocalPort(s.get()));
    DWORD tmo = 5000;
    setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    a.sin_port = htons(static_cast<u_short>(port));
    if (sendto(s.get(), msg.data(), static_cast<int>(msg.size()), 0, reinterpret_cast<sockaddr*>(&a), sizeof(a)) !=
        static_cast<int>(msg.size())) {
        return false;
    }
    char buf[2048];
    sockaddr_in from = {};
    int len = sizeof(from);
    const int n = recvfrom(s.get(), buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&from), &len);
    return n == static_cast<int>(msg.size()) && std::string(buf, static_cast<size_t>(n)) == msg &&
           ntohs(from.sin_port) == port;
}

// Nothing holds 127.0.0.1:port for UDP (an exclusive bind succeeds).
bool CanBindUdp(int port) {
    pf::UniqueSocket u(WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!u) return false;
    BOOL one = TRUE;
    setsockopt(u.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    return bind(u.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
}

// `n` appears in `text` as a token of its own: neither neighbour is a letter or a digit, so a
// port matches in "127.0.0.1:6240" or "port=6240" but not inside a hex rule id or a longer
// number.
bool ContainsNumber(const std::string& text, unsigned n) {
    const std::string d = std::to_string(n);
    auto alnum = [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
    };
    for (size_t pos = text.find(d); pos != std::string::npos; pos = text.find(d, pos + 1)) {
        const size_t end = pos + d.size();
        if ((pos == 0 || !alnum(text[pos - 1])) && (end >= text.size() || !alnum(text[end]))) return true;
    }
    return false;
}

std::vector<std::string> LogBodies(const FakeGhost& ghost) {
    std::vector<std::string> out;
    for (const auto& r : ghost.Requests()) {
        if (r.path == "/api/log-ingest") out.push_back(r.body);
    }
    return out;
}

bool LogHas(const FakeGhost& ghost, const std::string& needle) {
    for (const auto& b : LogBodies(ghost)) {
        if (b.find(needle) != std::string::npos) return true;
    }
    return false;
}

std::vector<json> TunnelBodies(const FakeGhost& ghost) {
    std::vector<json> out;
    for (const auto& r : ghost.Requests()) {
        if (r.path == "/api/upstream/tunnel") out.push_back(pf::ParseJsonNoThrow(r.body));
    }
    return out;
}

// ---- A hosted run ----------------------------------------------------------------------

// Starts the plugin hosted on `dataDir`; the page once api/state answers. The stop event is
// the caller's.
bool StartHosted(Child& c, FakeGhost& ghost, const std::string& stopEvent, const std::string& dataDir, Page* page) {
    if (!c.Start(pf_test::HostedEnv(stopEvent, dataDir, ghost.apiBase()))) return false;
    ghost.SetTargetPid(c.pid());  // Ghost duplicates tunnel sockets into the plugin's process
    if (!c.WriteStdin(pf::DumpSafe(pf_test::HostedHandshake(stopEvent, dataDir, ghost.apiBase())) + "\n")) return false;
    const std::string line = c.FirstLine(10000);
    const std::string url = pf_test::UiUrlOfReceipt(line);
    CHECK_MSG(!url.empty(), ("receipt: " + line).c_str());
    if (url.empty() || !PageOf(url, page)) return false;
    return pf_test::WaitUntil([&] { return page->Get("api/state").status == 200; }, 5000);
}

bool StopHosted(Child& c, HANDLE stopEvent) {
    SetEvent(stopEvent);
    DWORD code = 12345;
    const bool exited = c.ExitsWithin(3000, &code);
    CHECK_MSG(exited, "exits within 3 s of the stop event");
    CHECK_MSG(code == 0, ("exit code " + std::to_string(code)).c_str());
    return exited && code == 0;
}

struct Ids {
    std::string direct, nodeTcp, nodeUdp;
};

void HostedRun(FakeGhost& ghost, pf_test::TcpEchoServer& echo, const std::string& dataDir, const int ports[3], Ids* ids,
               std::set<unsigned short>* clientPorts) {
    const std::string name = pf_test::UniqueName("e2e");
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, pf::Utf8ToWide(name).c_str());
    CHECK(ev != nullptr);
    Child c(g_exe);
    Page page;
    const bool started = StartHosted(c, ghost, name, dataDir, &page);
    CHECK_MSG(started, "hosted plugin up, page answering");
    if (!started) {
        if (ev) CloseHandle(ev);
        return;
    }
    pf_test::FailureContext ctx([&] { return page.Describe() + " | ghost: " + ghost.Describe(); });

    // ---- 1. Three rules through the page, three round trips ----
    // The via-node TCP rule names the echo server by its IPv4 literal (the fake Ghost
    // connects to a literal as it is): a direct fallback would then reach the very same
    // server, so "zero connections" below can tell fail-closed from a fallback.
    ids->direct = AddRule(page, RuleBody("direct tcp", "tcp", ports[0], "127.0.0.1", echo.port(),
                                         json{{"kind", "direct"}}));
    ids->nodeTcp = AddRule(page, RuleBody("node tcp", "tcp", ports[1], "127.0.0.1", echo.port(),
                                          json{{"kind", "node"}, {"nodeId", "n1"}}));
    ids->nodeUdp = AddRule(page, RuleBody("node udp", "udp", ports[2], "echo.test", 9, json{{"kind", "active"}}));
    for (const std::string* id : {&ids->direct, &ids->nodeTcp, &ids->nodeUdp}) {
        CHECK_UNTIL(page.Status(*id) == "listening", 5000, page.Describe());
    }

    CHECK_MSG(TcpRoundTrip(ports[0], "hello, direct", clientPorts), "direct TCP round trip");
    const int echoBeforeNode = echo.Connections();
    CHECK_MSG(TcpRoundTrip(ports[1], "hello, node", clientPorts), "via-node TCP round trip");
    CHECK_EQ(echo.Connections(), echoBeforeNode + 1);  // the fake Ghost's own connection
    const int udpEchoedBefore = ghost.UdpEchoed();
    CHECK_MSG(UdpRoundTrip(ports[2], "hello, udp via node", clientPorts), "via-node UDP round trip");
    CHECK(ghost.UdpEchoed() > udpEchoedBefore);  // it went through the relay, not around it

    // Ghost was asked for exactly what the rules say, and only for the two via-node rules.
    const std::vector<json> tunnels = TunnelBodies(ghost);
    CHECK_EQ(tunnels.size(), static_cast<size_t>(2));
    if (tunnels.size() == 2) {
        CHECK_MSG(tunnels[0] == json({{"via", "node"}, {"nodeId", "n1"}, {"proto", "tcp"}, {"host", "127.0.0.1"},
                                      {"port", echo.port()}}),
                  pf::DumpSafe(tunnels[0]).c_str());
        CHECK_MSG(tunnels[1] == json({{"via", "active"}, {"proto", "udp"}, {"host", "echo.test"}, {"port", 9}}),
                  pf::DumpSafe(tunnels[1]).c_str());
    }

    // ---- 2. Ghost refuses the tunnel: closed, zero connections, the code on the rule ----
    ghost.SetTunnelError("upstream_unreachable");
    const int echoBefore = echo.Connections();
    {
        pf::UniqueSocket s = pf_test::Connect(ports[1]);
        CHECK(static_cast<bool>(s));
        if (s) {
            clientPorts->insert(LocalPort(s.get()));
            pf_test::SendAll(s.get(), "never forwarded");
            CHECK_MSG(pf_test::ClosedByPeer(s.get()), "the client connection is closed by the plugin");
        }
    }
    CHECK_UNTIL(page.LastError(ids->nodeTcp) == "upstream_unreachable", 5000, page.Describe());
    CHECK_MSG(!pf_test::WaitUntil([&] { return echo.Connections() != echoBefore; }, 1000),
              "the destination saw no connection: no direct fallback");
    ghost.SetTunnelError("");

    // ---- 3. Disable and enable a rule; what log.write carried ----
    CHECK(page.Post("api/rules/" + ids->direct + "/disable", json::object()).status == 200);
    CHECK_UNTIL(pf_test::CanBindTcp(ports[0]), 5000, page.Describe());
    CHECK(page.Post("api/rules/" + ids->direct + "/enable", json::object()).status == 200);
    CHECK_UNTIL(page.Status(ids->direct) == "listening", 5000, page.Describe());
    CHECK_MSG(TcpRoundTrip(ports[0], "hello again", clientPorts), "direct TCP after re-enabling");

    for (const char* needle : {"started (hosted)", "rule added: direct tcp", "rule added: node tcp",
                               "rule added: node udp", "rule disabled: direct tcp", "rule enabled: direct tcp"}) {
        CHECK_UNTIL(LogHas(ghost, needle), 10000, std::string("log.write never carried \"") + needle + "\"");
    }

    // ---- 4. Stop ----
    StopHosted(c, ev);
    // The last batch went out before the exit; the whole log is now known.
    CHECK(LogHas(ghost, "Port Forwarder stopping"));
    CloseHandle(ev);
}

// No line sent to log.write carries a client's port or the per-connection destination of
// the UDP rule.
void LogCarriesNoClientAddresses(const FakeGhost& ghost, const std::set<unsigned short>& clientPorts) {
    const std::vector<std::string> bodies = LogBodies(ghost);
    CHECK(!bodies.empty());
    CHECK(clientPorts.size() >= 5);  // every client above recorded its port
    for (const std::string& b : bodies) {
        for (unsigned short p : clientPorts) {
            CHECK_MSG(!ContainsNumber(b, p), ("a client port in a log line: " + std::to_string(p) + " in " + b).c_str());
        }
        CHECK_MSG(b.find("echo.test") == std::string::npos, b.c_str());
    }
}

// ---- 5. Restart on the same data directory ----

void RestartKeepsRules(FakeGhost& ghost, const std::string& dataDir, const int ports[3], const Ids& ids) {
    const std::string name = pf_test::UniqueName("e2e_restart");
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, pf::Utf8ToWide(name).c_str());
    Child c(g_exe);
    Page page;
    const bool started = StartHosted(c, ghost, name, dataDir, &page);
    CHECK_MSG(started, "restarted, page answering");
    if (started) {
        pf_test::FailureContext ctx([&] { return page.Describe(); });
        const json state = page.State();
        CHECK(state.is_object() && state.contains("rules") && state["rules"].is_array() && state["rules"].size() == 3);
        const std::pair<const std::string*, const char*> expect[] = {
            {&ids.direct, "direct tcp"}, {&ids.nodeTcp, "node tcp"}, {&ids.nodeUdp, "node udp"}};
        for (const auto& e : expect) {
            std::string n;
            CHECK_MSG(pf::JsonGetString(page.Rule(*e.first), "name", &n) && n == e.second, e.second);
            CHECK_UNTIL(page.Status(*e.first) == "listening", 5000, page.Describe());
        }
        std::set<unsigned short> ignored;
        CHECK_MSG(TcpRoundTrip(ports[0], "after restart, direct", &ignored), "direct after restart");
        CHECK_MSG(TcpRoundTrip(ports[1], "after restart, node", &ignored), "via node after restart");
        CHECK_MSG(UdpRoundTrip(ports[2], "after restart, udp", &ignored), "udp via node after restart");
    }
    StopHosted(c, ev);
    if (ev) CloseHandle(ev);
}

// ---- 6. Standalone on the same data directory ----

void StandaloneRun(const std::wstring& dataDir, const int ports[3], const Ids& ids) {
    Child c(g_exe);
    CHECK(c.Start({}, {L"--no-browser", L"--data-dir", dataDir}));
    const std::string probe = "unread";
    CHECK(c.WriteStdin(probe));  // no newline: a line reader would block before printing
    const std::vector<std::string> lines = c.Lines(2, 10000);
    CHECK_MSG(lines.size() == 2, "banner and the page address");
    if (lines.size() != 2) return;
    CHECK(lines[0].find("standalone") != std::string::npos);
    Page page;
    CHECK(PageOf(pf_test::UrlOfLine(lines[1]), &page));
    pf_test::FailureContext ctx([&] { return page.Describe(); });

    CHECK_UNTIL(page.Get("api/state").status == 200, 5000, "api/state");
    json state = page.State();
    CHECK(state.is_object() && state["hosted"] == false && state["ghost"] == "needs_ghost");
    CHECK_UNTIL(page.Status(ids.direct) == "listening", 5000, page.Describe());
    CHECK_UNTIL(page.Status(ids.nodeTcp) == "needs_ghost", 5000, page.Describe());
    CHECK_UNTIL(page.Status(ids.nodeUdp) == "needs_ghost", 5000, page.Describe());
    std::set<unsigned short> ignored;
    CHECK_MSG(TcpRoundTrip(ports[0], "standalone, direct", &ignored), "the direct rule forwards standalone");
    CHECK_MSG(pf_test::CanBindTcp(ports[1]), "a rule that needs Ghost does not listen standalone (tcp)");
    CHECK_MSG(CanBindUdp(ports[2]), "a rule that needs Ghost does not listen standalone (udp)");
    CHECK_MSG(c.StdinUnread() == probe.size(), "standalone never reads stdin");

    CHECK(page.Post("api/quit", json::object()).status == 200);
    DWORD code = 12345;
    CHECK_MSG(c.ExitsWithin(3000, &code), "quits within 3 s");
    CHECK(code == 0);
}

std::wstring Backslashes(std::wstring p) {
    for (auto& ch : p)
        if (ch == L'/') ch = L'\\';
    return p;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_end_to_end <port-forwarder.exe>\n");
        return 2;
    }
    g_exe = Backslashes(argv[1]);

    pf_test::WinsockScope wsa;
    CHECK(wsa.ok());
    FakeGhost ghost;
    CHECK(ghost.Start());
    pf_test::TcpEchoServer echo;
    CHECK(echo.Start());
    pf_test::ScopedTempDir dir;
    CHECK(dir.ok());
    const std::string dataDir = pf::WideToUtf8(dir.path());
    const int ports[3] = {pf_test::ReservePort(), pf_test::ReservePort(), pf_test::ReservePort()};
    CHECK(ports[0] && ports[1] && ports[2]);

    Ids ids;
    std::set<unsigned short> clientPorts;
    HostedRun(ghost, echo, dataDir, ports, &ids, &clientPorts);
    LogCarriesNoClientAddresses(ghost, clientPorts);
    RestartKeepsRules(ghost, dataDir, ports, ids);
    StandaloneRun(dir.path(), ports, ids);

    ghost.Stop();
    echo.Stop();
    return pf_test::TestExitCode();
}
