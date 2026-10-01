// Functional: the management page's server and API over real HTTP (ui_server.h, app.h).
//
// Every request goes out byte for byte as written (support/http_client.h), so the checks the
// server makes on Host, Origin, Content-Type, sizes and the path prefix are each exercised by
// a request that is wrong in exactly that one way. Behind the transport: rules are added,
// changed, enabled, disabled and deleted through the API, judged by the server (the page's
// own checks are only a convenience), saved to rules.json and run by the engine.

#include "app.h"
#include "fake_ghost.h"
#include "http_client.h"
#include "port_reserve.h"
#include "rule_store.h"
#include "test_support.h"
#include "tunnel_client.h"
#include "tunnel_source.h"
#include "ui_server.h"
#include "util_str.h"

#include <atomic>
#include <cstdio>
#include <functional>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

using pf::json;
using pf_test::BuildRequest;
using pf_test::HttpReply;
using pf_test::RawHttp;

namespace {

const char* kLanAddr = "192.0.2.10";  // the one "local" adapter address the rigs report

// A listen or remote port for a rule, held for TCP and UDP (support/port_reserve.h) until
// the rule that listens on it is posted (Rig::Post lets it go): nothing else on the machine
// can take it in between.
int FreePort() { return pf_test::ReservePort(); }

struct RigOptions {
    bool hosted = false;
    bool load = true;
    std::string frameAncestor;
    int maxConnections = pf::kUiMaxConnections;
    DWORD requestTimeoutMs = pf::kUiRequestTimeoutMs;
    bool permitted = false;
    std::shared_ptr<pf::GhostApi> api;
    // Runs on the data directory before the rules are loaded.
    std::function<void(const std::wstring&)> prepare;
};

struct Rig {
    pf_test::ScopedTempDir dir;
    // What the App is told this machine's addresses are; a test may change it.
    std::shared_ptr<std::vector<std::string>> addrs =
        std::make_shared<std::vector<std::string>>(std::vector<std::string>{kLanAddr});
    std::shared_ptr<std::atomic<int>> quits = std::make_shared<std::atomic<int>>(0);
    std::shared_ptr<pf::App> app;
    std::unique_ptr<pf::UiServer> ui;
    unsigned short port = 0;
    std::string prefix;

    std::string Origin() const { return "http://127.0.0.1:" + std::to_string(port); }
    std::string P(const std::string& sub) const { return "/" + prefix + "/" + sub; }

    HttpReply Get(const std::string& sub) const { return RawHttp(port, BuildRequest("GET", P(sub), port)); }
    HttpReply Post(const std::string& sub, const json& body) const {
        // The rule may listen on its port as soon as it is saved.
        if (body.is_object() && body.contains("listen") && body["listen"].is_object()) {
            long long p = 0;
            if (pf::JsonGetInt64(body["listen"], "port", &p)) pf_test::ReleasePort(static_cast<int>(p));
        }
        return RawHttp(port, BuildRequest("POST", P(sub), port, pf::DumpSafe(body), Origin(), "application/json"));
    }
    json State() const { return pf::ParseJsonNoThrow(Get("api/state").body); }
    // The rule with `id` in api/state, or null.
    json RuleInState(const std::string& id) const {
        const json s = State();
        if (!s.is_object() || !s.contains("rules") || !s["rules"].is_array()) return json();
        for (const json& r : s["rules"]) {
            if (r.is_object() && r.value("id", std::string()) == id) return r;
        }
        return json();
    }
};

std::unique_ptr<Rig> MakeRig(const RigOptions& o) {
    auto rig = std::make_unique<Rig>();
    if (!rig->dir.ok()) return nullptr;
    if (o.prepare) o.prepare(rig->dir.path());
    pf::AppOptions ao;
    ao.hosted = o.hosted;
    ao.dataDir = rig->dir.path();
    ao.lang = o.hosted ? "zh" : "";
    ao.permitted = o.permitted;
    if (o.api) {
        pf::TunnelClientOptions to;
        to.api = o.api.get();
        to.permitted = o.permitted;
        auto client = std::make_shared<pf::TunnelClient>(to);
        ao.nodes = client;
        ao.tunnel = std::make_shared<pf::ClientTunnelSource>(o.api, client, o.permitted);
    }
    auto addrs = rig->addrs;
    ao.localAddrs = [addrs] { return *addrs; };
    if (!o.hosted) {
        auto quits = rig->quits;
        ao.onQuit = [quits] { ++*quits; };
    }
    rig->app = std::make_shared<pf::App>(ao);
    if (o.load) {
        rig->app->LoadRules();
        rig->app->StartEngine();
    }
    pf::UiServerOptions uo;
    auto app = rig->app;
    uo.handler = [app](const pf::UiRequest& r) { return app->Handle(r); };
    uo.frameAncestor = o.frameAncestor;
    uo.maxConnections = o.maxConnections;
    uo.requestTimeoutMs = o.requestTimeoutMs;
    rig->ui = std::make_unique<pf::UiServer>(uo);
    std::string err;
    if (!rig->ui->Start(&err)) {
        std::fprintf(stderr, "UiServer::Start: %s\n", err.c_str());
        return nullptr;
    }
    rig->port = rig->ui->port();
    rig->prefix = rig->ui->prefix();
    return rig;
}

json TcpRule(const std::string& name, int listenPort, int remotePort, bool enabled = true) {
    json r = json::object();
    r["name"] = name;
    r["enabled"] = enabled;
    r["proto"] = "tcp";
    r["listen"] = json{{"addr", "127.0.0.1"}, {"port", listenPort}};
    r["remote"] = json{{"host", "127.0.0.1"}, {"port", remotePort}};
    r["egress"] = json{{"kind", "direct"}};
    return r;
}

std::string ErrorOf(const HttpReply& r) {
    const json j = pf::ParseJsonNoThrow(r.body);
    std::string e;
    pf::JsonGetString(j, "error", &e);
    return e;
}

std::string IdOf(const HttpReply& r) {
    const json j = pf::ParseJsonNoThrow(r.body);
    std::string id;
    pf::JsonGetString(j, "id", &id);
    return id;
}

// ---- Unit-level pieces -----------------------------------------------------------------------

void CspAndUrlRules() {
    CHECK(pf::UiCsp("http://127.0.0.1:23551") ==
          "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors http://127.0.0.1:23551");
    CHECK(pf::UiCsp("") == "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
    // Anything but a plain loopback origin frames nothing.
    CHECK(pf::UiCsp("http://evil.example:23551").find("frame-ancestors 'none'") != std::string::npos);
    CHECK(pf::UiCsp("http://127.0.0.1:23551; script-src *").find("frame-ancestors 'none'") != std::string::npos);
    CHECK(pf::UiCsp("http://127.0.0.1:0").find("frame-ancestors 'none'") != std::string::npos);

    const std::string p32(32, 'a');
    CHECK(pf::IsUiUrlShaped("http://127.0.0.1:53211/" + p32 + "/"));
    CHECK(pf::IsUiUrlShaped("http://127.0.0.1:1/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:80/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:23551/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:0/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:65536/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:123456/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:5321"));
    CHECK(!pf::IsUiUrlShaped("https://127.0.0.1:5321/"));
    CHECK(!pf::IsUiUrlShaped("http://localhost:5321/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:5321/a b/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:5321/\"/"));
    CHECK(!pf::IsUiUrlShaped("http://127.0.0.1:5321/" + std::string(2048, 'a')));

    CHECK(pf::IsJsonContentType("application/json"));
    CHECK(pf::IsJsonContentType("Application/JSON; charset=utf-8"));
    CHECK(!pf::IsJsonContentType("application/jsonx"));
    CHECK(!pf::IsJsonContentType("text/plain"));
    CHECK(!pf::IsJsonContentType("application/x-www-form-urlencoded"));
}

// ---- Transport checks ------------------------------------------------------------------------

void ServesThePageWithItsHeaders() {
    RigOptions o;
    o.hosted = true;
    o.frameAncestor = "http://127.0.0.1:23551";
    auto rig = MakeRig(o);
    CHECK(rig != nullptr);
    if (!rig) return;
    CHECK(rig->prefix.size() == 32 && rig->prefix.find_first_not_of("0123456789abcdef") == std::string::npos);
    CHECK(pf::IsUiUrlShaped(rig->ui->url()));
    CHECK(rig->ui->url() == "http://127.0.0.1:" + std::to_string(rig->port) + "/" + rig->prefix + "/");

    const HttpReply page = rig->Get("");
    CHECK_MSG(page.status == 200, page.raw.substr(0, 200).c_str());
    CHECK(page.Header("Content-Security-Policy") ==
          "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors http://127.0.0.1:23551");
    CHECK(page.Header("X-Content-Type-Options") == "nosniff");
    CHECK(page.Header("Referrer-Policy") == "no-referrer");
    CHECK(page.Header("Cache-Control") == "no-store");
    CHECK(page.Header("Connection") == "close");
    CHECK(page.Header("Content-Type") == "text/html; charset=utf-8");
    CHECK(page.body.find("<title>") != std::string::npos);
    CHECK(page.body.find("app.js") != std::string::npos);
    CHECK(std::to_string(page.body.size()) == page.Header("Content-Length"));

    const HttpReply js = rig->Get("app.js");
    CHECK(js.status == 200 && js.Header("Content-Type") == "text/javascript; charset=utf-8" && !js.body.empty());
    const HttpReply css = rig->Get("app.css");
    CHECK(css.status == 200 && css.Header("Content-Type") == "text/css; charset=utf-8" && !css.body.empty());
    // An error answer carries the same headers.
    const HttpReply nf = rig->Get("nothing-here");
    CHECK(nf.status == 404 && ErrorOf(nf) == pf::ui_err::kNotFound);
    CHECK(nf.Header("Content-Security-Policy") == page.Header("Content-Security-Policy"));

    // Standalone: nobody may frame the page.
    auto alone = MakeRig(RigOptions());
    CHECK(alone != nullptr);
    if (alone) {
        CHECK(alone->Get("").Header("Content-Security-Policy") ==
              "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
    }
}

void HostMustBeExact() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const std::string path = rig->P("api/state");
    const std::string p = std::to_string(rig->port);
    auto req = [&](const std::string& hostLines) {
        return RawHttp(rig->port, "GET " + path + " HTTP/1.1\r\n" + hostLines + "Connection: close\r\n\r\n");
    };
    CHECK(req("Host: 127.0.0.1:" + p + "\r\n").status == 200);
    const HttpReply rebinding = req("Host: evil.example:" + p + "\r\n");
    CHECK(rebinding.status == 400 && ErrorOf(rebinding) == pf::ui_err::kBadHost);
    CHECK(req("Host: localhost:" + p + "\r\n").status == 400);
    CHECK(req("Host: 127.0.0.1\r\n").status == 400);
    CHECK(req("Host: 127.0.0.1:" + std::to_string(rig->port + 1) + "\r\n").status == 400);
    CHECK(req("").status == 400);
    CHECK(req("Host: 127.0.0.1:" + p + "\r\nHost: 127.0.0.1:" + p + "\r\n").status == 400);
    // A rebinding page gets nothing, not even the page itself.
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\nHost: rebind.example:" + p + "\r\n\r\n").status ==
          400);
}

void PrefixIsRequired() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    auto get = [&](const std::string& target) { return RawHttp(rig->port, BuildRequest("GET", target, rig->port)); };
    CHECK(get(rig->P("")).status == 200);
    CHECK(get(rig->P("api/state")).status == 200);
    CHECK(get("/").status == 404);
    CHECK(get("/api/state").status == 404);
    CHECK(get("/app.js").status == 404);
    CHECK(get("/" + rig->prefix).status == 404);
    std::string wrong = rig->prefix;
    wrong[0] = wrong[0] == 'a' ? 'b' : 'a';
    CHECK(get("/" + wrong + "/").status == 404);
    CHECK(get("/" + wrong + "/api/state").status == 404);
    CHECK(get("/" + rig->prefix + "x/").status == 404);
    CHECK(get("/" + rig->prefix.substr(0, 31) + "/").status == 404);
    // A query string is not part of the path.
    CHECK(get(rig->P("api/state?x=1")).status == 200);
}

void PostNeedsOriginAndJson() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const std::string body = pf::DumpSafe(TcpRule("o", FreePort(), FreePort(), false));
    const std::string path = rig->P("api/rules");
    auto post = [&](const std::string& origin, const std::string& type) {
        return RawHttp(rig->port, BuildRequest("POST", path, rig->port, body, origin, type));
    };
    const HttpReply noOrigin = post("", "application/json");
    CHECK(noOrigin.status == 403 && ErrorOf(noOrigin) == pf::ui_err::kForbiddenOrigin);
    CHECK(post("http://evil.example", "application/json").status == 403);
    CHECK(post("http://localhost:" + std::to_string(rig->port), "application/json").status == 403);
    CHECK(post("null", "application/json").status == 403);
    CHECK(post(rig->Origin() + "/", "application/json").status == 403);
    const HttpReply plain = post(rig->Origin(), "text/plain");
    CHECK(plain.status == 403 && ErrorOf(plain) == pf::ui_err::kBadContentType);
    CHECK(post(rig->Origin(), "").status == 403);
    CHECK(post(rig->Origin(), "application/x-www-form-urlencoded").status == 403);
    CHECK(post(rig->Origin(), "multipart/form-data; boundary=x").status == 403);
    // Two Origin headers are not one.
    CHECK(RawHttp(rig->port, BuildRequest("POST", path, rig->port, body, rig->Origin(), "application/json",
                                          "Origin: " + rig->Origin() + "\r\n"))
              .status == 403);
    // None of the refused requests added anything.
    const json s = rig->State();
    CHECK(s.is_object() && s["rules"].is_array() && s["rules"].empty());

    const HttpReply good = post(rig->Origin(), "application/json; charset=utf-8");
    CHECK_MSG(good.status == 200, good.body.c_str());
    // A GET that names a foreign Origin is refused too.
    const HttpReply foreign =
        RawHttp(rig->port, BuildRequest("GET", rig->P("api/state"), rig->port, "", "http://evil.example"));
    CHECK(foreign.status == 403);
    CHECK(RawHttp(rig->port, BuildRequest("GET", rig->P("api/state"), rig->port, "", rig->Origin())).status == 200);
}

void SizeLimits() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const std::string path = rig->P("api/rules");
    // One byte over 64 KB: 413, judged from Content-Length.
    const std::string big(pf::kUiMaxBodyBytes + 1, 'x');
    const HttpReply tooBig =
        RawHttp(rig->port, BuildRequest("POST", path, rig->port, big, rig->Origin(), "application/json"));
    CHECK_MSG(tooBig.status == 413, tooBig.raw.substr(0, 100).c_str());
    CHECK(ErrorOf(tooBig) == pf::ui_err::kPayloadTooLarge);
    // Exactly 64 KB is read and judged (not JSON: 400 bad_body).
    const std::string edge(pf::kUiMaxBodyBytes, ' ');
    const HttpReply atLimit =
        RawHttp(rig->port, BuildRequest("POST", path, rig->port, edge, rig->Origin(), "application/json"));
    CHECK(atLimit.status == 400 && ErrorOf(atLimit) == pf::app_err::kBadBody);
    // A Content-Length that only claims a lot.
    CHECK(RawHttp(rig->port, "POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(rig->port) +
                                 "\r\nOrigin: " + rig->Origin() +
                                 "\r\nContent-Type: application/json\r\nContent-Length: 99999999999\r\n\r\n")
              .status == 413);
    CHECK(RawHttp(rig->port, "POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(rig->port) +
                                 "\r\nContent-Length: 12x\r\n\r\n")
              .status == 400);
    // Chunked bodies are not accepted.
    const HttpReply chunked =
        RawHttp(rig->port, "POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(rig->port) +
                               "\r\nOrigin: " + rig->Origin() +
                               "\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    CHECK(chunked.status == 411);
    // Headers over 16 KB: 431.
    const std::string filler = "X-Filler: " + std::string(pf::kUiMaxHeaderBytes, 'a') + "\r\n";
    const HttpReply bigHead = RawHttp(rig->port, BuildRequest("GET", rig->P("api/state"), rig->port, "", "", "", filler));
    CHECK(bigHead.status == 431 && ErrorOf(bigHead) == pf::ui_err::kHeadersTooLarge);
    // Just under the limit is fine.
    const std::string base = BuildRequest("GET", rig->P("api/state"), rig->port, "", "", "", "X-Filler: \r\n");
    const std::string fits = "X-Filler: " + std::string(pf::kUiMaxHeaderBytes - base.size(), 'a') + "\r\n";
    const std::string atHead = BuildRequest("GET", rig->P("api/state"), rig->port, "", "", "", fits);
    CHECK(atHead.size() == pf::kUiMaxHeaderBytes);
    CHECK(RawHttp(rig->port, atHead).status == 200);
    // One byte over, with the blank line inside what the server reads: still 431.
    const std::string over = BuildRequest("GET", rig->P("api/state"), rig->port, "", "", "",
                                          "X-Filler: " + std::string(pf::kUiMaxHeaderBytes - base.size() + 1, 'a') +
                                              "\r\n");
    CHECK(over.size() == pf::kUiMaxHeaderBytes + 1);
    CHECK(RawHttp(rig->port, over).status == 431);
}

void MalformedRequests() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const std::string host = "Host: 127.0.0.1:" + std::to_string(rig->port) + "\r\n";
    CHECK(RawHttp(rig->port, "GARBAGE\r\n\r\n").status == 400);
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/2.0\r\n" + host + "\r\n").status == 400);
    CHECK(RawHttp(rig->port, "GET  " + rig->P("") + " HTTP/1.1\r\n" + host + "\r\n").status == 400);
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\n" + host + " folded\r\n\r\n").status == 400);
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\n" + host + "Bad Name: x\r\n\r\n").status == 400);
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\n" + host + "X: a\nb\r\n\r\n").status == 400);
    // A control character other than tab in a header -- DEL, NUL -- is not HTTP.
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\n" + host + "X: a\x7f" "b\r\n\r\n").status == 400);
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\n" + host + std::string("X: a\0b\r\n\r\n", 10))
              .status == 400);
    CHECK(RawHttp(rig->port, "GET " + rig->P("") + " HTTP/1.1\r\n" + host + "X: a\tb\r\n\r\n").status == 200);
    // Two Content-Length headers, even equal ones: 400 bad_request from the parser (zero, so
    // that no other check -- excess bytes, the body -- could give the same answer).
    const std::string post = "POST " + rig->P("api/rules") + " HTTP/1.1\r\n" + host + "Origin: " + rig->Origin() +
                             "\r\nContent-Type: application/json\r\n";
    const HttpReply twoLengths = RawHttp(rig->port, post + "Content-Length: 0\r\nContent-Length: 0\r\n\r\n");
    CHECK(twoLengths.status == 400 && ErrorOf(twoLengths) == pf::ui_err::kBadRequest);
    const HttpReply oneLength = RawHttp(rig->port, post + "Content-Length: 0\r\n\r\n");
    CHECK(oneLength.status == 400 && ErrorOf(oneLength) == pf::app_err::kBadBody);
    // More bytes than Content-Length announced (sent in one piece, so they arrive with the
    // head): 400, never a second request read out of the first.
    const HttpReply longer = RawHttp(rig->port, post + "Content-Length: 2\r\n\r\n{}GET / HTTP/1.1\r\n\r\n");
    CHECK(longer.status == 400 && ErrorOf(longer) == pf::ui_err::kBadRequest);
    // The same request with an honest length is accepted (so the two rows above fail for
    // their one reason): {} is not a rule.
    const HttpReply honest = RawHttp(rig->port, post + "Content-Length: 2\r\n\r\n{}");
    CHECK(honest.status == 400 && ErrorOf(honest) == pf::rule_err::kBadName);
    CHECK(rig->State()["rules"].empty());
    CHECK(RawHttp(rig->port, "PUT " + rig->P("api/rules") + " HTTP/1.1\r\n" + host + "\r\n").status == 405);
    CHECK(rig->Get("api/rules").status == 405);
    CHECK(rig->Post("api/state", json::object()).status == 405);
    CHECK(rig->Post("", json::object()).status == 405);
}

void ConnectionLimitAndSlowClients() {
    RigOptions o;
    o.maxConnections = 2;
    o.requestTimeoutMs = 1500;
    auto rig = MakeRig(o);
    CHECK(rig != nullptr);
    if (!rig) return;
    auto open = [&] {
        SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(rig->port);
        connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a));
        return s;
    };
    SOCKET a = open(), b = open();
    // Partial headers: a slow client.
    const std::string partial = "GET " + rig->P("api/state") + " HTTP/1.1\r\nHost: 127.0.0.1:";
    send(a, partial.data(), static_cast<int>(partial.size()), 0);
    CHECK(pf_test::WaitUntil([&] { return rig->ui->ActiveConnections() == 2; }, 3000));
    const HttpReply third = rig->Get("api/state");
    CHECK_MSG(third.status == 503 && ErrorOf(third) == pf::ui_err::kBusy, third.raw.substr(0, 120).c_str());
    // The slow client is answered 408 once its time is up, and the idle one is closed.
    std::string got;
    char buf[1024];
    const ULONGLONG until = GetTickCount64() + 5000;
    while (GetTickCount64() < until) {
        WSAPOLLFD p = {};
        p.fd = a;
        p.events = POLLRDNORM;
        if (WSAPoll(&p, 1, 100) <= 0) continue;
        const int n = recv(a, buf, sizeof(buf), 0);
        if (n <= 0) break;
        got.append(buf, static_cast<size_t>(n));
    }
    CHECK_MSG(got.compare(0, 12, "HTTP/1.1 408") == 0, got.substr(0, 60).c_str());
    CHECK(pf_test::WaitUntil([&] { return rig->ui->ActiveConnections() == 0; }, 5000));
    closesocket(a);
    closesocket(b);
    CHECK(rig->Get("api/state").status == 200);
}

// Stop() waits at most stopWaitMs for a handler it cannot reach, and a second Stop() (the
// destructor's, after the owner's exit deadline was planned around the first) returns at once.
void StopIsBoundedAndIdempotent() {
    HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    auto entered = std::make_shared<std::atomic<bool>>(false);
    pf::UiServerOptions uo;
    uo.stopWaitMs = 300;
    uo.handler = [release, entered](const pf::UiRequest&) {
        entered->store(true);
        WaitForSingleObject(release, 10000);  // a handler blocked in a call no flag reaches
        return pf::UiResponse();
    };
    auto ui = std::make_unique<pf::UiServer>(uo);
    std::string err;
    CHECK(ui->Start(&err));
    const unsigned short port = ui->port();
    const std::string prefix = ui->prefix();
    std::thread client([port, prefix] { RawHttp(port, BuildRequest("GET", "/" + prefix + "/x", port), 15000); });
    CHECK(pf_test::WaitUntil([&] { return entered->load(); }, 3000));

    ULONGLONG t0 = GetTickCount64();
    ui->Stop();
    const ULONGLONG first = GetTickCount64() - t0;
    CHECK_MSG(first >= 250 && first < 1500, ("first Stop took " + std::to_string(first) + " ms").c_str());
    CHECK(ui->ActiveConnections() == 1);  // the blocked handler, left running
    t0 = GetTickCount64();
    ui->Stop();
    ui.reset();  // ~UiServer calls Stop() once more
    const ULONGLONG second = GetTickCount64() - t0;
    CHECK_MSG(second < 100, ("second Stop and the destructor took " + std::to_string(second) + " ms").c_str());
    SetEvent(release);
    client.join();
    CloseHandle(release);
}

// ---- The API ----------------------------------------------------------------------------------

void AddRuleShowsInStateAndRuns() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const int listen = FreePort();
    json body = TcpRule("web", listen, FreePort());
    body["id"] = "r_0000000000000000";  // ignored: the server draws the id
    const HttpReply added = rig->Post("api/rules", body);
    CHECK_MSG(added.status == 200, added.body.c_str());
    const std::string id = IdOf(added);
    CHECK(pf::IsRuleIdShaped(id) && id != "r_0000000000000000");

    CHECK_MSG(pf_test::WaitUntil([&] { return rig->RuleInState(id).value("status", "") == "listening"; }, 5000),
              rig->State().dump().c_str());
    const json r = rig->RuleInState(id);
    CHECK(r.value("name", "") == "web");
    CHECK(r["listen"]["port"].get<int>() == listen);
    CHECK(r.contains("stats") && r["stats"].is_object() && r["stats"]["lastError"].is_null());
    // The listener is real.
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(listen));
    CHECK(connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
    closesocket(s);

    // It is on disk, as the store will read it next start.
    pf::RuleStore again(rig->dir.path());
    const pf::LoadResult lr = again.Load();
    CHECK(lr.status == pf::LoadStatus::Ok && lr.rules.size() == 1 && lr.rules[0].id == id);

    // State carries the mode and the store.
    const json st = rig->State();
    CHECK(st["hosted"] == false && st["canQuit"] == true && st["ghost"] == "needs_ghost");
    CHECK(st["store"]["corrupt"] == false && st["store"]["locked"] == false);
    CHECK(st["localAddrs"] == json::array({kLanAddr}));
}

void LanNeedsAck() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    json r = TcpRule("lan", FreePort(), FreePort(), false);
    r["listen"]["addr"] = "0.0.0.0";
    HttpReply res = rig->Post("api/rules", r);
    CHECK_MSG(res.status == 400 && ErrorOf(res) == pf::rule_err::kLanAckRequired, res.body.c_str());
    r["listen"]["addr"] = kLanAddr;
    res = rig->Post("api/rules", r);
    CHECK(res.status == 400 && ErrorOf(res) == pf::rule_err::kLanAckRequired);
    // An address that is not ours.
    r["listen"]["addr"] = "198.51.100.1";
    r["lanAck"] = true;
    res = rig->Post("api/rules", r);
    CHECK(res.status == 400 && ErrorOf(res) == pf::rule_err::kListenAddrNotLocal);
    r["listen"]["addr"] = kLanAddr;
    res = rig->Post("api/rules", r);
    CHECK_MSG(res.status == 200, res.body.c_str());
    const std::string id = IdOf(res);
    // Changing it back to "no acknowledgement" is refused too.
    json change = r;
    change["lanAck"] = false;
    res = rig->Post("api/rules/" + id, change);
    CHECK(res.status == 400 && ErrorOf(res) == pf::rule_err::kLanAckRequired);
    // Moving it to an address that is not ours is refused on change as on add.
    change = r;
    change["listen"]["addr"] = "198.51.100.1";
    res = rig->Post("api/rules/" + id, change);
    CHECK(res.status == 400 && ErrorOf(res) == pf::rule_err::kListenAddrNotLocal);
    CHECK(rig->State()["rules"].size() == 1);

    // The adapter address goes away (a new DHCP lease): the rule can still be renamed,
    // enabled, disabled and deleted -- membership is judged only when listen.addr changes --
    // but no rule may move onto that address any more.
    rig->addrs->clear();
    change = r;
    change["name"] = "lan, renamed";
    res = rig->Post("api/rules/" + id, change);
    CHECK_MSG(res.status == 200, res.body.c_str());
    CHECK(rig->Post("api/rules/" + id + "/enable", json::object()).status == 200);
    CHECK(rig->Post("api/rules/" + id + "/disable", json::object()).status == 200);
    json other = TcpRule("other", FreePort(), FreePort(), false);
    other["listen"]["addr"] = kLanAddr;
    other["lanAck"] = true;
    CHECK(ErrorOf(rig->Post("api/rules", other)) == pf::rule_err::kListenAddrNotLocal);
    const HttpReply first = rig->Post("api/rules", TcpRule("loopback", FreePort(), FreePort(), false));
    CHECK(first.status == 200);
    json moved = TcpRule("loopback", FreePort(), FreePort(), false);
    moved["listen"]["addr"] = kLanAddr;
    moved["lanAck"] = true;
    CHECK(ErrorOf(rig->Post("api/rules/" + IdOf(first), moved)) == pf::rule_err::kListenAddrNotLocal);
    CHECK(rig->Post("api/rules/" + id + "/delete", json::object()).status == 200);
    CHECK(rig->State()["rules"].size() == 1);
}

void ConflictsAndValidation() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const int port = FreePort();
    const HttpReply first = rig->Post("api/rules", TcpRule("one", port, FreePort()));
    CHECK(first.status == 200);
    const std::string firstId = IdOf(first);
    const HttpReply clash = rig->Post("api/rules", TcpRule("two", port, FreePort()));
    CHECK_MSG(clash.status == 400 && ErrorOf(clash) == pf::rule_err::kListenConflict, clash.body.c_str());
    CHECK(pf::ParseJsonNoThrow(clash.body).contains("ruleId"));
    // 0.0.0.0 on the same port clashes too.
    json any = TcpRule("three", port, FreePort());
    any["listen"]["addr"] = "0.0.0.0";
    any["lanAck"] = true;
    CHECK(ErrorOf(rig->Post("api/rules", any)) == pf::rule_err::kListenConflict);
    // A disabled duplicate is allowed; enabling it is not.
    const HttpReply off = rig->Post("api/rules", TcpRule("four", port, FreePort(), false));
    CHECK(off.status == 200);
    const HttpReply on = rig->Post("api/rules/" + IdOf(off) + "/enable", json::object());
    CHECK(on.status == 400 && ErrorOf(on) == pf::rule_err::kListenConflict);
    // UDP on the same port is another socket.
    json udp = TcpRule("five", port, FreePort());
    udp["proto"] = "udp";
    CHECK(rig->Post("api/rules", udp).status == 200);
    // Field checks reach the page as their codes.
    json loop = TcpRule("loop", port + 0, port);
    loop["enabled"] = false;
    CHECK(ErrorOf(rig->Post("api/rules", loop)) == pf::rule_err::kLoop);
    json badHost = TcpRule("h", FreePort(), 80, false);
    badHost["remote"]["host"] = "127.1";
    CHECK(ErrorOf(rig->Post("api/rules", badHost)) == pf::rule_err::kBadHost);
    json noName = TcpRule("", FreePort(), 80, false);
    CHECK(ErrorOf(rig->Post("api/rules", noName)) == pf::rule_err::kBadName);
    CHECK(ErrorOf(rig->Post("api/rules", json::array())) == pf::app_err::kBadBody);
    const HttpReply notJson = RawHttp(rig->port, BuildRequest("POST", rig->P("api/rules"), rig->port, "{nope",
                                                              rig->Origin(), "application/json"));
    CHECK(notJson.status == 400 && ErrorOf(notJson) == pf::app_err::kBadBody);
    CHECK(rig->State()["rules"].size() == 3);
    (void)firstId;
}

void ChangeEnableDisableDelete() {
    auto rig = MakeRig(RigOptions());
    CHECK(rig != nullptr);
    if (!rig) return;
    const int port = FreePort();
    const HttpReply added = rig->Post("api/rules", TcpRule("a", port, FreePort()));
    const std::string id = IdOf(added);
    CHECK(pf_test::WaitUntil([&] { return rig->RuleInState(id).value("status", "") == "listening"; }, 5000));

    CHECK(rig->Post("api/rules/" + id + "/disable", json::object()).status == 200);
    CHECK(rig->RuleInState(id).value("status", "") == "disabled");
    CHECK(rig->RuleInState(id).value("enabled", true) == false);
    CHECK(rig->Post("api/rules/" + id + "/enable", json::object()).status == 200);
    CHECK(pf_test::WaitUntil([&] { return rig->RuleInState(id).value("status", "") == "listening"; }, 5000));

    json changed = TcpRule("renamed", port, FreePort());
    changed["id"] = "r_1111111111111111";  // the path names the rule
    CHECK(rig->Post("api/rules/" + id, changed).status == 200);
    CHECK(rig->RuleInState(id).value("name", "") == "renamed");
    CHECK(rig->State()["rules"].size() == 1);

    const std::string ghost = "r_0123456789abcdef";
    CHECK(rig->Post("api/rules/" + ghost + "/disable", json::object()).status == 404);
    CHECK(ErrorOf(rig->Post("api/rules/" + ghost, changed)) == pf::app_err::kRuleNotFound);
    CHECK(rig->Post("api/rules/not-an-id/delete", json::object()).status == 404);
    CHECK(rig->Post("api/rules/" + id + "/explode", json::object()).status == 404);

    CHECK(rig->Post("api/rules/" + id + "/delete", json::object()).status == 200);
    CHECK(rig->State()["rules"].empty());
    pf::RuleStore again(rig->dir.path());
    CHECK(again.Load().rules.empty());
}

void QuitOnlyStandalone() {
    RigOptions hosted;
    hosted.hosted = true;
    hosted.frameAncestor = "http://127.0.0.1:23551";
    auto h = MakeRig(hosted);
    CHECK(h != nullptr);
    if (h) {
        const HttpReply q = h->Post("api/quit", json::object());
        CHECK(q.status == 403 && ErrorOf(q) == pf::app_err::kQuitNotAllowed);
        CHECK(h->quits->load() == 0);
        CHECK(h->State()["canQuit"] == false);
        CHECK(h->State()["lang"] == "zh");
    }
    auto s = MakeRig(RigOptions());
    CHECK(s != nullptr);
    if (s) {
        // Needs our Origin like every POST.
        CHECK(RawHttp(s->port, BuildRequest("POST", s->P("api/quit"), s->port, "{}", "", "application/json")).status ==
              403);
        CHECK(s->quits->load() == 0);
        CHECK(s->Post("api/quit", json::object()).status == 200);
        CHECK(s->quits->load() == 1);
    }
}

void StoreStates() {
    // Not loaded yet: the API says so, the page itself is served.
    RigOptions early;
    early.load = false;
    auto e = MakeRig(early);
    CHECK(e != nullptr);
    if (e) {
        CHECK(e->Get("").status == 200);
        const HttpReply st = e->Get("api/state");
        CHECK(st.status == 503 && ErrorOf(st) == pf::app_err::kStarting);
        CHECK(e->Post("api/rules", TcpRule("x", FreePort(), FreePort())).status == 503);
        e->app->LoadRules();
        CHECK(e->Get("api/state").status == 200);
    }

    // rules.json cannot be read (it is a directory): nothing may be written.
    RigOptions locked;
    locked.prepare = [](const std::wstring& dir) { CreateDirectoryW((dir + L"\\rules.json").c_str(), nullptr); };
    auto l = MakeRig(locked);
    CHECK(l != nullptr);
    if (l) {
        const json st = l->State();
        CHECK(st["store"]["locked"] == true && st["store"]["status"] == "unreadable");
        const HttpReply add = l->Post("api/rules", TcpRule("x", FreePort(), FreePort()));
        CHECK_MSG(add.status == 409 && ErrorOf(add) == pf::store_err::kStoreLocked, add.body.c_str());
        CHECK(l->State()["rules"].empty());
    }

    // A corrupt file is kept aside and the page is told.
    RigOptions corrupt;
    corrupt.prepare = [](const std::wstring& dir) {
        HANDLE h = CreateFileW((dir + L"\\rules.json").c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
        DWORD n = 0;
        WriteFile(h, "{not json", 9, &n, nullptr);
        CloseHandle(h);
    };
    auto c = MakeRig(corrupt);
    CHECK(c != nullptr);
    if (c) {
        const json st = c->State();
        CHECK(st["store"]["corrupt"] == true && st["store"]["code"] == pf::store_err::kBadJson);
        CHECK(st["store"]["corruptFile"].get<std::string>().rfind("rules.json.corrupt-", 0) == 0);
        CHECK(st["store"]["locked"] == false);
        CHECK(c->Post("api/rules", TcpRule("x", FreePort(), FreePort(), false)).status == 200);
    }
}

void ViaNodeRules() {
    // Standalone: a via-node rule is saved but does not listen.
    auto s = MakeRig(RigOptions());
    CHECK(s != nullptr);
    if (s) {
        json r = TcpRule("via", FreePort(), 443);
        r["remote"]["host"] = "example.com";
        r["egress"] = json{{"kind", "active"}};
        const HttpReply res = s->Post("api/rules", r);
        CHECK(res.status == 200);
        CHECK(pf_test::WaitUntil(
            [&] { return s->RuleInState(IdOf(res)).value("status", "") == pf::rule_status::kNeedsGhost; }, 3000));
        const json nodes = pf::ParseJsonNoThrow(s->Get("api/nodes").body);
        CHECK(nodes["nodes"].empty() && nodes["code"] == "needs_ghost" && nodes["active"].is_null());
    }

    // Hosted with a (fake) Ghost: the node list passes through, without anything the page
    // does not need.
    pf_test::FakeGhost ghost;
    CHECK(ghost.Start());
    pf_test::FakeNode a;
    a.id = "n1";
    a.name = "Tokyo";
    a.type = "socks5";
    a.active = true;
    pf_test::FakeNode b;
    b.id = "n2";
    b.name = "Old";
    b.type = "http";
    b.valid = false;
    b.udp = false;
    ghost.SetNodes({a, b});
    pf::GhostApiOptions go;
    go.apiBase = ghost.apiBase();
    go.token = "tok";
    RigOptions o;
    o.hosted = true;
    o.permitted = true;
    o.api = std::make_shared<pf::GhostApi>(go);
    o.frameAncestor = ghost.apiBase();
    auto h = MakeRig(o);
    CHECK(h != nullptr);
    if (h) {
        CHECK(h->State()["ghost"] == "");
        const json nodes = pf::ParseJsonNoThrow(h->Get("api/nodes").body);
        CHECK_MSG(nodes["code"] == "" && nodes["active"] == "n1" && nodes["nodes"].size() == 2, nodes.dump().c_str());
        if (nodes["nodes"].size() == 2) {
            const json& n2 = nodes["nodes"][1];
            CHECK(n2["id"] == "n2" && n2["valid"] == false && n2["udp"] == false && n2["type"] == "http");
            CHECK(n2.size() == 6);
        }
        json r = TcpRule("via", FreePort(), 443, false);
        r["remote"]["host"] = "example.com";
        r["egress"] = json{{"kind", "node"}, {"nodeId", "n2"}};
        CHECK(h->Post("api/rules", r).status == 200);
        h->app->Stop();
        o.api->Shutdown();
    }
    ghost.Stop();
}

}  // namespace

int main() {
    pf_test::WinsockScope wsa;
    CHECK(wsa.ok());
    CspAndUrlRules();
    ServesThePageWithItsHeaders();
    HostMustBeExact();
    PrefixIsRequired();
    PostNeedsOriginAndJson();
    SizeLimits();
    MalformedRequests();
    ConnectionLimitAndSlowClients();
    StopIsBoundedAndIdempotent();
    AddRuleShowsInStateAndRuns();
    LanNeedsAck();
    ConflictsAndValidation();
    ChangeEnableDisableDelete();
    QuitOnlyStandalone();
    StoreStates();
    ViaNodeRules();
    return pf_test::TestExitCode();
}
