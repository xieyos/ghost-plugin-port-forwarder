// Functional: the Ghost API client (ghost_api.h) against the fake Ghost over real
// loopback HTTP -- the headers on the wire, 401, 429 and the local token bucket (on a fake
// clock), and how answers are judged.

#include "fake_clock.h"
#include "fake_ghost.h"
#include "ghost_api.h"
#include "test_support.h"

#include <string>
#include <thread>
#include <vector>

using pf::ApiResult;
using pf::GhostApi;
using pf::GhostApiOptions;
using pf::json;
using pf_test::FakeClock;
using pf_test::FakeGhost;
namespace A = pf::api_err;

namespace {

const char* kToken = "{0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0}";

GhostApiOptions Opts(const FakeGhost& fg, FakeClock* clock) {
    GhostApiOptions o;
    o.apiBase = fg.apiBase();
    o.token = kToken;
    o.clock = clock;
    o.random01 = [] { return 1.0; };
    return o;
}

void TestHeaders() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));

    ApiResult g = api.Get("/api/upstream/list");
    CHECK(g.ok() && g.httpStatus == 200 && g.body.is_object());
    ApiResult p = api.Post("/api/log-ingest", json{{"entries", json::array()}});
    CHECK(p.ok());

    const auto reqs = fg.Requests();
    CHECK(reqs.size() == 2);
    for (const auto& r : reqs) {
        CHECK_MSG(r.HeaderCount("X-Ghost-Plugin-Token") == 1, r.path.c_str());
        CHECK_MSG(r.Header("X-Ghost-Plugin-Token") == kToken, "the token, verbatim");
        CHECK_MSG(r.HeaderCount("Origin") == 0, "a native plugin sends no Origin");
        CHECK_MSG(r.HeaderCount("X-Ghost-Token") == 0, "never the session header");
        CHECK_MSG(r.HeaderCount("X-Ghost-Host-Token") == 0, "never the host header");
        CHECK(r.HeaderCount("Cookie") == 0);
        // One connection per request: on a reused connection that the server closed,
        // WinHTTP may resend a request on its own -- a second tunnel. (A test that cuts a
        // reused connection did not provoke that resend here, so the header is what is
        // pinned.)
        CHECK_MSG(_stricmp(r.Header("Connection").c_str(), "close") == 0, "Connection: close on every request");
    }
    if (reqs.size() == 2) {
        CHECK(reqs[0].method == "GET" && reqs[0].path == "/api/upstream/list");
        CHECK(reqs[1].method == "POST" && reqs[1].path == "/api/log-ingest");
        CHECK(reqs[1].Header("Content-Type") == "application/json");
        CHECK(pf::ParseJsonNoThrow(reqs[1].body) == json({{"entries", json::array()}}));
    }
    CHECK_MSG(clock.Waits().empty(), "two calls never wait on the bucket");
}

void Test429Bounded() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));
    fg.Set429Always(true);

    ApiResult r = api.Get("/api/upstream/list");
    CHECK(r.code == A::kRateLimited && r.httpStatus == 429);
    CHECK_MSG(fg.CountPath("/api/upstream/list") == 1 + pf::kMax429Retries, "one try plus five retries, no more");
    const std::vector<uint32_t> want = {312, 625, 1250, 2500, 5000};  // 250 * 2^n + 25 % (random01 = 1)
    CHECK_MSG(clock.Waits() == want, "exponential backoff with jitter between the tries");

    // Two 429s, then an answer: success on the third request.
    fg.Set429Always(false);
    fg.Set429Count(2);
    clock.ClearWaits();
    r = api.Get("/api/upstream/list");
    CHECK(r.ok());
    CHECK(fg.CountPath("/api/upstream/list") == 1 + pf::kMax429Retries + 3);
    CHECK((clock.Waits() == std::vector<uint32_t>{312, 625}));
}

void Test401IsFinal() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));
    CHECK(api.Get("/api/upstream/list").ok());
    CHECK(!api.Unavailable());

    fg.SetUnauthorized(true);
    ApiResult r = api.Post("/api/upstream/tunnel", json::object());
    CHECK(r.code == A::kGhostUnavailable && r.httpStatus == 401);
    CHECK(api.Unavailable());
    const size_t before = fg.Requests().size();

    // Even after Ghost would accept again, nothing more is sent: a token never comes back.
    fg.SetUnauthorized(false);
    CHECK(api.Get("/api/upstream/list").code == A::kGhostUnavailable);
    CHECK(api.Post("/api/log-ingest", json{{"entries", json::array()}}).code == A::kGhostUnavailable);
    CHECK_MSG(fg.Requests().size() == before, "no request after a 401");
}

void TestTokenBucketPacing() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));

    bool allOk = true;
    for (int i = 0; i < 90; ++i) allOk = api.Get("/api/upstream/list").ok() && allOk;
    CHECK(allOk);
    CHECK_MSG(clock.Waits().empty(), "a burst of 90 goes out at once");
    for (int i = 0; i < 5; ++i) allOk = api.Get("/api/upstream/list").ok() && allOk;
    CHECK(allOk);
    const auto waits = clock.Waits();
    CHECK_MSG(waits.size() == 5, "every call past the burst waits for its token");
    for (uint32_t w : waits) CHECK_MSG(w >= 50 && w <= 60, "about 1/18 s each");
    CHECK(fg.CountPath("/api/upstream/list") == 95);
}

void TestAnswers() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));

    // A 200 error answer carries its code.
    fg.SetTunnelFixedBody(R"({"status":"error","error":"upstream_auth_failed"})");
    ApiResult r = api.Post("/api/upstream/tunnel", json::object());
    CHECK(r.code == "upstream_auth_failed" && r.httpStatus == 200);

    // Codes of another shape, bodies that are not an object, a missing status.
    const char* odd[] = {R"({"status":"error","error":"Upstream Refused"})", R"({"status":"error","error":7})",
                         R"({"status":"error"})", R"([1,2])", R"("ok")", R"({"error":"x"})", R"(not json)",
                         R"({"status":7})"};
    for (const char* body : odd) {
        fg.SetTunnelFixedBody(body);
        CHECK_MSG(api.Post("/api/upstream/tunnel", json::object()).code == A::kBadResponse, body);
    }
    // Not 200 (and not 401/403/429): bad_response.
    CHECK(api.Get("/no/such/route").code == A::kBadResponse);
    CHECK(api.Get("/no/such/route").httpStatus == 404);
    // A path that is not a path never goes out.
    const size_t before = fg.Requests().size();
    CHECK(api.Get("api/upstream/list").code == A::kBadResponse);
    CHECK(api.Get(std::string("/x\r\nOrigin: http://127.0.0.1:1")).code == A::kBadResponse);
    CHECK(fg.Requests().size() == before);
}

void TestUnusableConfig() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    const std::string bases[] = {"http://localhost:" + std::to_string(fg.port()), "https://127.0.0.1:1",
                                 fg.apiBase() + "/"};
    for (const auto& b : bases) {
        GhostApiOptions o = Opts(fg, &clock);
        o.apiBase = b;
        GhostApi api(o);
        CHECK_MSG(api.Unavailable() && api.Get("/api/upstream/list").code == A::kGhostUnavailable, b.c_str());
    }
    GhostApiOptions o = Opts(fg, &clock);
    o.token = "abc\r\nOrigin: x";
    GhostApi api(o);
    CHECK_MSG(api.Get("/api/upstream/list").code == A::kGhostUnavailable, "a token that is not token-shaped");
    CHECK_MSG(fg.Requests().empty(), "nothing went out");
}

void TestTransportFailureNotRetried() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));
    CHECK(api.Get("/api/upstream/list").ok());  // a connection WinHTTP could have kept
    fg.SetTunnelDrop(true);
    ApiResult r = api.Post("/api/upstream/tunnel", json{{"via", "active"}});
    CHECK(r.code == A::kGhostUnreachable && r.httpStatus == 0);
    CHECK_MSG(fg.CountPath("/api/upstream/tunnel") == 1, "a request without an answer is sent once");
    CHECK(!api.Unavailable());

    // Nobody listening at all.
    GhostApiOptions o = Opts(fg, &clock);
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    o.apiBase = "http://127.0.0.1:" + std::to_string(l.port);
    l.Close();
    GhostApi dead(o);
    CHECK(dead.Get("/api/upstream/list").code == A::kGhostUnreachable);
}

void TestShutdown() {
    FakeGhost fg;
    CHECK(fg.Start());
    FakeClock clock;
    GhostApi api(Opts(fg, &clock));
    api.Shutdown();
    CHECK(api.Get("/api/upstream/list").code == A::kCancelled);
    CHECK(fg.Requests().empty());

    // A 429 backoff ends with Shutdown (real clock, so the wait is real).
    FakeGhost fg2;
    CHECK(fg2.Start());
    fg2.Set429Always(true);
    GhostApiOptions o;
    o.apiBase = fg2.apiBase();
    o.token = kToken;
    o.random01 = [] { return 0.0; };
    o.max429Retries = 50;
    GhostApi slow(o);
    ApiResult r;
    std::thread t([&] { r = slow.Get("/api/upstream/list"); });
    CHECK(pf_test::WaitUntil([&] { return fg2.CountPath("/api/upstream/list") >= 3; }, 10000));
    const ULONGLONG t0 = GetTickCount64();
    slow.Shutdown();
    t.join();
    CHECK(r.code == A::kCancelled);
    CHECK_MSG(GetTickCount64() - t0 < 1500, "Shutdown ends the backoff wait at once");
}

}  // namespace

int main() {
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    TestHeaders();
    Test429Bounded();
    Test401IsFinal();
    TestTokenBucketPacing();
    TestAnswers();
    TestUnusableConfig();
    TestTransportFailureNotRetried();
    TestShutdown();
    return pf_test::TestExitCode();
}
