// Unit: the pure pieces under the Ghost API client -- the token bucket, the 429 backoff,
// strict base64, the reason-code shape, the upstream.list parser, UTF-8 truncation.

#include "applog.h"
#include "base64.h"
#include "ghost_api.h"
#include "test_support.h"
#include "token_bucket.h"
#include "tunnel_client.h"

#include <string>

using pf::json;

namespace {

void TestTokenBucket() {
    // TryTake: a full bucket of 3 gives 3, then refuses until time passes.
    pf::TokenBucket b(2.0, 3.0);
    CHECK(b.TryTake(1000));
    CHECK(b.TryTake(1000));
    CHECK(b.TryTake(1000));
    CHECK_MSG(!b.TryTake(1000), "empty bucket refuses");
    CHECK_MSG(!b.TryTake(1499), "0.998 of a token is not a token");
    CHECK_MSG(b.TryTake(1500), "2/s refills one token in 500 ms");
    CHECK(!b.TryTake(1500));
    // Refill never exceeds the burst.
    CHECK(b.TryTake(100000));
    CHECK(b.TryTake(100000));
    CHECK(b.TryTake(100000));
    CHECK_MSG(!b.TryTake(100000), "refill is capped at the burst");

    // Reserve: the burst is free, then each reservation waits its turn.
    pf::TokenBucket r(18.0, 90.0);
    bool allFree = true;
    for (int i = 0; i < 90; ++i) allFree = allFree && r.Reserve(0) == 0;
    CHECK_MSG(allFree, "the first 90 reservations need no wait");
    const uint64_t w1 = r.Reserve(0);
    const uint64_t w2 = r.Reserve(0);
    CHECK_MSG(w1 == 56, "token 91 waits ceil(1000/18) = 56 ms");
    CHECK_MSG(w2 == 112, "token 92 queues behind it: ceil(2000/18) = 112 ms");
    // Time passing pays the debt back.
    CHECK_MSG(r.Reserve(1000) == 0, "after a second 18 tokens came back, more than the debt of 2");
}

void TestBackoff() {
    CHECK(pf::BackoffMs(0, 0.0) == 250);
    CHECK(pf::BackoffMs(1, 0.0) == 500);
    CHECK(pf::BackoffMs(4, 0.0) == 4000);
    CHECK(pf::BackoffMs(0, 1.0) == 312);
    CHECK(pf::BackoffMs(3, 1.0) == 2500);
    CHECK_MSG(pf::BackoffMs(5, 0.0) == 8000, "250 * 2^5 = 8000, the cap");
    CHECK_MSG(pf::BackoffMs(5, 1.0) == 8000, "jitter never lifts it over the cap");
    CHECK_MSG(pf::BackoffMs(40, 1.0) == 8000, "no overflow for a large attempt");
    CHECK_MSG(pf::BackoffMs(2, 7.0) == 1250, "random01 above 1 is clamped");
    CHECK_MSG(pf::BackoffMs(-3, 0.0) == 250, "negative attempt reads as 0");
}

void TestBase64() {
    std::string out;
    // RFC 4648 section 10 test vectors.
    const char* vec[][2] = {{"", ""},         {"Zg==", "f"},       {"Zm8=", "fo"},      {"Zm9v", "foo"},
                            {"Zm9vYg==", "foob"}, {"Zm9vYmE=", "fooba"}, {"Zm9vYmFy", "foobar"}};
    for (const auto& v : vec) {
        CHECK_MSG(pf::DecodeBase64Strict(v[0], &out) && out == v[1], v[0]);
    }
    CHECK(pf::DecodeBase64Strict("+/+/", &out) && out == std::string("\xfb\xff\xbf", 3));
    const char* bad[] = {"Zg",    "Zg=",  "Zm9v\n", " Zm9v", "Zm9v=",  "Z===", "Zg=a", "Zm==Zm9v",
                         "-_-_",  "Zm9!", "====",   "Zm9vY",  "Zm 9v", "Z=g="};
    for (const char* b : bad) {
        out = "x";
        CHECK_MSG(!pf::DecodeBase64Strict(b, &out) && out.empty(), b);
    }
}

void TestReasonCode() {
    CHECK(pf::IsReasonCodeShaped("plugin_not_running"));
    CHECK(pf::IsReasonCodeShaped("a"));
    CHECK(pf::IsReasonCodeShaped("e2e_ok"));
    CHECK(!pf::IsReasonCodeShaped(""));
    CHECK(!pf::IsReasonCodeShaped("Upstream_refused"));
    CHECK(!pf::IsReasonCodeShaped("_x"));
    CHECK(!pf::IsReasonCodeShaped("9x"));
    CHECK(!pf::IsReasonCodeShaped("a-b"));
    CHECK(!pf::IsReasonCodeShaped("a b"));
    CHECK(!pf::IsReasonCodeShaped("<script>"));
    CHECK(pf::IsReasonCodeShaped(std::string(64, 'a')));
    CHECK(!pf::IsReasonCodeShaped(std::string(65, 'a')));
}

json Node(const char* id) {
    return json{{"id", id}, {"name", "N"}, {"type", "socks5"}, {"active", false}, {"valid", true}, {"udp", false}};
}

void TestParseNodeList() {
    json good = json{{"status", "ok"}, {"active", "n1"}, {"nodes", json::array({Node("n1"), Node("n2")})}};
    pf::NodeList l = pf::ParseNodeList(good);
    CHECK(l.ok() && l.hasActive && l.active == "n1" && l.nodes.size() == 2);

    json nullActive = good;
    nullActive["active"] = nullptr;
    l = pf::ParseNodeList(nullActive);
    CHECK_MSG(l.ok() && !l.hasActive && l.active.empty(), "active:null is no active node");

    // Each odd entry is skipped; the good one survives.
    const char* keys[] = {"id", "name", "type", "active", "valid", "udp"};
    for (const char* k : keys) {
        json odd = Node("n9");
        odd[k] = 7;  // wrong type for every key (ids, names, types are strings; the rest booleans)
        json doc = json{{"status", "ok"}, {"active", nullptr}, {"nodes", json::array({odd, Node("n2")})}};
        l = pf::ParseNodeList(doc);
        CHECK_MSG(l.ok() && l.nodes.size() == 1 && l.nodes[0].id == "n2", k);
        json missing = Node("n9");
        missing.erase(k);
        doc["nodes"] = json::array({missing, Node("n2")});
        l = pf::ParseNodeList(doc);
        CHECK_MSG(l.ok() && l.nodes.size() == 1 && l.nodes[0].id == "n2", k);
    }
    json badId = json{{"status", "ok"}, {"active", nullptr}, {"nodes", json::array({Node("a b"), 5, Node("n2")})}};
    l = pf::ParseNodeList(badId);
    CHECK_MSG(l.ok() && l.nodes.size() == 1, "an id that is no node id, and a non-object, are skipped");

    // Whole-answer failures.
    json bad1 = good;
    bad1["status"] = "error";
    CHECK(pf::ParseNodeList(bad1).code == pf::api_err::kBadResponse);
    json bad2 = good;
    bad2["active"] = 1;
    CHECK(pf::ParseNodeList(bad2).code == pf::api_err::kBadResponse);
    json bad3 = good;
    bad3.erase("active");
    CHECK(pf::ParseNodeList(bad3).code == pf::api_err::kBadResponse);
    json bad4 = good;
    bad4["nodes"] = json::object();
    CHECK(pf::ParseNodeList(bad4).code == pf::api_err::kBadResponse);
    CHECK(pf::ParseNodeList(json::array()).code == pf::api_err::kBadResponse);
}

void TestTruncateUtf8() {
    CHECK(pf::TruncateUtf8("abc", 5) == "abc");
    CHECK(pf::TruncateUtf8("abcdef", 3) == "abc");
    const std::string cjk = "\xe7\xab\xaf\xe5\x8f\xa3";  // two 3-byte characters
    CHECK(pf::TruncateUtf8(cjk, 6) == cjk);
    CHECK_MSG(pf::TruncateUtf8(cjk, 5) == cjk.substr(0, 3), "never cut into a sequence");
    CHECK(pf::TruncateUtf8(cjk, 4) == cjk.substr(0, 3));
    CHECK(pf::TruncateUtf8(cjk, 3) == cjk.substr(0, 3));
    CHECK(pf::TruncateUtf8(cjk, 2).empty());
}

}  // namespace

int main() {
    TestTokenBucket();
    TestBackoff();
    TestBase64();
    TestReasonCode();
    TestParseNodeList();
    TestTruncateUtf8();
    return pf_test::TestExitCode();
}
