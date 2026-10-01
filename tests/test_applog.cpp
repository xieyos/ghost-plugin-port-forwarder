// Functional: the plugin's log (applog.h) -- log.write batches to the fake Ghost, the
// entry bucket, the request spacing, the shape of each entry, limits, and the local file
// when log.write is not granted, in standalone mode and after a 401.

#include "applog.h"
#include "fake_clock.h"
#include "fake_ghost.h"
#include "test_support.h"
#include "util_str.h"

#include <memory>
#include <string>
#include <vector>

using pf::AppLog;
using pf::AppLogOptions;
using pf::GhostApi;
using pf::GhostApiOptions;
using pf::json;
using pf::LogLevel;
using pf_test::FakeGhost;
using pf_test::FakeRequest;

namespace {

const char* kIngest = "/api/log-ingest";

std::unique_ptr<GhostApi> MakeApi(const FakeGhost& fg) {
    GhostApiOptions o;
    o.apiBase = fg.apiBase();
    o.token = "applog-token";
    return std::make_unique<GhostApi>(o);
}

std::vector<FakeRequest> Ingests(const FakeGhost& fg) {
    std::vector<FakeRequest> r;
    for (auto& q : fg.Requests()) {
        if (q.path == kIngest) r.push_back(q);
    }
    return r;
}

std::string ReadFileUtf8(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::string();
    std::string s;
    char buf[8192];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof(buf), &n, nullptr) && n > 0) s.append(buf, n);
    CloseHandle(h);
    return s;
}

int CountLines(const std::string& s) {
    int n = 0;
    for (char c : s) n += (c == '\n');
    return n;
}

bool FileExists(const std::wstring& p) { return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES; }

void TestBatchingAndBucket() {
    FakeGhost fg;
    CHECK(fg.Start());
    auto api = MakeApi(fg);
    // The log's clock is fake: the bucket sees all 25 writes at one instant (on a real clock
    // a slow machine refills a token between writes), and the one-second spacing is read
    // back as the waits the sender asked for.
    pf_test::FakeClock clock;
    AppLogOptions o;
    o.api = api.get();
    o.canWrite = true;
    o.clock = &clock;
    AppLog log(o);
    CHECK(log.Remote());
    // Written before Start(), so that no wait of the sender moves the clock in between.
    for (int i = 0; i < 25; ++i) {
        log.Write(i % 3 == 0 ? LogLevel::Info : (i % 3 == 1 ? LogLevel::Warn : LogLevel::Error),
                  "entry " + std::to_string(i), {{"rule", "r" + std::to_string(i)}});
    }
    CHECK_MSG(log.Dropped() == 5, "burst of 20: five of 25 instant entries are dropped");
    log.Start();
    CHECK(pf_test::WaitUntil([&] { return log.SentEntries() == 20; }, 8000));
    log.Stop();
    CHECK(log.Dropped() == 5);

    const auto reqs = Ingests(fg);
    CHECK(reqs.size() >= 2);
    size_t total = 0;
    int next = 0;
    for (size_t i = 0; i < reqs.size(); ++i) {
        const json body = pf::ParseJsonNoThrow(reqs[i].body);
        CHECK(body.is_object() && body.size() == 1 && body.contains("entries"));
        CHECK_MSG(!body.contains("v") && !body.contains("items"), "the key is entries, with no v");
        const json& entries = body["entries"];
        CHECK(entries.is_array() && !entries.empty());
        CHECK_MSG(entries.size() <= pf::kLogBatch, "at most 10 entries per request");
        for (const auto& e : entries) {
            CHECK(e.is_object() && e.size() == 3);
            const char* want = next % 3 == 0 ? "info" : (next % 3 == 1 ? "warn" : "error");
            CHECK(e["level"] == want);
            CHECK(e["text"] == "entry " + std::to_string(next));
            CHECK(e["fields"] == json({{"rule", "r" + std::to_string(next)}}));
            ++next;
        }
        total += entries.size();
    }
    CHECK(total == 20);
    // At most one request per second: the sender waited a full interval after every request
    // but (possibly) the last.
    const auto waits = clock.Waits();
    CHECK_MSG(waits.size() + 1 >= reqs.size(), "a wait between every two requests");
    for (uint32_t w : waits) CHECK(w == pf::kLogMinIntervalMs);
}

void TestStopFlushes() {
    FakeGhost fg;
    CHECK(fg.Start());
    auto api = MakeApi(fg);
    AppLogOptions o;
    o.api = api.get();
    o.canWrite = true;
    AppLog log(o);
    log.Start();
    log.Write(LogLevel::Info, "one");
    log.Write(LogLevel::Info, "two");
    log.Write(LogLevel::Info, "three");
    log.Stop();
    CHECK_MSG(log.SentEntries() == 3, "Stop sends what is queued");
    CHECK(log.Dropped() == 0);
    log.Write(LogLevel::Info, "after stop");
    CHECK(log.Dropped() == 1);
}

void TestLimits() {
    FakeGhost fg;
    CHECK(fg.Start());
    auto api = MakeApi(fg);
    AppLogOptions o;
    o.api = api.get();
    o.canWrite = true;
    AppLog log(o);
    log.Start();
    std::string cjk;
    for (int i = 0; i < 1000; ++i) cjk += "\xe7\xab\xaf";  // 3000 bytes
    pf::LogFields fields;
    for (int i = 0; i < 20; ++i) fields.emplace_back("k" + std::to_string(i), std::string(600, 'v'));
    log.Write(LogLevel::Warn, cjk, fields);
    CHECK(pf_test::WaitUntil([&] { return log.SentEntries() == 1; }, 5000));
    log.Stop();
    const auto reqs = Ingests(fg);
    CHECK(reqs.size() == 1);
    if (reqs.size() == 1) {
        const json e = pf::ParseJsonNoThrow(reqs[0].body)["entries"][0];
        const std::string text = e["text"].get<std::string>();
        CHECK_MSG(text.size() == 2046, "2 KB, cut on a character boundary (682 * 3 bytes)");
        CHECK(text == cjk.substr(0, 2046));
        CHECK_MSG(e["fields"].size() == pf::kLogMaxFields, "16 fields");
        CHECK(e["fields"]["k0"].get<std::string>().size() == pf::kLogMaxFieldValueBytes);
        CHECK(!e["fields"].contains("k16"));
    }
}

void TestNotGrantedWritesLocally() {
    FakeGhost fg;
    CHECK(fg.Start());
    auto api = MakeApi(fg);
    pf_test::ScopedTempDir dir;
    CHECK(dir.ok());
    AppLogOptions o;
    o.api = api.get();
    o.canWrite = false;  // log.write not granted
    o.localDir = dir.path();
    AppLog log(o);
    CHECK(!log.Remote());
    log.Start();
    log.Write(LogLevel::Warn, "bind failed\r\nsecond line", {{"rule", "r_0123456789abcdef"}, {"code", "bind_failed"}});
    log.Write(LogLevel::Info, "started");
    log.Stop();
    CHECK_MSG(fg.Requests().empty(), "without log.write nothing is sent");
    CHECK(log.LocalEntries() == 2);
    const std::string text = ReadFileUtf8(dir.path() + L"\\port-forwarder.log");
    CHECK(CountLines(text) == 2);
    CHECK_MSG(text.find(" warn bind failed  second line rule=r_0123456789abcdef code=bind_failed\n") != std::string::npos,
              "one line per entry, control characters flattened");
    CHECK(text.find(" info started\n") != std::string::npos);

    // Standalone: no API at all.
    pf_test::ScopedTempDir dir2;
    AppLogOptions s;
    s.localDir = dir2.path();
    AppLog standalone(s);
    standalone.Start();
    standalone.Write(LogLevel::Error, "standalone");
    standalone.Stop();
    CHECK(standalone.LocalEntries() == 1);
    CHECK(ReadFileUtf8(dir2.path() + L"\\port-forwarder.log").find(" error standalone\n") != std::string::npos);
}

void TestUnauthorizedFallsBackToLocal() {
    FakeGhost fg;
    CHECK(fg.Start());
    fg.SetUnauthorized(true);
    auto api = MakeApi(fg);
    pf_test::ScopedTempDir dir;
    AppLogOptions o;
    o.api = api.get();
    o.canWrite = true;
    o.localDir = dir.path();
    o.minIntervalMs = 50;
    AppLog log(o);
    log.Start();
    log.Write(LogLevel::Info, "first");
    CHECK(pf_test::WaitUntil([&] { return log.LocalEntries() == 1; }, 5000));
    CHECK(!log.Remote());
    log.Write(LogLevel::Info, "second");
    log.Stop();
    CHECK_MSG(Ingests(fg).size() == 1, "one 401, then no more requests");
    CHECK(log.LocalEntries() == 2 && log.Dropped() == 0);
    const std::string text = ReadFileUtf8(dir.path() + L"\\port-forwarder.log");
    CHECK(text.find(" info first\n") != std::string::npos && text.find(" info second\n") != std::string::npos);
}

void TestLocalRolls() {
    pf_test::ScopedTempDir dir;
    AppLogOptions o;
    o.localDir = dir.path();
    o.fileMaxBytes = 400;
    o.burst = 1000;
    o.ratePerSec = 1000;
    {
        AppLog log(o);
        log.Start();
        for (int i = 0; i < 30; ++i) {
            log.Write(LogLevel::Info, "line " + std::to_string(i) + " " + std::string(40, 'x'));
            // One entry per batch, so the size check runs between entries.
            const uint64_t want = static_cast<uint64_t>(i) + 1;
            pf_test::WaitUntil([&] { return log.LocalEntries() == want; }, 2000);
        }
        log.Stop();
        CHECK(log.LocalEntries() == 30);
    }
    const std::wstring cur = dir.path() + L"\\port-forwarder.log";
    CHECK(FileExists(cur));
    CHECK_MSG(FileExists(cur + L".1"), "rolled once it would pass the limit");
    CHECK_MSG(!FileExists(cur + L".2"), "two files at most");
    CHECK(ReadFileUtf8(cur).size() <= 400);
    CHECK(ReadFileUtf8(cur + L".1").size() <= 400);
    CHECK(ReadFileUtf8(cur).find("line 29 ") != std::string::npos);
}

// Another program holds port-forwarder.log.1 without FILE_SHARE_DELETE, so the roll cannot
// replace it. The current file is emptied instead of growing past the limit, and the held
// file is left alone.
void TestRollBlockedByReader() {
    pf_test::ScopedTempDir dir;
    const std::wstring cur = dir.path() + L"\\port-forwarder.log";
    const std::wstring old = cur + L".1";
    {
        HANDLE h = CreateFileW(old.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        CHECK(h != INVALID_HANDLE_VALUE);
        DWORD n = 0;
        WriteFile(h, "held\n", 5, &n, nullptr);
        CloseHandle(h);
    }
    HANDLE reader =
        CreateFileW(old.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(reader != INVALID_HANDLE_VALUE);

    AppLogOptions o;
    o.localDir = dir.path();
    o.fileMaxBytes = 400;
    o.burst = 1000;
    o.ratePerSec = 1000;
    uint64_t largest = 0;
    {
        AppLog log(o);
        log.Start();
        for (int i = 0; i < 30; ++i) {
            log.Write(LogLevel::Info, "line " + std::to_string(i) + " " + std::string(40, 'x'));
            const uint64_t want = static_cast<uint64_t>(i) + 1;
            pf_test::WaitUntil([&] { return log.LocalEntries() + log.Dropped() == want; }, 2000);
            const uint64_t size = ReadFileUtf8(cur).size();
            if (size > largest) largest = size;
        }
        log.Stop();
        CHECK(log.LocalEntries() + log.Dropped() == 30);
        CHECK_MSG(log.LocalEntries() == 30, "emptying the file made room every time");
    }
    CloseHandle(reader);
    CHECK_MSG(largest <= 400, "never past the limit while the roll is blocked");
    CHECK(ReadFileUtf8(cur).find("line 29 ") != std::string::npos);
    CHECK_MSG(ReadFileUtf8(old) == "held\n", "the held file is not touched");
}

}  // namespace

int main() {
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    TestBatchingAndBucket();
    TestStopFlushes();
    TestLimits();
    TestNotGrantedWritesLocally();
    TestUnauthorizedFallsBackToLocal();
    TestLocalRolls();
    TestRollBlockedByReader();
    return pf_test::TestExitCode();
}
