// Functional: rules.json on a real file system (rule_store.h), in a temporary directory
// whose name has a CJK component.

#include "rule_store.h"
#include "test_support.h"

#include <windows.h>

#include <string>
#include <vector>

using pf::LoadStatus;
using pf::Rule;
namespace E = pf::rule_err;

namespace {

const long long kNow = 1700000000;

std::wstring Join(const std::wstring& dir, const std::wstring& name) { return dir + L"\\" + name; }

bool WriteBytes(const std::wstring& path, const std::string& bytes) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    const bool ok = bytes.empty() || (WriteFile(h, bytes.data(), static_cast<DWORD>(bytes.size()), &n, nullptr) &&
                                      n == bytes.size());
    CloseHandle(h);
    return ok;
}

bool ReadBytes(const std::wstring& path, std::string* out) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    std::string data;
    char buf[64 * 1024];
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(h, buf, sizeof(buf), &n, nullptr)) {
            CloseHandle(h);
            return false;
        }
        if (n == 0) break;
        data.append(buf, n);
    }
    CloseHandle(h);
    *out = std::move(data);
    return true;
}

bool Exists(const std::wstring& path) { return GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES; }

std::vector<std::wstring> ListDir(const std::wstring& dir) {
    std::vector<std::wstring> names;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return names;
    do {
        const std::wstring n = fd.cFileName;
        if (n != L"." && n != L"..") names.push_back(n);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return names;
}

Rule MakeRule(const std::string& id, pf::Proto proto, const std::string& addr, int port, const std::string& name) {
    Rule r;
    r.id = id;
    r.name = name;
    r.proto = proto;
    r.listenAddr = addr;
    r.listenPort = port;
    r.remoteHost = "example.com";
    r.remotePort = 443;
    r.lanAck = addr != "127.0.0.1";
    return r;
}

std::vector<Rule> SampleRules() {
    Rule a = MakeRule("r_0000000000000001", pf::Proto::Tcp, "127.0.0.1", 8080, "\xE7\xAB\xAF\xE5\x8F\xA3 web");
    Rule b = MakeRule("r_0000000000000002", pf::Proto::Udp, "0.0.0.0", 5353, "dns");
    b.egress = pf::EgressKind::Node;
    b.nodeId = "hk-1";
    b.udpIdleSec = 30;
    b.remoteHost = "2001:db8::53";
    b.remotePort = 53;
    Rule c = MakeRule("r_0000000000000003", pf::Proto::Tcp, "127.0.0.1", 2222, "ssh");
    c.enabled = false;
    c.egress = pf::EgressKind::Active;
    c.maxConnections = 4;
    return {a, b, c};
}

void MissingFile() {
    pf_test::ScopedTempDir dir;
    CHECK(dir.ok());
    const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
    CHECK_MSG(r.status == LoadStatus::Missing, "no rules.json: Missing");
    CHECK(!r.corrupt && r.rules.empty());
    CHECK_MSG(ListDir(dir.path()).empty(), "loading created nothing");
}

void RoundTrip() {
    pf_test::ScopedTempDir dir;
    const std::vector<Rule> rules = SampleRules();
    std::string err;
    CHECK_MSG(pf::SaveRules(dir.path(), rules, &err), err.c_str());
    const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
    CHECK_MSG(r.status == LoadStatus::Ok, "saved file loads");
    CHECK(!r.corrupt);
    CHECK_MSG(r.rules.size() == rules.size(), "same number of rules");
    for (size_t i = 0; i < rules.size() && i < r.rules.size(); ++i) CHECK_MSG(r.rules[i] == rules[i], "rule round trip");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "only rules.json in the directory (no temporary left)");

    std::string bytes;
    CHECK(ReadBytes(pf::RulesFilePath(dir.path()), &bytes));
    CHECK_MSG(bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") != 0, "no BOM");
    CHECK_MSG(bytes.find("\xE7\xAB\xAF\xE5\x8F\xA3") != std::string::npos, "the name is written as UTF-8");

    // Saving an empty set is a valid file too.
    CHECK(pf::SaveRules(dir.path(), {}, &err));
    const pf::LoadResult empty = pf::LoadRules(dir.path(), kNow);
    CHECK_MSG(empty.status == LoadStatus::Ok && empty.rules.empty(), "empty set round trip");

    // A trailing separator on the data directory is fine.
    CHECK(pf::RulesFilePath(L"C:\\d\\") == L"C:\\d\\rules.json");
    CHECK(pf::RulesFilePath(L"C:\\d") == L"C:\\d\\rules.json");
}

// Writes `bytes` as rules.json, loads, and checks it was renamed aside byte for byte.
void ExpectCorrupt(const char* label, const std::string& bytes, const std::string& reason) {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(WriteBytes(path, bytes));
    const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
    const std::string l = std::string(label) + ": status Corrupt, reason '" + reason + "', got '" + r.reason + "'";
    CHECK_MSG(r.status == LoadStatus::Corrupt && r.corrupt, l.c_str());
    CHECK_MSG(r.reason == reason, l.c_str());
    CHECK_MSG(r.rules.empty(), "starts with no rules");
    const std::wstring aside = path + L".corrupt-1700000000";
    CHECK_MSG(r.corruptPath == aside, "renamed to rules.json.corrupt-<now>");
    CHECK_MSG(!Exists(path), "rules.json is gone");
    std::string kept;
    CHECK_MSG(ReadBytes(aside, &kept) && kept == bytes, "the corrupt copy is byte for byte the old file");
}

void CorruptFiles() {
    ExpectCorrupt("not JSON", "{\"v\":1,\"rules\":[", "bad_json");
    ExpectCorrupt("empty file", "", "bad_json");
    ExpectCorrupt("v 2", "{\"v\":2,\"rules\":[]}", E::kBadVersion);
    std::string badHost = pf::RuleDocumentToJson(SampleRules()).dump();
    const size_t at = badHost.find("example.com");
    badHost.replace(at, 11, "127.1");
    ExpectCorrupt("a rule with a bad host", badHost, E::kBadHost);

    // Size: exactly 256 KB of valid JSON loads; one byte more is corrupt.
    const std::string doc = "{\"v\":1,\"rules\":[]}";
    std::string exact = doc + std::string(pf::kMaxRulesFileBytes - doc.size(), ' ');
    {
        pf_test::ScopedTempDir dir;
        CHECK(WriteBytes(pf::RulesFilePath(dir.path()), exact));
        const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
        CHECK_MSG(r.status == LoadStatus::Ok, "exactly 256 KB loads");
    }
    ExpectCorrupt("256 KB + 1", exact + " ", "too_large");

    // A UTF-8 BOM (Notepad adds one) is not damage: the parser skips it, and we never
    // write one ourselves (RoundTrip checks that).
    {
        pf_test::ScopedTempDir dir;
        const std::string withBom = "\xEF\xBB\xBF" + pf::RuleDocumentToJson(SampleRules()).dump();
        CHECK(WriteBytes(pf::RulesFilePath(dir.path()), withBom));
        const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
        CHECK_MSG(r.status == LoadStatus::Ok && r.rules.size() == 3, "a BOM-prefixed file loads");
    }
}

void SecondCorruptInOneSecond() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(WriteBytes(path, "first"));
    CHECK(pf::LoadRules(dir.path(), kNow).corrupt);
    CHECK(WriteBytes(path, "second"));
    const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
    CHECK_MSG(r.corruptPath == path + L".corrupt-1700000000-1", "the second copy gets -1, the first is kept");
    std::string first, second;
    CHECK(ReadBytes(path + L".corrupt-1700000000", &first) && first == "first");
    CHECK(ReadBytes(path + L".corrupt-1700000000-1", &second) && second == "second");
}

// A listen address that is no longer on this machine does not make the file corrupt.
void StoredAddressFromAnotherNetwork() {
    pf_test::ScopedTempDir dir;
    std::vector<Rule> rules = {MakeRule("r_00000000000000aa", pf::Proto::Tcp, "10.255.255.1", 80, "lan")};
    std::string err;
    CHECK_MSG(pf::SaveRules(dir.path(), rules, &err), err.c_str());
    const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
    CHECK_MSG(r.status == LoadStatus::Ok && r.rules.size() == 1, "kept, to fail at bind time instead");
}

void UnreadableIsNotCorrupt() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(CreateDirectoryW(path.c_str(), nullptr));  // rules.json is a directory
    const pf::LoadResult r = pf::LoadRules(dir.path(), kNow);
    CHECK_MSG(r.status == LoadStatus::Unreadable && !r.corrupt, "a directory named rules.json: Unreadable");
    CHECK_MSG(Exists(path) && ListDir(dir.path()).size() == 1, "left alone, not renamed");
}

// The atomic replace: while another process holds rules.json open without sharing delete,
// the replace fails -- and the old file must be exactly what it was, with no temporary left.
void FailedSaveLeavesTheOldFile() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    std::string err;
    CHECK(pf::SaveRules(dir.path(), SampleRules(), &err));
    std::string before;
    CHECK(ReadBytes(path, &before));

    HANDLE holder = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(holder != INVALID_HANDLE_VALUE);
    std::vector<Rule> other = SampleRules();
    other.pop_back();
    err.clear();
    const bool saved = pf::SaveRules(dir.path(), other, &err);
    CloseHandle(holder);
    CHECK_MSG(!saved, "the replace fails while the file is held");
    CHECK_MSG(!err.empty(), "and says why");
    std::string after;
    CHECK(ReadBytes(path, &after));
    CHECK_MSG(after == before, "rules.json is byte for byte unchanged");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "the temporary file was removed");

    // And once released, the same save goes through.
    CHECK(pf::SaveRules(dir.path(), other, &err));
    CHECK(pf::LoadRules(dir.path(), kNow).rules.size() == 2);
}

// The replace, observed from inside: at the moment before it, the new content is complete in
// a temporary file next to rules.json and rules.json is still the old file. An in-place
// writer (truncate, then write) fails this even when nothing goes wrong.
void TemporaryThenReplace() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    std::string err;
    CHECK(pf::SaveRules(dir.path(), SampleRules(), &err));
    std::string before;
    CHECK(ReadBytes(path, &before));

    std::vector<Rule> next = SampleRules();
    next[0].name = "renamed";
    bool called = false;
    std::string tmpBytes, liveBytes;
    std::wstring tmpPath;
    pf::testing::SetBeforeReplaceHookForTest([&](const std::wstring& tmp) {
        called = true;
        tmpPath = tmp;
        ReadBytes(tmp, &tmpBytes);
        ReadBytes(path, &liveBytes);
        return true;
    });
    const bool saved = pf::SaveRules(dir.path(), next, &err);
    pf::testing::SetBeforeReplaceHookForTest(nullptr);
    CHECK_MSG(saved && called, "saved through the hook");
    const std::wstring prefix = path + L".tmp-";
    CHECK_MSG(tmpPath.size() == prefix.size() + 16 && tmpPath.compare(0, prefix.size(), prefix) == 0,
              "the temporary is rules.json.tmp-<16 hex> in the same directory");
    CHECK_MSG(liveBytes == before, "rules.json was still the old file just before the replace");
    std::vector<Rule> inTmp;
    CHECK_MSG(pf::ParseRuleDocument(pf::ParseJsonNoThrow(tmpBytes), &inTmp).empty() && inTmp.size() == 3 &&
                  inTmp[0].name == "renamed",
              "the temporary already held the complete new document");
    std::string after;
    CHECK(ReadBytes(path, &after));
    CHECK_MSG(after == tmpBytes, "and then became rules.json");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "no temporary left");

    // A failure at that moment: the old file stays, the temporary goes.
    next[0].name = "never";
    pf::testing::SetBeforeReplaceHookForTest([](const std::wstring&) { return false; });
    const bool failed = !pf::SaveRules(dir.path(), next, &err);
    pf::testing::SetBeforeReplaceHookForTest(nullptr);
    CHECK_MSG(failed, "the save reports the failure");
    std::string kept;
    CHECK(ReadBytes(path, &kept));
    CHECK_MSG(kept == after, "rules.json is byte for byte the last good file");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "the temporary was removed");
}

void RefusesWhatItWouldReject() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    std::string err;
    CHECK(pf::SaveRules(dir.path(), SampleRules(), &err));
    std::string before;
    CHECK(ReadBytes(path, &before));

    std::vector<Rule> dup = SampleRules();
    dup[1].id = dup[0].id;
    CHECK_MSG(!pf::SaveRules(dir.path(), dup, &err) && err == E::kDuplicateId, "duplicate ids are not written");
    std::vector<Rule> bad = SampleRules();
    bad[0].remoteHost = "127.1";
    CHECK_MSG(!pf::SaveRules(dir.path(), bad, &err) && err == E::kBadHost, "an invalid rule is not written");
    std::string after;
    CHECK(ReadBytes(path, &after));
    CHECK_MSG(after == before && ListDir(dir.path()).size() == 1, "nothing was touched");
}

void SaveIntoMissingDirectory() {
    pf_test::ScopedTempDir dir;
    const std::wstring missing = Join(dir.path(), L"\x4E0D\x5B58\x5728");  // 不存在
    std::string err;
    CHECK_MSG(!pf::SaveRules(missing, SampleRules(), &err), "the directory must exist");
    CHECK(!Exists(missing));
}

void RuleIds() {
    const std::string a = pf::NewRuleId(), b = pf::NewRuleId();
    CHECK_MSG(pf::IsRuleIdShaped(a) && pf::IsRuleIdShaped(b), "r_ + 16 lower-case hex");
    CHECK_MSG(a != b, "two ids differ");
}

}  // namespace

int main() {
    MissingFile();
    RoundTrip();
    CorruptFiles();
    SecondCorruptInOneSecond();
    StoredAddressFromAnotherNetwork();
    UnreadableIsNotCorrupt();
    FailedSaveLeavesTheOldFile();
    TemporaryThenReplace();
    RefusesWhatItWouldReject();
    SaveIntoMissingDirectory();
    RuleIds();
    return pf_test::TestExitCode();
}
