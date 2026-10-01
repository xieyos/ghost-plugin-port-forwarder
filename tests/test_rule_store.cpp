// Functional: rules.json on a real file system (rule_store.h), in a temporary directory
// whose name has a CJK component.

#include "rule_store.h"
#include "test_support.h"

#include <windows.h>

#include <string>
#include <vector>

using pf::LoadStatus;
using pf::Rule;
using pf::RuleStore;
namespace E = pf::rule_err;
namespace S = pf::store_err;

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

// Opens `path` for reading with the given share mode, the way another process would.
HANDLE Hold(const std::wstring& path, DWORD share) {
    return CreateFileW(path.c_str(), GENERIC_READ, share, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
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

// A store over `dir` that has been loaded (so it may save).
bool SaveFresh(const std::wstring& dir, const std::vector<Rule>& rules) {
    RuleStore store(dir);
    store.Load(kNow);
    std::string code;
    return store.Save(rules, &code);
}

void MissingFile() {
    pf_test::ScopedTempDir dir;
    CHECK(dir.ok());
    RuleStore store(dir.path());
    const pf::LoadResult r = store.Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Missing, "no rules.json: Missing");
    CHECK(!r.corrupt && r.rules.empty() && r.code.empty());
    CHECK_MSG(r.mayOverwrite && store.MayOverwrite(), "a first start may save");
    CHECK_MSG(ListDir(dir.path()).empty(), "loading created nothing");
}

void SaveBeforeLoad() {
    pf_test::ScopedTempDir dir;
    RuleStore store(dir.path());
    std::string code;
    CHECK_MSG(!store.MayOverwrite(), "a store that has not loaded may not overwrite");
    CHECK_MSG(!store.Save(SampleRules(), &code) && code == S::kStoreLocked, "save before load: store_locked");
    CHECK(ListDir(dir.path()).empty());
}

void EmptyDataDir() {
    RuleStore store(L"");
    const pf::LoadResult r = store.Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Unreadable && r.code == S::kBadDataDir && !r.mayOverwrite,
              "empty dataDir: Unreadable, bad_data_dir");
    std::string code;
    CHECK_MSG(!store.Save(SampleRules(), &code) && code == S::kBadDataDir, "empty dataDir: save refused");
}

void RoundTrip() {
    pf_test::ScopedTempDir dir;
    const std::vector<Rule> rules = SampleRules();
    RuleStore store(dir.path());
    store.Load(kNow);
    std::string code, detail;
    CHECK_MSG(store.Save(rules, &code, &detail), (code + " " + detail).c_str());
    RuleStore again(dir.path());
    const pf::LoadResult r = again.Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Ok && r.mayOverwrite, "saved file loads");
    CHECK(!r.corrupt);
    CHECK_MSG(r.rules.size() == rules.size(), "same number of rules");
    for (size_t i = 0; i < rules.size() && i < r.rules.size(); ++i) CHECK_MSG(r.rules[i] == rules[i], "rule round trip");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "only rules.json in the directory (no temporary left)");

    std::string bytes;
    CHECK(ReadBytes(pf::RulesFilePath(dir.path()), &bytes));
    CHECK_MSG(bytes.size() >= 3 && bytes.compare(0, 3, "\xEF\xBB\xBF") != 0, "no BOM");
    CHECK_MSG(bytes.find("\xE7\xAB\xAF\xE5\x8F\xA3") != std::string::npos, "the name is written as UTF-8");

    // Saving an empty set is a valid file too, and the same store keeps saving.
    CHECK(store.Save({}, &code));
    const pf::LoadResult empty = RuleStore(dir.path()).Load(kNow);
    CHECK_MSG(empty.status == LoadStatus::Ok && empty.rules.empty(), "empty set round trip");

    CHECK(pf::RulesFilePath(L"C:\\d\\") == L"C:\\d\\rules.json");
    CHECK(pf::RulesFilePath(L"C:\\d") == L"C:\\d\\rules.json");
}

// Writes `bytes` as rules.json, loads, and checks it was renamed aside byte for byte.
void ExpectCorrupt(const char* label, const std::string& bytes, const std::string& code) {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(WriteBytes(path, bytes));
    RuleStore store(dir.path());
    const pf::LoadResult r = store.Load(kNow);
    const std::string l = std::string(label) + ": status Corrupt, code '" + code + "', got '" + r.code + "'";
    CHECK_MSG(r.status == LoadStatus::Corrupt && r.corrupt, l.c_str());
    CHECK_MSG(r.code == code, l.c_str());
    CHECK_MSG(r.rules.empty(), "starts with no rules");
    const std::wstring aside = path + L".corrupt-1700000000";
    CHECK_MSG(r.corruptPath == aside, "renamed to rules.json.corrupt-<now>");
    CHECK_MSG(r.mayOverwrite, "moved aside, so saving is allowed");
    CHECK_MSG(!Exists(path), "rules.json is gone");
    std::string kept;
    CHECK_MSG(ReadBytes(aside, &kept) && kept == bytes, "the corrupt copy is byte for byte the old file");
}

void CorruptFiles() {
    ExpectCorrupt("not JSON", "{\"v\":1,\"rules\":[", S::kBadJson);
    ExpectCorrupt("empty file", "", S::kBadJson);
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
        CHECK_MSG(RuleStore(dir.path()).Load(kNow).status == LoadStatus::Ok, "exactly 256 KB loads");
    }
    ExpectCorrupt("256 KB + 1", exact + " ", S::kTooLarge);

    // A UTF-8 BOM (Notepad adds one) is not damage: the parser skips it, and we never
    // write one ourselves (RoundTrip checks that).
    {
        pf_test::ScopedTempDir dir;
        const std::string withBom = "\xEF\xBB\xBF" + pf::RuleDocumentToJson(SampleRules()).dump();
        CHECK(WriteBytes(pf::RulesFilePath(dir.path()), withBom));
        const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
        CHECK_MSG(r.status == LoadStatus::Ok && r.rules.size() == 3, "a BOM-prefixed file loads");
    }
}

void SecondCorruptInOneSecond() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(WriteBytes(path, "first"));
    CHECK(RuleStore(dir.path()).Load(kNow).corrupt);
    CHECK(WriteBytes(path, "second"));
    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    CHECK_MSG(r.corruptPath == path + L".corrupt-1700000000-1", "the second copy gets -1, the first is kept");
    std::string first, second;
    CHECK(ReadBytes(path + L".corrupt-1700000000", &first) && first == "first");
    CHECK(ReadBytes(path + L".corrupt-1700000000-1", &second) && second == "second");
}

// A corrupt file that cannot be moved aside (another process holds it without sharing
// delete) stays in place, and nothing may overwrite it.
void CorruptButStuck() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    const std::string bytes = "{ this is what the user typed";
    CHECK(WriteBytes(path, bytes));
    HANDLE holder = Hold(path, FILE_SHARE_READ | FILE_SHARE_WRITE);
    CHECK(holder != INVALID_HANDLE_VALUE);
    RuleStore store(dir.path());
    const pf::LoadResult r = store.Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Corrupt && r.code == S::kBadJson, "still Corrupt");
    CHECK_MSG(r.corruptPath.empty() && !r.detail.empty(), "no copy, and the detail says why");
    CHECK_MSG(!r.mayOverwrite && !store.MayOverwrite(), "may not overwrite");
    CloseHandle(holder);  // released: only the store's own lock is left to stop the save
    std::string code;
    CHECK_MSG(!store.Save(SampleRules(), &code) && code == S::kStoreLocked, "save refused: store_locked");
    std::string after;
    CHECK_MSG(ReadBytes(path, &after) && after == bytes, "the corrupt file is byte for byte intact");

    // A later load that succeeds (here: moves it aside) unlocks the store.
    const pf::LoadResult again = store.Load(kNow);
    CHECK_MSG(again.corrupt && again.mayOverwrite && !again.corruptPath.empty(), "moved aside on the next load");
    CHECK_MSG(store.Save(SampleRules(), &code), "and saving works again");
}

// A listen address that is no longer on this machine does not make the file corrupt.
void StoredAddressFromAnotherNetwork() {
    pf_test::ScopedTempDir dir;
    std::vector<Rule> rules = {MakeRule("r_00000000000000aa", pf::Proto::Tcp, "10.255.255.1", 80, "lan")};
    CHECK(SaveFresh(dir.path(), rules));
    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Ok && r.rules.size() == 1, "kept, to fail at bind time instead");
}

void UnreadableDirectory() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(CreateDirectoryW(path.c_str(), nullptr));  // rules.json is a directory
    RuleStore store(dir.path());
    const pf::LoadResult r = store.Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Unreadable && !r.corrupt && r.code == S::kIoError,
              "a directory named rules.json: Unreadable, io_error");
    CHECK_MSG(!r.mayOverwrite, "may not overwrite");
    CHECK_MSG(Exists(path) && ListDir(dir.path()).size() == 1, "left alone, not renamed");
}

// The item that matters: a file the store could not read is never replaced by a save.
void UnreadableIsNeverOverwritten() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(SaveFresh(dir.path(), SampleRules()));
    std::string before;
    CHECK(ReadBytes(path, &before));

    HANDLE holder = Hold(path, 0);  // no sharing at all: every open fails
    CHECK(holder != INVALID_HANDLE_VALUE);
    int retries = 0;
    pf::testing::SetRetryHookForTest([&](pf::testing::RetryPoint where, int) {
        if (where == pf::testing::RetryPoint::Read) ++retries;
    });
    RuleStore store(dir.path());
    const pf::LoadResult r = store.Load(kNow);
    pf::testing::SetRetryHookForTest(nullptr);
    CloseHandle(holder);
    CHECK_MSG(r.status == LoadStatus::Unreadable && r.code == S::kIoError && !r.mayOverwrite, "Unreadable");
    CHECK_MSG(retries == 4, "a sharing violation is retried, boundedly (4 retries after the first try)");

    std::string code;
    CHECK_MSG(!store.Save({}, &code) && code == S::kStoreLocked, "the empty list is not saved over it");
    std::string after;
    CHECK_MSG(ReadBytes(path, &after) && after == before, "rules.json is byte for byte unchanged");

    const pf::LoadResult again = store.Load(kNow);
    CHECK_MSG(again.status == LoadStatus::Ok && again.rules.size() == 3, "readable again: the rules are back");
    CHECK_MSG(store.Save(SampleRules(), &code), "and the store unlocked");
}

// An editor that has rules.json open for writing, sharing everything, does not stop a
// load: the store's own open shares read, write and delete.
void SharingWriterDoesNotBlockLoad() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(SaveFresh(dir.path(), SampleRules()));
    HANDLE writer = CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, nullptr);
    CHECK(writer != INVALID_HANDLE_VALUE);
    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    CloseHandle(writer);
    CHECK_MSG(r.status == LoadStatus::Ok && r.rules.size() == 3, "loads while a sharing writer holds the file");
}

// A holder that lets go during the retries does not make the load fail.
void ShortSharingViolationIsRetried() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    CHECK(SaveFresh(dir.path(), SampleRules()));
    HANDLE holder = Hold(path, 0);
    CHECK(holder != INVALID_HANDLE_VALUE);
    pf::testing::SetRetryHookForTest([&](pf::testing::RetryPoint where, int attempt) {
        if (where == pf::testing::RetryPoint::Read && attempt == 0 && holder != INVALID_HANDLE_VALUE) {
            CloseHandle(holder);
            holder = INVALID_HANDLE_VALUE;
        }
    });
    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    pf::testing::SetRetryHookForTest(nullptr);
    if (holder != INVALID_HANDLE_VALUE) CloseHandle(holder);
    CHECK_MSG(r.status == LoadStatus::Ok && r.rules.size() == 3, "loaded after the holder let go");
}

// The atomic replace: while another process holds rules.json open WITHOUT sharing delete,
// the replace fails -- and the old file must be exactly what it was, with no temporary left.
void FailedSaveLeavesTheOldFile() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    RuleStore store(dir.path());
    store.Load(kNow);
    std::string code, detail;
    CHECK(store.Save(SampleRules(), &code));
    std::string before;
    CHECK(ReadBytes(path, &before));

    HANDLE holder = Hold(path, FILE_SHARE_READ);
    CHECK(holder != INVALID_HANDLE_VALUE);
    std::vector<Rule> other = SampleRules();
    other.pop_back();
    code.clear();
    int retries = 0;
    pf::testing::SetRetryHookForTest([&](pf::testing::RetryPoint where, int) {
        if (where == pf::testing::RetryPoint::Replace) ++retries;
    });
    const bool saved = store.Save(other, &code, &detail);
    pf::testing::SetRetryHookForTest(nullptr);
    CloseHandle(holder);
    CHECK_MSG(retries == 4, "the replace is retried, boundedly (4 retries after the first try)");
    CHECK_MSG(!saved, "the replace fails while the file is held without share-delete");
    CHECK_MSG(code == S::kIoError && !detail.empty(), "io_error, and the detail says why");
    std::string after;
    CHECK(ReadBytes(path, &after));
    CHECK_MSG(after == before, "rules.json is byte for byte unchanged");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "the temporary file was removed");

    // A failed replace does not lock the store: once released, the same save goes through.
    CHECK(store.Save(other, &code));
    CHECK(RuleStore(dir.path()).Load(kNow).rules.size() == 2);
}

// A holder without share-delete that lets go during the retries does not fail the save.
void ShortHoldOnReplaceIsRetried() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    RuleStore store(dir.path());
    store.Load(kNow);
    std::string code, detail;
    CHECK(store.Save(SampleRules(), &code));
    HANDLE holder = Hold(path, FILE_SHARE_READ);
    CHECK(holder != INVALID_HANDLE_VALUE);
    pf::testing::SetRetryHookForTest([&](pf::testing::RetryPoint where, int attempt) {
        if (where == pf::testing::RetryPoint::Replace && attempt == 0 && holder != INVALID_HANDLE_VALUE) {
            CloseHandle(holder);
            holder = INVALID_HANDLE_VALUE;
        }
    });
    std::vector<Rule> next = SampleRules();
    next[0].name = "after the hold";
    const bool saved = store.Save(next, &code, &detail);
    pf::testing::SetRetryHookForTest(nullptr);
    if (holder != INVALID_HANDLE_VALUE) CloseHandle(holder);
    CHECK_MSG(saved, ("saved once the holder let go: " + code + " " + detail).c_str());
    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    CHECK_MSG(!r.rules.empty() && r.rules[0].name == "after the hold", "the new file is in place");
}

// A reader that shares delete -- what scanners and indexers do -- must not block a save.
void ShareDeleteReaderDoesNotBlock() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    RuleStore store(dir.path());
    store.Load(kNow);
    std::string code, detail;
    CHECK(store.Save(SampleRules(), &code));

    HANDLE holder = Hold(path, FILE_SHARE_READ | FILE_SHARE_DELETE);
    CHECK(holder != INVALID_HANDLE_VALUE);
    std::vector<Rule> next = SampleRules();
    next[0].name = "while held";
    const bool saved = store.Save(next, &code, &detail);
    CHECK_MSG(saved, ("a share-delete reader does not block the replace: " + code + " " + detail).c_str());
    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    CloseHandle(holder);
    CHECK_MSG(r.status == LoadStatus::Ok && !r.rules.empty() && r.rules[0].name == "while held",
              "the new file is in place while the old one is still held");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "no temporary left");

    // The fallback (MoveFileExW) cannot do this -- the reason for the POSIX rename. This
    // also shows the force switch really takes the other path.
    pf::testing::SetForceClassicReplaceForTest(true);
    std::string fallbackBefore;
    CHECK(ReadBytes(path, &fallbackBefore));
    holder = Hold(path, FILE_SHARE_READ | FILE_SHARE_DELETE);
    CHECK(holder != INVALID_HANDLE_VALUE);
    next[0].name = "classic";
    const bool classicSaved = store.Save(next, &code, &detail);
    CloseHandle(holder);
    CHECK_MSG(!classicSaved && code == S::kIoError, "MoveFileExW is blocked by the same reader");
    std::string fallbackAfter;
    CHECK(ReadBytes(path, &fallbackAfter));
    CHECK_MSG(fallbackAfter == fallbackBefore && ListDir(dir.path()).size() == 1, "and leaves everything intact");
    // Without a holder the fallback saves normally.
    CHECK_MSG(store.Save(next, &code), "the fallback path saves");
    pf::testing::SetForceClassicReplaceForTest(false);
    const pf::LoadResult viaFallback = RuleStore(dir.path()).Load(kNow);
    CHECK_MSG(!viaFallback.rules.empty() && viaFallback.rules[0].name == "classic", "fallback round trip");
}

// The replace, observed from inside: at the moment before it, the new content is complete in
// a temporary file next to rules.json and rules.json is still the old file. An in-place
// writer (truncate, then write) fails this even when nothing goes wrong.
void TemporaryThenReplace() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    RuleStore store(dir.path());
    store.Load(kNow);
    std::string code;
    CHECK(store.Save(SampleRules(), &code));
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
    const bool saved = store.Save(next, &code);
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
    const bool failed = !store.Save(next, &code);
    pf::testing::SetBeforeReplaceHookForTest(nullptr);
    CHECK_MSG(failed && code == S::kIoError, "the save reports the failure as io_error");
    std::string kept;
    CHECK(ReadBytes(path, &kept));
    CHECK_MSG(kept == after, "rules.json is byte for byte the last good file");
    CHECK_MSG(ListDir(dir.path()).size() == 1, "the temporary was removed");
}

// Leftovers of a save interrupted by a crash: exactly rules.json.tmp-<16 lower hex>,
// regular files only, are removed on load; every near miss is left alone.
void StaleTemporaries() {
    pf_test::ScopedTempDir dir;
    const std::wstring stale[] = {L"rules.json.tmp-0123456789abcdef", L"rules.json.tmp-fedcba9876543210"};
    // NTFS names are case-insensitive, so the upper-case near miss uses other digits than a
    // stale name (it would otherwise be the same file).
    const std::wstring keep[] = {
        L"rules.json.tmp-ABCDEF0123456789",     L"rules.json.tmp-0123456789abcde",
        L"rules.json.tmp-0123456789abcdef0",    L"rules.json.tmp-0123456789abcdef.bak",
        L"rules.json.tmp-g123456789abcdef",     L"xrules.json.tmp-0123456789abcdef",
        L"rules.json.tmp-",                     L"rules.json.corrupt-1700000000",
    };
    for (const auto& n : stale) CHECK(WriteBytes(Join(dir.path(), n), "partial"));
    for (const auto& n : keep) CHECK(WriteBytes(Join(dir.path(), n), "keep"));
    const std::wstring dirShaped = Join(dir.path(), L"rules.json.tmp-aaaaaaaaaaaaaaaa");
    CHECK(CreateDirectoryW(dirShaped.c_str(), nullptr));

    const pf::LoadResult r = RuleStore(dir.path()).Load(kNow);
    CHECK_MSG(r.status == LoadStatus::Missing, "the load itself is unaffected");
    CHECK_MSG(r.staleTempsRemoved == 2, "two stale temporaries removed");
    for (const auto& n : stale) CHECK_MSG(!Exists(Join(dir.path(), n)), "stale temporary removed");
    for (const auto& n : keep) CHECK_MSG(Exists(Join(dir.path(), n)), "near miss kept");
    CHECK_MSG(Exists(dirShaped), "a directory of the exact shape is kept");
}

void RefusesWhatItWouldReject() {
    pf_test::ScopedTempDir dir;
    const std::wstring path = pf::RulesFilePath(dir.path());
    RuleStore store(dir.path());
    store.Load(kNow);
    std::string code;
    CHECK(store.Save(SampleRules(), &code));
    std::string before;
    CHECK(ReadBytes(path, &before));

    std::vector<Rule> dup = SampleRules();
    dup[1].id = dup[0].id;
    CHECK_MSG(!store.Save(dup, &code) && code == E::kDuplicateId, "duplicate ids are not written");
    std::vector<Rule> bad = SampleRules();
    bad[0].remoteHost = "127.1";
    CHECK_MSG(!store.Save(bad, &code) && code == E::kBadHost, "an invalid rule is not written");
    std::string after;
    CHECK(ReadBytes(path, &after));
    CHECK_MSG(after == before && ListDir(dir.path()).size() == 1, "nothing was touched");
}

void SaveIntoMissingDirectory() {
    pf_test::ScopedTempDir dir;
    const std::wstring missing = Join(dir.path(), L"\x4E0D\x5B58\x5728");  // 不存在
    RuleStore store(missing);
    CHECK_MSG(store.Load(kNow).status == LoadStatus::Missing, "a missing directory loads as Missing");
    std::string code;
    CHECK_MSG(!store.Save(SampleRules(), &code) && code == S::kIoError, "the directory must exist: io_error");
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
    SaveBeforeLoad();
    EmptyDataDir();
    RoundTrip();
    CorruptFiles();
    SecondCorruptInOneSecond();
    CorruptButStuck();
    StoredAddressFromAnotherNetwork();
    UnreadableDirectory();
    UnreadableIsNeverOverwritten();
    SharingWriterDoesNotBlockLoad();
    ShortSharingViolationIsRetried();
    FailedSaveLeavesTheOldFile();
    ShortHoldOnReplaceIsRetried();
    ShareDeleteReaderDoesNotBlock();
    TemporaryThenReplace();
    StaleTemporaries();
    RefusesWhatItWouldReject();
    SaveIntoMissingDirectory();
    RuleIds();
    return pf_test::TestExitCode();
}
