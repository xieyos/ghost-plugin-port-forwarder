#include "rule_store.h"

#include "json_util.h"
#include "random_hex.h"

#include <windows.h>

#include <atomic>
#include <cstring>
#include <ctime>
#include <vector>

namespace pf {

namespace {

// A sharing violation is usually a scanner or indexer that has the file open for a
// moment. Retry briefly, then give up: these run on a request thread.
constexpr int kShareRetries = 5;
constexpr DWORD kShareRetryMs = 40;

const wchar_t kTmpPrefix[] = L"rules.json.tmp-";
constexpr size_t kTmpHexDigits = 16;

testing::BeforeReplaceHook& ReplaceHook() {
    static testing::BeforeReplaceHook hook;
    return hook;
}
testing::RetryHook& RetryHookSlot() {
    static testing::RetryHook hook;
    return hook;
}

// Before each retry after a sharing violation.
void BeforeRetry(testing::RetryPoint where, int attempt) {
    if (RetryHookSlot()) RetryHookSlot()(where, attempt);
    Sleep(kShareRetryMs);
}
std::atomic<bool>& ForceClassicReplace() {
    static std::atomic<bool> force{false};
    return force;
}

std::string Win32Detail(const char* step, DWORD e) {
    return std::string(step) + " (error " + std::to_string(e) + ")";
}

bool IsSharingError(DWORD e) { return e == ERROR_SHARING_VIOLATION || e == ERROR_ACCESS_DENIED; }

enum class ReadOutcome { Ok, Missing, TooLarge, Error };

// Opens with every share mode (a reader must not get in a writer's way) and retries a
// sharing violation briefly. Reads at most kMaxRulesFileBytes; one byte more means "too
// large" (the file may also grow between the size check and the read).
ReadOutcome ReadRulesFile(const std::wstring& path, std::string* bytes, std::string* detail) {
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int attempt = 0;; ++attempt) {
        h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ReadOutcome::Missing;
        if (e != ERROR_SHARING_VIOLATION || attempt + 1 >= kShareRetries) {
            *detail = Win32Detail("open rules.json", e);
            return ReadOutcome::Error;
        }
        BeforeRetry(testing::RetryPoint::Read, attempt);
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(h, &size)) {
        *detail = Win32Detail("size of rules.json", GetLastError());
        CloseHandle(h);
        return ReadOutcome::Error;
    }
    if (size.QuadPart > static_cast<LONGLONG>(kMaxRulesFileBytes)) {
        CloseHandle(h);
        return ReadOutcome::TooLarge;
    }
    std::string data(kMaxRulesFileBytes + 1, '\0');
    size_t got = 0;
    for (;;) {
        DWORD n = 0;
        if (!ReadFile(h, data.data() + got, static_cast<DWORD>(data.size() - got), &n, nullptr)) {
            *detail = Win32Detail("read rules.json", GetLastError());
            CloseHandle(h);
            return ReadOutcome::Error;
        }
        if (n == 0) break;
        got += n;
        if (got == data.size()) break;
    }
    CloseHandle(h);
    if (got > kMaxRulesFileBytes) return ReadOutcome::TooLarge;
    data.resize(got);
    *bytes = std::move(data);
    return ReadOutcome::Ok;
}

// rules.json -> rules.json.corrupt-<now>[-n]. Never replaces an existing file.
bool RenameAside(const std::wstring& path, long long nowUnixSec, std::wstring* renamedTo, DWORD* win32) {
    const std::wstring base = path + L".corrupt-" + std::to_wstring(nowUnixSec);
    for (int n = 0; n < 100; ++n) {
        const std::wstring candidate = n == 0 ? base : base + L"-" + std::to_wstring(n);
        if (MoveFileExW(path.c_str(), candidate.c_str(), MOVEFILE_WRITE_THROUGH)) {
            *renamedTo = candidate;
            return true;
        }
        const DWORD e = GetLastError();
        if (e != ERROR_ALREADY_EXISTS && e != ERROR_FILE_EXISTS) {
            *win32 = e;
            return false;
        }
    }
    *win32 = ERROR_ALREADY_EXISTS;
    return false;
}

LoadResult Corrupt(const std::wstring& path, long long nowUnixSec, const std::string& code) {
    LoadResult r;
    r.status = LoadStatus::Corrupt;
    r.corrupt = true;
    r.code = code;
    DWORD e = 0;
    if (RenameAside(path, nowUnixSec, &r.corruptPath, &e)) {
        r.mayOverwrite = true;
    } else {
        // Still in place: overwriting it now would destroy the only copy.
        r.corruptPath.clear();
        r.mayOverwrite = false;
        r.detail = Win32Detail("rename the corrupt rules.json aside", e);
    }
    return r;
}

bool IsStaleTempName(const wchar_t* name) {
    const size_t prefixLen = sizeof(kTmpPrefix) / sizeof(kTmpPrefix[0]) - 1;
    if (wcsncmp(name, kTmpPrefix, prefixLen) != 0) return false;
    const wchar_t* hex = name + prefixLen;
    size_t n = 0;
    for (; hex[n]; ++n) {
        const wchar_t c = hex[n];
        if (!((c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f'))) return false;
    }
    return n == kTmpHexDigits;
}

// Removes rules.json.tmp-<16 lower hex> regular files left by an interrupted save.
// Nothing else is touched: no other name, no directory, no reparse point.
int RemoveStaleTemps(const std::wstring& dataDir) {
    std::wstring pattern = dataDir;
    if (pattern.back() != L'\\' && pattern.back() != L'/') pattern.push_back(L'\\');
    const std::wstring dirWithSep = pattern;
    pattern += kTmpPrefix;
    pattern += L"*";
    WIN32_FIND_DATAW fd;
    // FindExInfoBasic: no 8.3 names. The pattern may still match a short name, so the
    // long name is checked exactly below.
    HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int removed = 0;
    do {
        if (fd.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (!IsStaleTempName(fd.cFileName)) continue;
        if (DeleteFileW((dirWithSep + fd.cFileName).c_str())) ++removed;
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return removed;
}

bool WriteAll(HANDLE h, const std::string& bytes) {
    size_t done = 0;
    while (done < bytes.size()) {
        DWORD n = 0;
        if (!WriteFile(h, bytes.data() + done, static_cast<DWORD>(bytes.size() - done), &n, nullptr) || n == 0) {
            return false;
        }
        done += n;
    }
    return true;
}

enum class ReplaceOutcome { Replaced, Unsupported, Failed };

// Renames the open temporary over `target` through its own handle, with POSIX semantics:
// the old rules.json is unlinked even if someone holds it open with FILE_SHARE_DELETE.
ReplaceOutcome PosixReplace(HANDLE h, const std::wstring& target, DWORD* win32) {
    if (ForceClassicReplace().load()) return ReplaceOutcome::Unsupported;
    const size_t nameBytes = target.size() * sizeof(wchar_t);
    std::vector<unsigned char> buf(sizeof(FILE_RENAME_INFO) + nameBytes, 0);
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buf.data());
    info->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS | FILE_RENAME_FLAG_POSIX_SEMANTICS;
    info->RootDirectory = nullptr;
    info->FileNameLength = static_cast<DWORD>(nameBytes);
    memcpy(info->FileName, target.data(), nameBytes);
    for (int attempt = 0;; ++attempt) {
        if (SetFileInformationByHandle(h, FileRenameInfoEx, info, static_cast<DWORD>(buf.size()))) {
            return ReplaceOutcome::Replaced;
        }
        const DWORD e = GetLastError();
        if (e == ERROR_INVALID_PARAMETER || e == ERROR_NOT_SUPPORTED || e == ERROR_INVALID_FUNCTION) {
            return ReplaceOutcome::Unsupported;
        }
        if (!IsSharingError(e) || attempt + 1 >= kShareRetries) {
            *win32 = e;
            return ReplaceOutcome::Failed;
        }
        BeforeRetry(testing::RetryPoint::Replace, attempt);
    }
}

bool ClassicReplace(const std::wstring& tmp, const std::wstring& target, DWORD* win32) {
    for (int attempt = 0;; ++attempt) {
        if (MoveFileExW(tmp.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return true;
        const DWORD e = GetLastError();
        if (!IsSharingError(e) || attempt + 1 >= kShareRetries) {
            *win32 = e;
            return false;
        }
        BeforeRetry(testing::RetryPoint::Replace, attempt);
    }
}

}  // namespace

std::wstring RulesFilePath(const std::wstring& dataDir) {
    std::wstring p = dataDir;
    if (!p.empty() && p.back() != L'\\' && p.back() != L'/') p.push_back(L'\\');
    return p + L"rules.json";
}

RuleStore::RuleStore(std::wstring dataDir) : dataDir_(std::move(dataDir)) {
    if (!dataDir_.empty()) path_ = RulesFilePath(dataDir_);
}

bool RuleStore::MayOverwrite() const {
    std::lock_guard<std::mutex> lock(mu_);
    return mayOverwrite_;
}

LoadResult RuleStore::Load() {
    return Load(static_cast<long long>(std::time(nullptr)));
}

LoadResult RuleStore::Load(long long nowUnixSec) {
    std::lock_guard<std::mutex> lock(mu_);
    LoadResult r;
    if (dataDir_.empty()) {
        r.status = LoadStatus::Unreadable;
        r.code = store_err::kBadDataDir;
        mayOverwrite_ = false;
        return r;
    }
    const int stale = RemoveStaleTemps(dataDir_);

    std::string bytes, detail;
    switch (ReadRulesFile(path_, &bytes, &detail)) {
        case ReadOutcome::Missing:
            r.status = LoadStatus::Missing;
            r.mayOverwrite = true;
            break;
        case ReadOutcome::Error:
            r.status = LoadStatus::Unreadable;
            r.code = store_err::kIoError;
            r.detail = detail;
            r.mayOverwrite = false;
            break;
        case ReadOutcome::TooLarge:
            r = Corrupt(path_, nowUnixSec, store_err::kTooLarge);
            break;
        case ReadOutcome::Ok: {
            const json doc = ParseJsonNoThrow(bytes);
            std::vector<Rule> rules;
            const std::string code = doc.is_discarded() ? std::string(store_err::kBadJson) : ParseRuleDocument(doc, &rules);
            if (!code.empty()) {
                r = Corrupt(path_, nowUnixSec, code);
            } else {
                r.status = LoadStatus::Ok;
                r.rules = std::move(rules);
                r.mayOverwrite = true;
            }
            break;
        }
    }
    r.staleTempsRemoved = stale;
    mayOverwrite_ = r.mayOverwrite;
    return r;
}

bool RuleStore::Save(const std::vector<Rule>& rules, std::string* code, std::string* detail) {
    std::lock_guard<std::mutex> lock(mu_);
    auto fail = [&](const char* c, const std::string& d) {
        if (code) *code = c;
        if (detail) *detail = d;
        return false;
    };
    if (dataDir_.empty()) return fail(store_err::kBadDataDir, "");
    if (!mayOverwrite_) return fail(store_err::kStoreLocked, "rules.json was not loaded cleanly");

    std::string invalid;
    for (const Rule& r : rules) {
        invalid = ValidateStoredRule(r);
        if (!invalid.empty()) break;
    }
    if (invalid.empty()) invalid = ValidateSet(rules);
    if (!invalid.empty()) {
        if (code) *code = invalid;
        if (detail) detail->clear();
        return false;
    }

    const std::string bytes = RuleDocumentToJson(rules).dump(2, ' ', false, json::error_handler_t::replace) + "\n";
    const std::string suffix = RandomHex(kTmpHexDigits / 2);
    if (suffix.empty()) return fail(store_err::kRngFailed, "");
    std::wstring tmp = dataDir_;
    if (tmp.back() != L'\\' && tmp.back() != L'/') tmp.push_back(L'\\');
    tmp += kTmpPrefix;
    tmp += std::wstring(suffix.begin(), suffix.end());

    // DELETE access: the rename goes through this handle. Sharing reads only.
    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return fail(store_err::kIoError, Win32Detail("create the temporary", GetLastError()));
    if (!WriteAll(h, bytes) || !FlushFileBuffers(h)) {
        const DWORD e = GetLastError();
        CloseHandle(h);
        DeleteFileW(tmp.c_str());
        return fail(store_err::kIoError, Win32Detail("write the temporary", e));
    }
    if (ReplaceHook() && !ReplaceHook()(tmp)) {
        CloseHandle(h);
        DeleteFileW(tmp.c_str());
        return fail(store_err::kIoError, "the test hook failed the replace");
    }

    DWORD e = 0;
    const ReplaceOutcome posix = PosixReplace(h, path_, &e);
    CloseHandle(h);
    if (posix == ReplaceOutcome::Replaced) return true;
    if (posix == ReplaceOutcome::Unsupported && ClassicReplace(tmp, path_, &e)) return true;
    DeleteFileW(tmp.c_str());
    return fail(store_err::kIoError, Win32Detail("replace rules.json", e));
}

void testing::SetBeforeReplaceHookForTest(BeforeReplaceHook hook) {
    ReplaceHook() = std::move(hook);
}

void testing::SetRetryHookForTest(RetryHook hook) {
    RetryHookSlot() = std::move(hook);
}

void testing::SetForceClassicReplaceForTest(bool force) {
    ForceClassicReplace().store(force);
}

std::string NewRuleId() {
    const std::string hex = RandomHex(8);
    return hex.empty() ? std::string() : "r_" + hex;
}

}  // namespace pf
