#include "rule_store.h"

#include "json_util.h"
#include "random_hex.h"

#include <windows.h>

#include <ctime>

namespace pf {

namespace {

testing::BeforeReplaceHook& ReplaceHook() {
    static testing::BeforeReplaceHook hook;
    return hook;
}

enum class ReadOutcome { Ok, Missing, TooLarge, Error };

// Reads at most kMaxRulesFileBytes; one byte more means "too large" (the file may also
// grow between the size check and the read).
ReadOutcome ReadRulesFile(const std::wstring& path, std::string* bytes, DWORD* win32) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD e = GetLastError();
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND) return ReadOutcome::Missing;
        *win32 = e;
        return ReadOutcome::Error;
    }
    LARGE_INTEGER size = {};
    if (!GetFileSizeEx(h, &size)) {
        *win32 = GetLastError();
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
            *win32 = GetLastError();
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

LoadResult Corrupt(const std::wstring& path, long long nowUnixSec, const std::string& reason) {
    LoadResult r;
    r.status = LoadStatus::Corrupt;
    r.corrupt = true;
    r.reason = reason;
    DWORD e = 0;
    if (!RenameAside(path, nowUnixSec, &r.corruptPath, &e)) {
        r.corruptPath.clear();
        r.reason += "; could not rename it aside (error " + std::to_string(e) + ")";
    }
    return r;
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

}  // namespace

std::wstring RulesFilePath(const std::wstring& dataDir) {
    std::wstring p = dataDir;
    if (!p.empty() && p.back() != L'\\' && p.back() != L'/') p.push_back(L'\\');
    return p + L"rules.json";
}

LoadResult LoadRules(const std::wstring& dataDir, long long nowUnixSec) {
    const std::wstring path = RulesFilePath(dataDir);
    std::string bytes;
    DWORD win32 = 0;
    switch (ReadRulesFile(path, &bytes, &win32)) {
        case ReadOutcome::Missing: {
            LoadResult r;
            r.status = LoadStatus::Missing;
            return r;
        }
        case ReadOutcome::Error: {
            LoadResult r;
            r.status = LoadStatus::Unreadable;
            r.reason = "error " + std::to_string(win32);
            return r;
        }
        case ReadOutcome::TooLarge:
            return Corrupt(path, nowUnixSec, "too_large");
        case ReadOutcome::Ok:
            break;
    }
    const json doc = ParseJsonNoThrow(bytes);
    if (doc.is_discarded()) return Corrupt(path, nowUnixSec, "bad_json");
    std::vector<Rule> rules;
    const std::string code = ParseRuleDocument(doc, &rules);
    if (!code.empty()) return Corrupt(path, nowUnixSec, code);
    LoadResult r;
    r.status = LoadStatus::Ok;
    r.rules = std::move(rules);
    return r;
}

LoadResult LoadRules(const std::wstring& dataDir) {
    return LoadRules(dataDir, static_cast<long long>(std::time(nullptr)));
}

bool SaveRules(const std::wstring& dataDir, const std::vector<Rule>& rules, std::string* error) {
    std::string code;
    for (const Rule& r : rules) {
        code = ValidateStoredRule(r);
        if (!code.empty()) break;
    }
    if (code.empty()) code = ValidateSet(rules);
    if (!code.empty()) {
        if (error) *error = code;
        return false;
    }

    const std::string bytes = RuleDocumentToJson(rules).dump(2, ' ', false, json::error_handler_t::replace) + "\n";
    const std::wstring path = RulesFilePath(dataDir);
    const std::string suffix = RandomHex(8);
    if (suffix.empty()) {
        if (error) *error = "random number generator failed";
        return false;
    }
    const std::wstring tmp = path + L".tmp-" + std::wstring(suffix.begin(), suffix.end());

    HANDLE h = CreateFileW(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        if (error) *error = "cannot create the temporary file (error " + std::to_string(GetLastError()) + ")";
        return false;
    }
    if (!WriteAll(h, bytes) || !FlushFileBuffers(h)) {
        const DWORD e = GetLastError();
        CloseHandle(h);
        DeleteFileW(tmp.c_str());
        if (error) *error = "cannot write the temporary file (error " + std::to_string(e) + ")";
        return false;
    }
    CloseHandle(h);
    if (ReplaceHook() && !ReplaceHook()(tmp)) {
        DeleteFileW(tmp.c_str());
        if (error) *error = "the test hook failed the replace";
        return false;
    }
    if (!MoveFileExW(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        const DWORD e = GetLastError();
        DeleteFileW(tmp.c_str());
        if (error) *error = "cannot replace rules.json (error " + std::to_string(e) + ")";
        return false;
    }
    return true;
}

void testing::SetBeforeReplaceHookForTest(BeforeReplaceHook hook) {
    ReplaceHook() = std::move(hook);
}

std::string NewRuleId() {
    const std::string hex = RandomHex(8);
    return hex.empty() ? std::string() : "r_" + hex;
}

}  // namespace pf
