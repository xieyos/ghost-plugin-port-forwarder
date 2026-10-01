// rules.json in the plugin's data directory.
//
// Loading never "repairs": a file that cannot be parsed, fails validation or is larger
// than 256 KB is renamed aside to rules.json.corrupt-<unix seconds> -- kept, so nothing
// the user typed is destroyed -- and the plugin starts with no rules and tells the page
// (LoadResult::corrupt).
//
// Saving is atomic: a temporary file with a random name in the same directory, written,
// flushed, then moved over rules.json with MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH).
// If any step fails, rules.json is exactly what it was before.
#pragma once

#include "rules.h"

#include <functional>
#include <string>
#include <vector>

namespace pf {

constexpr size_t kMaxRulesFileBytes = 256 * 1024;

enum class LoadStatus {
    Ok,          // read and valid (possibly an empty rule list)
    Missing,     // no rules.json yet: a first start
    Corrupt,     // renamed aside (corruptPath), started empty
    Unreadable,  // exists but could not be opened or read; left alone, started empty
};

struct LoadResult {
    LoadStatus status = LoadStatus::Missing;
    std::vector<Rule> rules;
    // True exactly when status == Corrupt; the flag the page shows.
    bool corrupt = false;
    // Where the bad file went; empty if it could not be renamed (then `reason` says so).
    std::wstring corruptPath;
    // Corrupt: too_large, bad_json or a rule_err code. Unreadable: the Win32 error.
    std::string reason;
};

// <dataDir>\rules.json
std::wstring RulesFilePath(const std::wstring& dataDir);

// `nowUnixSec` names the corrupt copy; when that name is taken, -1, -2, ... are tried.
// Unreadable is not Corrupt: a file we could not read is not known to be bad, and a
// caller must not save over it without telling the user (SaveRules would replace it).
LoadResult LoadRules(const std::wstring& dataDir, long long nowUnixSec);
LoadResult LoadRules(const std::wstring& dataDir);  // the current time

// Refuses (returns false, `error` = the code, nothing written) a set that LoadRules would
// reject -- every rule ValidateStoredRule, then ValidateSet -- so the plugin never writes
// a file it would rename aside on the next start. The directory must already exist.
bool SaveRules(const std::wstring& dataDir, const std::vector<Rule>& rules, std::string* error);

// "r_" + 16 lower-case hex digits from BCryptGenRandom; "" if the RNG failed.
std::string NewRuleId();

namespace testing {
// Called by SaveRules after the temporary file is written, flushed and closed, and before
// it replaces rules.json -- the one moment where "atomic" is observable. Returning false
// makes the save fail there, as a failed replace would. nullptr (the default) = no hook.
// Not thread-safe; tests only.
using BeforeReplaceHook = std::function<bool(const std::wstring& tmpPath)>;
void SetBeforeReplaceHookForTest(BeforeReplaceHook hook);
}  // namespace testing

}  // namespace pf
