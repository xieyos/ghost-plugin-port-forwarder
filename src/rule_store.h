// rules.json in the plugin's data directory.
//
// Loading never "repairs": a file that cannot be parsed, fails validation or is larger
// than 256 KB is renamed aside to rules.json.corrupt-<unix seconds> -- kept, so nothing
// the user typed is destroyed -- and the plugin starts with no rules and tells the page
// (LoadResult::corrupt).
//
// Nothing is ever overwritten silently. A file the store could not read (Unreadable), or
// a corrupt one it could not move aside, stays where it is, and the store refuses every
// save (store_locked) until a later Load succeeds -- the page shows the problem instead
// of the user's rules being replaced by an empty list. A save before any Load is refused
// the same way: the store does not know what it would overwrite.
//
// Saving is atomic: a temporary file with a random name in the same directory, written,
// flushed, then renamed over rules.json through its own handle with POSIX semantics
// (FileRenameInfoEx, REPLACE_IF_EXISTS | POSIX_SEMANTICS), so a reader that opened
// rules.json with FILE_SHARE_DELETE -- an antivirus scanner, the search indexer -- does
// not block the replace. Where that call is unsupported (older Windows, FAT, some network
// file systems) it falls back to MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH). Both are
// retried briefly on a sharing violation. If any step fails, rules.json is exactly what it
// was before and the temporary is removed.
//
// Paths: dataDir is the host's per-plugin data directory or the standalone
// %LOCALAPPDATA%\<id>\ -- short, well under MAX_PATH -- and the store adds at most
// "\rules.json.corrupt-<20 digits>-<2 digits>". No \\?\ long-path handling is done; a
// path that does not fit fails as io_error (Unreadable on load, and the store locks).
#pragma once

#include "rules.h"

#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace pf {

constexpr size_t kMaxRulesFileBytes = 256 * 1024;

// ---- Reason codes (alongside rule_err; the page localizes them) ---------------------------
namespace store_err {
constexpr const char* kBadDataDir = "bad_data_dir";  // the data directory is empty
constexpr const char* kIoError = "io_error";         // a file system call failed (detail says which)
constexpr const char* kRngFailed = "rng_failed";     // BCryptGenRandom failed
constexpr const char* kTooLarge = "too_large";       // rules.json is over 256 KB
constexpr const char* kBadJson = "bad_json";         // rules.json is not JSON
constexpr const char* kStoreLocked = "store_locked"; // a save while overwriting is not allowed
}  // namespace store_err

enum class LoadStatus {
    Ok,          // read and valid (possibly an empty rule list)
    Missing,     // no rules.json yet: a first start
    Corrupt,     // invalid: renamed aside (corruptPath), or left in place if that failed
    Unreadable,  // exists but could not be opened or read; left alone
};

struct LoadResult {
    LoadStatus status = LoadStatus::Missing;
    std::vector<Rule> rules;  // empty unless Ok
    // True exactly when status == Corrupt; the flag the page shows.
    bool corrupt = false;
    // Where the bad file went; empty if it could not be renamed.
    std::wstring corruptPath;
    // Whether the next Save may replace rules.json: true for Ok, Missing and a Corrupt
    // file that was moved aside; false for Unreadable and for a Corrupt file still in place.
    bool mayOverwrite = false;
    // Corrupt: too_large, bad_json or a rule_err code. Unreadable: io_error or bad_data_dir.
    std::string code;
    // For logs only, never shown as the reason: the failing step and Win32 error.
    std::string detail;
    // How many stale rules.json.tmp-<16 hex> files (from a save interrupted by a crash or
    // power loss) this load removed.
    int staleTempsRemoved = 0;
};

// <dataDir>\rules.json
std::wstring RulesFilePath(const std::wstring& dataDir);

// One per data directory. Load and Save are serialized by an internal mutex, so the UI
// server's request threads may call them concurrently.
class RuleStore {
public:
    explicit RuleStore(std::wstring dataDir);
    RuleStore(const RuleStore&) = delete;
    RuleStore& operator=(const RuleStore&) = delete;

    // `nowUnixSec` names the corrupt copy; when that name is taken, -1, -2, ... are tried.
    // Also removes stale temporaries of the exact shape rules.json.tmp-<16 lower hex>.
    LoadResult Load(long long nowUnixSec);
    LoadResult Load();  // the current time

    // Refuses, with nothing written:
    //   bad_data_dir, store_locked (see the top of this file),
    //   any code LoadRules would reject the set with -- every rule ValidateStoredRule, then
    //   ValidateSet -- so the plugin never writes a file it would rename aside next start;
    //   rng_failed, io_error (`detail` names the step and the Win32 error).
    // The directory must already exist.
    bool Save(const std::vector<Rule>& rules, std::string* code, std::string* detail = nullptr);

    bool MayOverwrite() const;
    const std::wstring& FilePath() const { return path_; }

private:
    mutable std::mutex mu_;
    std::wstring dataDir_;
    std::wstring path_;
    bool mayOverwrite_ = false;
};

// "r_" + 16 lower-case hex digits from BCryptGenRandom; "" if the RNG failed.
std::string NewRuleId();

namespace testing {
// Called by Save after the temporary file is written and flushed (its handle still open,
// sharing reads), before it replaces rules.json -- the one moment where "atomic" is
// observable. Returning false makes the save fail there, as a failed replace would.
// nullptr (the default) = no hook. Not thread-safe; tests only.
using BeforeReplaceHook = std::function<bool(const std::wstring& tmpPath)>;
void SetBeforeReplaceHookForTest(BeforeReplaceHook hook);
// Called with the attempt number (0-based) each time a sharing violation is about to be
// retried: opening rules.json for reading (Read) or replacing it (Replace). Tests only.
enum class RetryPoint { Read, Replace };
using RetryHook = std::function<void(RetryPoint where, int attempt)>;
void SetRetryHookForTest(RetryHook hook);
// Skips the POSIX rename as if the file system did not support it, so the MoveFileExW
// fallback runs. Tests only.
void SetForceClassicReplaceForTest(bool force);
}  // namespace testing

}  // namespace pf
