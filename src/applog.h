// The plugin's log: Ghost's application log through log.write when granted
// (spec-plugin-api.md section 5), otherwise a local file.
//
//   remote  POST /api/log-ingest {"entries":[{"level","text","fields"}]} -- the key is
//           "entries", there is no "v". At most 10 entries per request and at most one
//           request per second, sent from one background thread. Ghost forces src, tag
//           and plane; we only choose level, text and fields.
//   local   <dir>\port-forwarder.log, rolled at 1 MB to port-forwarder.log.1 (two files
//           at most). Used when log.write is not granted, in standalone mode, and from the
//           moment Ghost answers 401 (the token is gone; nothing will be accepted again).
//           If the roll fails (another program holds port-forwarder.log.1 without
//           FILE_SHARE_DELETE), the current file is emptied instead; if even that fails the
//           batch is dropped. The file never grows past the limit.
//
// Entries are admitted through a local bucket of 2/s, burst 20 -- well under Ghost's
// per-plugin entry budget of 5/s, burst 50, which the plugin shares with nothing else but
// which lands in Ghost's 1000-entry Control ring together with Ghost's own events. An entry
// that does not fit is dropped and counted (Dropped()), never queued for later.
//
// What callers must never log: client IP addresses and per-connection destinations. The
// log is about the plugin (started, a rule bound or failed to bind, a node failed), not
// about who used a forwarded port for what. Nothing here can enforce that; the callers do.
//
// Limits applied before sending, so Ghost never has to truncate: text 2 KB, at most 16
// fields, each value 512 bytes (spec-limits.md 7), cut on a UTF-8 boundary.
#pragma once

#include "clock.h"
#include "ghost_api.h"
#include "token_bucket.h"

#include <windows.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace pf {

enum class LogLevel { Info, Warn, Error };
const char* LogLevelName(LogLevel l);  // "info" / "warn" / "error"

constexpr const char* kPermLogWrite = "log.write";
constexpr size_t kLogMaxTextBytes = 2048;
constexpr size_t kLogMaxFields = 16;
constexpr size_t kLogMaxFieldValueBytes = 512;
constexpr size_t kLogBatch = 10;
constexpr uint32_t kLogMinIntervalMs = 1000;
constexpr double kLogRatePerSec = 2.0;
constexpr double kLogBurst = 20.0;
constexpr uint64_t kLogFileMaxBytes = 1024 * 1024;
constexpr const wchar_t* kLogFileName = L"port-forwarder.log";

using LogFields = std::vector<std::pair<std::string, std::string>>;

// Cuts `s` to at most `maxBytes` without splitting a UTF-8 sequence.
std::string TruncateUtf8(const std::string& s, size_t maxBytes);

struct AppLogOptions {
    // Null = standalone. Not owned: the GhostApi must outlive the AppLog -- and, since a
    // forwarder's straggler thread may log through a LogFn that holds the AppLog by
    // shared_ptr (forward_common.h), outlive every such thread too. Keep a shared_ptr to the
    // GhostApi next to the AppLog (or inside the LogFn), never only a raw pointer.
    GhostApi* api = nullptr;
    bool canWrite = false;      // log.write granted
    std::wstring localDir;      // where port-forwarder.log goes; "" = no local file
    Clock* clock = nullptr;     // null = DefaultClock()
    uint32_t minIntervalMs = kLogMinIntervalMs;
    double ratePerSec = kLogRatePerSec;
    double burst = kLogBurst;
    size_t batch = kLogBatch;
    uint64_t fileMaxBytes = kLogFileMaxBytes;
};

class AppLog {
public:
    explicit AppLog(AppLogOptions opts);
    ~AppLog();  // Stop()
    AppLog(const AppLog&) = delete;
    AppLog& operator=(const AppLog&) = delete;

    void Start();
    // Sends what is queued -- at most one more request -- then ends the thread. Entries
    // still queued after that are counted as dropped.
    //
    // Order at exit: AppLog::Stop() BEFORE GhostApi::Shutdown(). Shutdown cancels every
    // wait and aborts every request on the wire, the last batch included.
    void Stop();

    void Write(LogLevel level, const std::string& text, const LogFields& fields = {});

    uint64_t Dropped() const { return dropped_.load(); }
    uint64_t SentEntries() const { return sent_.load(); }
    uint64_t LocalEntries() const { return local_.load(); }
    bool Remote() const { return remote_.load(); }

private:
    struct Entry {
        LogLevel level;
        std::string text;
        LogFields fields;
        uint64_t unixMs;
    };

    void Run();
    void Deliver(std::vector<Entry>& batch, bool finalFlush);
    void WriteLocal(const std::vector<Entry>& batch);

    GhostApi* api_;
    std::wstring localDir_;
    Clock* clock_;
    uint32_t minIntervalMs_;
    size_t batch_;
    uint64_t fileMaxBytes_;
    HANDLE stopEvent_ = nullptr;

    std::atomic<bool> remote_{false};
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> sent_{0};
    std::atomic<uint64_t> local_{0};

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Entry> queue_;
    TokenBucket bucket_;
    bool stopping_ = false;
    bool started_ = false;
    std::thread thread_;
};

}  // namespace pf
