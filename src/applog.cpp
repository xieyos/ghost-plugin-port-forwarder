#include "applog.h"

#include "json_util.h"

#include <cstdio>
#include <exception>
#include <iterator>

namespace pf {

namespace {

constexpr size_t kMaxQueuedEntries = 1000;
constexpr size_t kMaxFieldKeyBytes = 64;
constexpr DWORD kIngestReceiveTimeoutMs = 5000;
constexpr DWORD kFinalIngestReceiveTimeoutMs = 2000;

uint64_t UnixMsNow() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    // 100 ns ticks since 1601 -> ms since 1970.
    return (u.QuadPart - 116444736000000000ull) / 10000ull;
}

std::string FormatUtc(uint64_t unixMs) {
    ULARGE_INTEGER u;
    u.QuadPart = unixMs * 10000ull + 116444736000000000ull;
    FILETIME ft;
    ft.dwLowDateTime = u.LowPart;
    ft.dwHighDateTime = u.HighPart;
    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return "0000-00-00T00:00:00.000Z";
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear, st.wMonth, st.wDay, st.wHour,
                  st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

// One entry is one line in the local file: control characters become spaces.
std::string OneLine(const std::string& s) {
    std::string r = s;
    for (char& c : r) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (u < 0x20 || u == 0x7f) c = ' ';
    }
    return r;
}

bool AppendToFile(const std::wstring& path, const std::string& text) {
    HANDLE h = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD n = 0;
    const bool ok = WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &n, nullptr) && n == text.size();
    CloseHandle(h);
    return ok;
}

uint64_t FileSize(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA a;
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &a)) return 0;
    return (static_cast<uint64_t>(a.nFileSizeHigh) << 32) | a.nFileSizeLow;
}

}  // namespace

const char* LogLevelName(LogLevel l) {
    switch (l) {
        case LogLevel::Warn:
            return "warn";
        case LogLevel::Error:
            return "error";
        case LogLevel::Info:
        default:
            return "info";
    }
}

std::string TruncateUtf8(const std::string& s, size_t maxBytes) {
    if (s.size() <= maxBytes) return s;
    size_t cut = maxBytes;
    // Step back over continuation bytes (10xxxxxx) to the start of the cut sequence.
    while (cut > 0 && (static_cast<unsigned char>(s[cut]) & 0xC0) == 0x80) --cut;
    return s.substr(0, cut);
}

AppLog::AppLog(AppLogOptions opts)
    : api_(opts.api),
      localDir_(std::move(opts.localDir)),
      clock_(opts.clock ? opts.clock : DefaultClock()),
      minIntervalMs_(opts.minIntervalMs),
      batch_(opts.batch >= 1 ? opts.batch : 1),
      fileMaxBytes_(opts.fileMaxBytes),
      bucket_(opts.ratePerSec > 0 ? opts.ratePerSec : kLogRatePerSec, opts.burst >= 1 ? opts.burst : 1.0) {
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    remote_ = api_ != nullptr && opts.canWrite && !api_->Unavailable();
}

AppLog::~AppLog() {
    Stop();
    if (stopEvent_) CloseHandle(stopEvent_);
}

void AppLog::Start() {
    std::lock_guard<std::mutex> lock(mu_);
    if (started_ || stopping_) return;
    started_ = true;
    thread_ = std::thread([this] { Run(); });
}

void AppLog::Stop() {
    {
        std::lock_guard<std::mutex> lock(mu_);
        stopping_ = true;
    }
    if (stopEvent_) SetEvent(stopEvent_);
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void AppLog::Write(LogLevel level, const std::string& text, const LogFields& fields) {
    Entry e;
    e.level = level;
    e.text = TruncateUtf8(text, kLogMaxTextBytes);
    for (const auto& kv : fields) {
        if (e.fields.size() >= kLogMaxFields) break;
        if (kv.first.empty()) continue;
        e.fields.emplace_back(TruncateUtf8(kv.first, kMaxFieldKeyBytes), TruncateUtf8(kv.second, kLogMaxFieldValueBytes));
    }
    e.unixMs = UnixMsNow();
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stopping_ || queue_.size() >= kMaxQueuedEntries || !bucket_.TryTake(clock_->NowMs())) {
            ++dropped_;
            return;
        }
        queue_.push_back(std::move(e));
    }
    cv_.notify_one();
}

void AppLog::Run() {
    try {
        for (;;) {
            std::vector<Entry> batch;
            bool stopping = false;
            {
                std::unique_lock<std::mutex> lock(mu_);
                cv_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                stopping = stopping_;
                // Remote: one request's worth. Local: everything (a file append is cheap).
                const size_t n = remote_.load() ? batch_ : queue_.size();
                while (!queue_.empty() && batch.size() < n) {
                    batch.push_back(std::move(queue_.front()));
                    queue_.pop_front();
                }
            }
            const bool sentRemote = !batch.empty() && remote_.load();
            if (!batch.empty()) Deliver(batch, stopping);
            if (stopping) {
                std::lock_guard<std::mutex> lock(mu_);
                if (remote_.load()) {
                    dropped_ += queue_.size();
                } else {
                    std::vector<Entry> rest(std::make_move_iterator(queue_.begin()),
                                            std::make_move_iterator(queue_.end()));
                    WriteLocal(rest);
                }
                queue_.clear();
                return;
            }
            // At most one request per second. Stop cuts the wait short; the final flush
            // above may then come sooner than a second after the previous request.
            if (sentRemote) clock_->Wait(minIntervalMs_, stopEvent_);
        }
    } catch (...) {
        // Never let an exception out of the thread; the log just goes quiet.
    }
}

void AppLog::Deliver(std::vector<Entry>& batch, bool finalFlush) {
    if (remote_.load() && api_ && !api_->Unavailable()) {
        json entries = json::array();
        for (const Entry& e : batch) {
            json fields = json::object();
            for (const auto& kv : e.fields) fields[kv.first] = kv.second;
            entries.push_back(json{{"level", LogLevelName(e.level)}, {"text", e.text}, {"fields", fields}});
        }
        const json body = json{{"entries", entries}};
        const ApiResult r =
            api_->Post("/api/log-ingest", body, finalFlush ? kFinalIngestReceiveTimeoutMs : kIngestReceiveTimeoutMs);
        if (r.ok()) {
            sent_ += batch.size();
            return;
        }
        if (r.code != api_err::kGhostUnavailable) {
            dropped_ += batch.size();
            return;
        }
        // The token is gone for good: from now on, and for this batch, the local file.
        remote_ = false;
    } else if (remote_.load()) {
        remote_ = false;
    }
    WriteLocal(batch);
}

void AppLog::WriteLocal(const std::vector<Entry>& batch) {
    if (batch.empty()) return;
    if (localDir_.empty()) {
        dropped_ += batch.size();
        return;
    }
    std::string text;
    for (const Entry& e : batch) {
        text += FormatUtc(e.unixMs);
        text += ' ';
        text += LogLevelName(e.level);
        text += ' ';
        text += OneLine(e.text);
        for (const auto& kv : e.fields) {
            text += ' ';
            text += OneLine(kv.first);
            text += '=';
            text += OneLine(kv.second);
        }
        text += '\n';
    }
    const std::wstring path = localDir_ + L"\\" + kLogFileName;
    if (FileSize(path) + text.size() > fileMaxBytes_) {
        const std::wstring old = path + L".1";
        if (!MoveFileExW(path.c_str(), old.c_str(), MOVEFILE_REPLACE_EXISTING)) {
            // Replacing .1 fails while another program holds it without FILE_SHARE_DELETE
            // (an editor, a log viewer). Losing this file's history beats growing past the
            // limit for as long as that program keeps it open.
            HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                                   TRUNCATE_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        }
        // Still no room (the file could not be emptied either, or this batch alone is over
        // the limit): the batch is dropped.
        if (FileSize(path) + text.size() > fileMaxBytes_) {
            dropped_ += batch.size();
            return;
        }
    }
    if (AppendToFile(path, text)) {
        local_ += batch.size();
    } else {
        dropped_ += batch.size();
    }
}

}  // namespace pf
