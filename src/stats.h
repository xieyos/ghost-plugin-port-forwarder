// Per-rule counters, read by the management page.
//
// Every counter is an atomic written by the rule's own threads (accept thread, one pump
// thread per connection; for a UDP rule its one poll thread writes them all) and read by
// Snapshot() from any thread. lastError is the one compound value and has its own lock.
//
// lastError.count is how many times IN A ROW the same code was recorded: a node that keeps
// refusing shows "upstream_unreachable x 37", and a different code starts again at 1. It is
// about the rule, never about a client: no address and no destination is kept here.
#pragma once

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

namespace pf {

// Milliseconds since 1970-01-01 UTC (for "when" shown to the user, not for timing).
inline uint64_t UnixMsNow() {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER u;
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (u.QuadPart - 116444736000000000ull) / 10000ull;
}

struct LastError {
    std::string code;     // "" = none yet
    uint64_t atUnixMs = 0;  // the latest occurrence
    uint64_t count = 0;     // consecutive occurrences of `code`
};

struct StatsSnapshot {
    uint64_t activeConnections = 0;
    uint64_t totalConnections = 0;     // TCP: accepted and handed to a pump thread; UDP: sessions created
    uint64_t rejectedConnections = 0;  // closed at once: a connection limit was reached
    uint64_t bytesUp = 0;              // client -> remote, bytes the remote side accepted
    uint64_t bytesDown = 0;            // remote -> client, bytes the client side accepted
    uint64_t udpSessions = 0;          // UDP sessions open now (including those being opened)
    uint64_t droppedDatagrams = 0;     // UDP datagrams not forwarded, for any reason
    LastError lastError;
};

class RuleStats {
public:
    std::atomic<uint64_t> activeConnections{0};
    std::atomic<uint64_t> totalConnections{0};
    std::atomic<uint64_t> rejectedConnections{0};
    std::atomic<uint64_t> bytesUp{0};
    std::atomic<uint64_t> bytesDown{0};
    std::atomic<uint64_t> udpSessions{0};
    std::atomic<uint64_t> droppedDatagrams{0};

    // Records one occurrence of `code`. Returns true when this is the first of a run (the
    // previous error was a different code or there was none) -- the moment worth a log line;
    // repeats only bump the count.
    bool RecordError(const std::string& code) {
        std::lock_guard<std::mutex> lock(mu_);
        const bool first = last_.code != code;
        if (first) {
            last_.code = code;
            last_.count = 0;
        }
        ++last_.count;
        last_.atUnixMs = UnixMsNow();
        return first;
    }

    StatsSnapshot Snapshot() const {
        StatsSnapshot s;
        s.activeConnections = activeConnections.load();
        s.totalConnections = totalConnections.load();
        s.rejectedConnections = rejectedConnections.load();
        s.bytesUp = bytesUp.load();
        s.bytesDown = bytesDown.load();
        s.udpSessions = udpSessions.load();
        s.droppedDatagrams = droppedDatagrams.load();
        std::lock_guard<std::mutex> lock(mu_);
        s.lastError = last_;
        return s;
    }

private:
    mutable std::mutex mu_;
    LastError last_;
};

}  // namespace pf
