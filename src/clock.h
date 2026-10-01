// A clock that tests can replace. Everything that waits on time -- the API client's
// token bucket, the 429 backoff, the plugin_not_running retries, the log batcher's
// request spacing -- asks a Clock instead of calling GetTickCount64/Sleep, so a test can
// drive minutes of policy in microseconds and read back exactly how long it was asked to
// wait.
#pragma once

#include <windows.h>

#include <cstdint>

namespace pf {

class Clock {
public:
    virtual ~Clock() = default;
    // Milliseconds on a monotonic scale. Only differences mean anything.
    virtual uint64_t NowMs() = 0;
    // Waits `ms`, or until `cancel` (may be null) is signalled. True when the whole time
    // passed, false when the wait was cancelled.
    virtual bool Wait(uint32_t ms, HANDLE cancel) = 0;
};

// GetTickCount64 and WaitForSingleObject.
class SystemClock final : public Clock {
public:
    uint64_t NowMs() override { return GetTickCount64(); }
    bool Wait(uint32_t ms, HANDLE cancel) override {
        if (!cancel) {
            Sleep(ms);
            return true;
        }
        return WaitForSingleObject(cancel, ms) == WAIT_TIMEOUT;
    }
};

// The process-wide system clock (stateless; one instance is enough).
inline Clock* DefaultClock() {
    static SystemClock clock;
    return &clock;
}

}  // namespace pf
