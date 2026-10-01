// A pf::Clock whose waits never end on their own: Wait(ms, cancel) counts itself in and
// blocks until `cancel` is signalled (GhostApi::Shutdown, TunnelClient::Shutdown), then
// answers "cancelled". NowMs is the real tick count.
//
// It turns "a thread is in a 429 backoff" from a window of a few hundred milliseconds into
// a state that lasts exactly until the test ends it: InWait() says how many threads are in
// it right now, so a test can wait for that instead of guessing from request counts (the
// fake Ghost records a request before it answers, so a recorded request does not mean the
// client is already backing off).
//
// A wait without a cancel event cannot be ended by anyone; it returns at once instead.
// Give the GhostApi a token bucket that never waits (a huge rate and burst), or bucket waits
// land in the gate too.
#pragma once

#include "clock.h"

#include <windows.h>

#include <atomic>
#include <cstdint>

namespace pf_test {

class GateClock final : public pf::Clock {
public:
    uint64_t NowMs() override { return GetTickCount64(); }
    bool Wait(uint32_t, HANDLE cancel) override {
        if (!cancel) return true;
        ++entered_;
        ++inWait_;
        WaitForSingleObject(cancel, INFINITE);
        --inWait_;
        return false;
    }

    int InWait() const { return inWait_.load(); }
    int Entered() const { return entered_.load(); }

private:
    std::atomic<int> inWait_{0};
    std::atomic<int> entered_{0};
};

}  // namespace pf_test
