// A pf::Clock that only moves when waited on: Wait(ms) records the request and advances
// time by ms at once (unless the cancel event is already signalled). Thread-safe.
#pragma once

#include "clock.h"

#include <cstdint>
#include <mutex>
#include <vector>

namespace pf_test {

class FakeClock final : public pf::Clock {
public:
    explicit FakeClock(uint64_t start = 1000000) : now_(start) {}

    uint64_t NowMs() override {
        std::lock_guard<std::mutex> lock(mu_);
        return now_;
    }
    bool Wait(uint32_t ms, HANDLE cancel) override {
        if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) return false;
        std::lock_guard<std::mutex> lock(mu_);
        waits_.push_back(ms);
        now_ += ms;
        return true;
    }

    void Advance(uint64_t ms) {
        std::lock_guard<std::mutex> lock(mu_);
        now_ += ms;
    }
    std::vector<uint32_t> Waits() const {
        std::lock_guard<std::mutex> lock(mu_);
        return waits_;
    }
    void ClearWaits() {
        std::lock_guard<std::mutex> lock(mu_);
        waits_.clear();
    }

private:
    mutable std::mutex mu_;
    uint64_t now_;
    std::vector<uint32_t> waits_;
};

}  // namespace pf_test
