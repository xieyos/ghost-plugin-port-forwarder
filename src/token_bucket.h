// Rate policy as pure functions of time: a token bucket and the 429 backoff. No clock is
// read here -- the caller passes "now" -- so the tests drive them with plain numbers.
#pragma once

#include <algorithm>
#include <cstdint>

namespace pf {

// A token bucket: `ratePerSec` tokens flow in continuously up to `burst`. It starts full.
//
// Two ways to spend:
//   TryTake  -- take one token if there is one, else refuse (log entries: drop and count).
//   Reserve  -- always take one, letting the balance go negative, and answer how long the
//               caller must wait before acting on it (API calls: wait, never drop). Waiters
//               queue up in reservation order instead of all waking at once.
class TokenBucket {
public:
    TokenBucket(double ratePerSec, double burst) : rate_(ratePerSec), burst_(burst), tokens_(burst) {}

    bool TryTake(uint64_t nowMs) {
        Refill(nowMs);
        if (tokens_ < 1.0) return false;
        tokens_ -= 1.0;
        return true;
    }

    // Milliseconds to wait before the reserved token is really there (0 = now).
    uint64_t Reserve(uint64_t nowMs) {
        Refill(nowMs);
        tokens_ -= 1.0;
        if (tokens_ >= 0.0) return 0;
        const double waitMs = (-tokens_) * 1000.0 / rate_;
        return static_cast<uint64_t>(waitMs) + ((waitMs > static_cast<double>(static_cast<uint64_t>(waitMs))) ? 1 : 0);
    }

    double Tokens(uint64_t nowMs) {
        Refill(nowMs);
        return tokens_;
    }

private:
    void Refill(uint64_t nowMs) {
        if (!started_) {
            started_ = true;
            last_ = nowMs;
            return;
        }
        if (nowMs <= last_) return;
        tokens_ = std::min(burst_, tokens_ + static_cast<double>(nowMs - last_) * rate_ / 1000.0);
        last_ = nowMs;
    }

    double rate_;
    double burst_;
    double tokens_;
    uint64_t last_ = 0;
    bool started_ = false;
};

// The wait before retry number `attempt` (0 = the first retry) after a 429: exponential
// from 250 ms, doubling, plus up to 25 % jitter (`random01` in [0, 1]), never above 8 s.
// Ghost refills the budget continuously and sends no Retry-After, so a short exponential
// wait is enough; the jitter keeps several waiting threads from retrying in lock step.
constexpr uint32_t kBackoffStartMs = 250;
constexpr uint32_t kBackoffCapMs = 8000;

inline uint32_t BackoffMs(int attempt, double random01) {
    if (attempt < 0) attempt = 0;
    uint64_t base = kBackoffStartMs;
    for (int i = 0; i < attempt && base < kBackoffCapMs; ++i) base *= 2;
    base = std::min<uint64_t>(base, kBackoffCapMs);
    if (!(random01 >= 0.0)) random01 = 0.0;  // also catches NaN
    if (random01 > 1.0) random01 = 1.0;
    const uint64_t jitter = static_cast<uint64_t>(static_cast<double>(base) * 0.25 * random01);
    return static_cast<uint32_t>(std::min<uint64_t>(base + jitter, kBackoffCapMs));
}

}  // namespace pf
