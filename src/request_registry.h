// The live-request registry of GhostApi: which request handles are in flight, and who may
// close each one. Pure bookkeeping -- it never calls WinHTTP -- so it can be tested with
// made-up handle values.
//
// Every handle is closed exactly once: by its owner if the owner removes it (Release returns
// true), or by whoever took it with TakeTag/TakeAll (Shutdown/Abort), which remove it first
// and then close it.
//
// An entry is {handle, tag, generation}. The owner keeps the generation Register gave it and
// passes it to Owned/Release. The handle value alone is not enough: once Abort closed a
// handle, WinHTTP may hand the same value to the next request, which registers it again --
// the first owner, comparing values only, would think the new request was still its own,
// call WinHTTP on it, and finally Release (and close) someone else's request.
//
// What the generation does NOT close: Owned() and the WinHTTP call after it are two steps.
// If Shutdown/Abort takes and closes the handle between them, and WinHTTP hands the same
// value to a new request in that same instant, the owner's one call (send, receive, query,
// read) acts on that new request. Release still refuses -- the owner never closes a handle
// it does not own -- so the worst case is one stray call on a stranger's request, and it
// needs an abort racing a reuse within a few instructions, which happens only while the
// plugin is stopping or a rule's tunnel requests are being aborted. Closing it fully means
// asynchronous WinHTTP (an abort then cancels the owner's own operation instead of closing
// the handle under it); that is out of scope for v1.
#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

namespace pf {

class RequestRegistry {
public:
    // 0 when refused (closed, or `tag` was aborted); otherwise the entry's generation.
    uint64_t Register(void* handle, uintptr_t tag) {
        std::lock_guard<std::mutex> lock(mu_);
        if (closed_) return 0;
        if (tag != 0) {
            for (uintptr_t t : abortedTags_) {
                if (t == tag) return 0;
            }
        }
        const uint64_t gen = ++nextGen_;
        live_.push_back(Entry{handle, tag, gen});
        return gen;
    }

    // Whether this owner's entry is still there (nobody took it).
    bool Owned(void* handle, uint64_t gen) const {
        std::lock_guard<std::mutex> lock(mu_);
        for (const Entry& e : live_) {
            if (e.handle == handle && e.gen == gen) return true;
        }
        return false;
    }

    // Removes this owner's entry. True: the owner closes the handle. False: someone took it
    // and closes it.
    bool Release(void* handle, uint64_t gen) {
        std::lock_guard<std::mutex> lock(mu_);
        for (auto it = live_.begin(); it != live_.end(); ++it) {
            if (it->handle == handle && it->gen == gen) {
                live_.erase(it);
                return true;
            }
        }
        return false;
    }

    // Refuses `tag` from now on and removes its entries; the caller closes what it gets.
    std::vector<void*> TakeTag(uintptr_t tag) {
        std::vector<void*> out;
        if (tag == 0) return out;
        std::lock_guard<std::mutex> lock(mu_);
        abortedTags_.push_back(tag);
        for (auto it = live_.begin(); it != live_.end();) {
            if (it->tag == tag) {
                out.push_back(it->handle);
                it = live_.erase(it);
            } else {
                ++it;
            }
        }
        return out;
    }

    // Refuses everything from now on and removes every entry; the caller closes them.
    std::vector<void*> TakeAll() {
        std::lock_guard<std::mutex> lock(mu_);
        closed_ = true;
        std::vector<void*> out;
        for (const Entry& e : live_) out.push_back(e.handle);
        live_.clear();
        return out;
    }

    bool Refused(uintptr_t tag) const {
        std::lock_guard<std::mutex> lock(mu_);
        if (closed_) return true;
        if (tag == 0) return false;
        for (uintptr_t t : abortedTags_) {
            if (t == tag) return true;
        }
        return false;
    }

private:
    struct Entry {
        void* handle;
        uintptr_t tag;
        uint64_t gen;
    };
    mutable std::mutex mu_;
    std::vector<Entry> live_;
    std::vector<uintptr_t> abortedTags_;
    uint64_t nextGen_ = 0;
    bool closed_ = false;
};

}  // namespace pf
