// A move-only owner of one SOCKET: closed exactly once, by whoever holds it last.
#pragma once

#include <winsock2.h>

#include <utility>

namespace pf {

class UniqueSocket {
public:
    UniqueSocket() = default;
    explicit UniqueSocket(SOCKET s) : s_(s) {}
    ~UniqueSocket() { Reset(); }
    UniqueSocket(const UniqueSocket&) = delete;
    UniqueSocket& operator=(const UniqueSocket&) = delete;
    UniqueSocket(UniqueSocket&& o) noexcept : s_(o.Release()) {}
    UniqueSocket& operator=(UniqueSocket&& o) noexcept {
        if (this != &o) Reset(o.Release());
        return *this;
    }

    SOCKET get() const { return s_; }
    bool valid() const { return s_ != INVALID_SOCKET; }
    explicit operator bool() const { return valid(); }

    SOCKET Release() { return std::exchange(s_, INVALID_SOCKET); }
    void Reset(SOCKET s = INVALID_SOCKET) {
        if (s_ != INVALID_SOCKET) closesocket(s_);
        s_ = s;
    }

private:
    SOCKET s_ = INVALID_SOCKET;
};

}  // namespace pf
