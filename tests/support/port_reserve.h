// Ports for the rules of a test, held until the moment they are needed.
//
// "Bind port 0, read the port, close, use it later" leaves a window in which anything else
// on the machine can take the port -- and a TCP pick says nothing about whether UDP is free
// on the same number. ReservePort() holds 127.0.0.1:<port> for BOTH protocols (a listening
// TCP socket and a bound UDP socket) and never hands out the same port twice in a process;
// ReleasePorts(rules) lets go of the listen ports of `rules` just before they are applied.
#pragma once

#include "rules.h"
#include "test_support.h"

#include <map>
#include <mutex>
#include <set>
#include <vector>

namespace pf_test {

namespace detail {

struct Held {
    SOCKET tcp = INVALID_SOCKET;
    SOCKET udp = INVALID_SOCKET;
};

inline std::mutex& ReserveMu() {
    static std::mutex mu;
    return mu;
}
inline std::map<int, Held>& HeldPorts() {
    static std::map<int, Held> held;
    return held;
}
inline std::set<int>& HandedPorts() {
    static std::set<int> handed;
    return handed;
}

}  // namespace detail

// 0 when no port could be reserved.
inline int ReservePort() {
    std::lock_guard<std::mutex> lock(detail::ReserveMu());
    for (int attempt = 0; attempt < 100; ++attempt) {
        LoopbackListener l;
        if (!ListenLoopback(&l)) return 0;
        const int port = l.port;
        if (detail::HandedPorts().count(port) != 0) continue;
        SOCKET u = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        if (u == INVALID_SOCKET) return 0;
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(static_cast<u_short>(port));
        if (bind(u, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            closesocket(u);
            continue;  // UDP is taken on this number: pick another
        }
        detail::Held h;
        h.tcp = l.sock;
        h.udp = u;
        l.sock = INVALID_SOCKET;  // kept, not closed
        detail::HeldPorts()[port] = h;
        detail::HandedPorts().insert(port);
        return port;
    }
    return 0;
}

inline void ReleasePort(int port) {
    std::lock_guard<std::mutex> lock(detail::ReserveMu());
    auto it = detail::HeldPorts().find(port);
    if (it == detail::HeldPorts().end()) return;
    closesocket(it->second.tcp);
    closesocket(it->second.udp);
    detail::HeldPorts().erase(it);
}

inline void ReleasePorts(const std::vector<pf::Rule>& rules) {
    for (const pf::Rule& r : rules) ReleasePort(r.listenPort);
}

}  // namespace pf_test
