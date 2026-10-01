// Client-side TCP helpers for the tests that talk to a forwarder over real loopback
// sockets: connect with a bounded receive, exact sends and receives, and the questions "did
// the other side close this connection" and "is anything listening on this port".
#pragma once

#include "test_support.h"
#include "unique_socket.h"

#include <mstcpip.h>

#include <string>

namespace pf_test {

// Connects to 127.0.0.1:port; a 5 s receive timeout so a test never hangs on a recv.
// WSA_FLAG_OVERLAPPED although nothing here is overlapped: on a socket created without it,
// blocking calls on one handle are serialised, so a send on one thread waits behind a recv
// on another -- and the half-close case does exactly that.
inline pf::UniqueSocket Connect(int port) {
    pf::UniqueSocket s(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return s;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    if (connect(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) return pf::UniqueSocket();
    DWORD tmo = 5000;
    setsockopt(s.get(), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tmo), sizeof(tmo));
    return s;
}

inline bool SendAll(SOCKET s, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        const int n = send(s, data.data() + off, static_cast<int>(data.size() - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

inline bool RecvExactly(SOCKET s, size_t n, std::string* out) {
    out->clear();
    char buf[8192];
    while (out->size() < n) {
        const int want = static_cast<int>(n - out->size() < sizeof(buf) ? n - out->size() : sizeof(buf));
        const int k = recv(s, buf, want, 0);
        if (k <= 0) return false;
        out->append(buf, static_cast<size_t>(k));
    }
    return true;
}

inline bool RoundTrip(SOCKET s, const std::string& msg) {
    std::string got;
    return SendAll(s, msg) && RecvExactly(s, msg.size(), &got) && got == msg;
}

// Reads until the peer ends the stream. True only for a clean EOF (recv == 0) -- not a
// reset and not the receive timeout.
inline bool RecvUntilEof(SOCKET s, std::string* out) {
    out->clear();
    char buf[16384];
    for (;;) {
        const int k = recv(s, buf, sizeof(buf), 0);
        if (k == 0) return true;
        if (k < 0) return false;
        out->append(buf, static_cast<size_t>(k));
    }
}

// The connection was closed by the other side: EOF or a reset, NOT the receive timeout.
inline bool ClosedByPeer(SOCKET s) {
    char buf[64];
    for (;;) {
        const int k = recv(s, buf, sizeof(buf), 0);
        if (k == 0) return true;
        if (k > 0) continue;
        const int e = WSAGetLastError();
        return e == WSAECONNRESET || e == WSAECONNABORTED;
    }
}

// Nothing listens on 127.0.0.1:port. Windows retries a refused connect for about 2 s;
// TCP_MAXRTMS cuts that short (the answer is a RST either way, never a timeout on loopback).
inline bool Refused(int port) {
    pf::UniqueSocket s(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return false;
    DWORD maxRtMs = 300;
    setsockopt(s.get(), IPPROTO_TCP, TCP_MAXRTMS, reinterpret_cast<const char*>(&maxRtMs), sizeof(maxRtMs));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    return connect(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0;
}

// Nothing holds 127.0.0.1:port for TCP (an exclusive bind succeeds). Unlike Refused(), it
// never connects, so it cannot start a connection on a listener that is still there.
inline bool CanBindTcp(int port) {
    pf::UniqueSocket t(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    if (!t) return false;
    BOOL one = TRUE;
    setsockopt(t.get(), SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&one), sizeof(one));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    return bind(t.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0;
}

}  // namespace pf_test
