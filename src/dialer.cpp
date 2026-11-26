#include "dialer.h"

#include "forward_common.h"
#include "resolve.h"

#include <ws2tcpip.h>

#include <cstdint>
#include <utility>
#include <vector>

namespace pf {

namespace {

bool SetNonBlocking(SOCKET s) {
    u_long one = 1;
    return ioctlsocket(s, FIONBIO, &one) == 0;
}

bool Stopped(const DialCancel& c) { return c.stop && c.stop->load(); }

}  // namespace

// The name is resolved first. Then one attempt per address, in the resolver's order
// (families interleaved): the next one starts kStaggerDelayMs after the previous, or at
// once when the previous failed, and earlier attempts keep running -- the first to connect
// wins and the others are closed. Without the stagger a dead first address costs the whole
// budget: "localhost" is ::1 first on most machines, and Windows retries a refused loopback
// connect for about 2 s.
std::string ConnectDirect(const std::string& host, int port, const DialCancel& cancel, UniqueSocket* out) {
    std::vector<ResolvedAddr> addrs;
    const std::string rc = ResolveHost(host, port, SOCK_STREAM, cancel.stopEvent, &addrs);
    if (!rc.empty()) return rc;
    InterleaveFamilies(&addrs);

    std::vector<UniqueSocket> pending;
    size_t next = 0;
    const uint64_t deadline = GetTickCount64() + kDirectConnectTimeoutMs;
    uint64_t nextStartAt = 0;  // the first attempt starts at once
    while (!Stopped(cancel)) {
        const uint64_t now = GetTickCount64();
        if (now >= deadline) break;
        if (next < addrs.size() && now >= nextStartAt && pending.size() < FD_SETSIZE) {
            const ResolvedAddr& a = addrs[next++];
            UniqueSocket c(WSASocketW(a.family, SOCK_STREAM, IPPROTO_TCP, nullptr, 0,
                                      WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
            if (c && SetNonBlocking(c.get())) {
                if (connect(c.get(), reinterpret_cast<const sockaddr*>(&a.addr), a.len) == 0) {
                    *out = std::move(c);
                    return std::string();
                }
                if (WSAGetLastError() == WSAEWOULDBLOCK) {
                    pending.push_back(std::move(c));
                    nextStartAt = now + kStaggerDelayMs;
                    continue;
                }
            }
            nextStartAt = now;  // this address failed at once: the next one now
            continue;
        }
        if (pending.empty()) {
            if (next >= addrs.size()) break;  // every address failed
            continue;
        }
        uint64_t until = deadline;
        if (next < addrs.size() && nextStartAt < until) until = nextStartAt;
        uint64_t waitMs = until > now ? until - now : 0;
        if (waitMs > kPollSliceMs) waitMs = kPollSliceMs;
        fd_set w;
        fd_set e;
        FD_ZERO(&w);
        FD_ZERO(&e);
        for (const UniqueSocket& p : pending) {
            FD_SET(p.get(), &w);
            FD_SET(p.get(), &e);
        }
        timeval tv = {0, static_cast<long>(waitMs) * 1000};
        const int n = select(0, nullptr, &w, &e, &tv);
        if (n == SOCKET_ERROR) break;
        for (size_t i = 0; n > 0 && i < pending.size();) {
            const SOCKET ps = pending[i].get();
            const bool writable = FD_ISSET(ps, &w) != 0;
            if (!writable && !FD_ISSET(ps, &e)) {
                ++i;
                continue;
            }
            int err = 0;
            int len = sizeof(err);
            if (writable && getsockopt(ps, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len) == 0 &&
                err == 0) {
                *out = std::move(pending[i]);
                return std::string();  // the other attempts close with `pending`
            }
            pending.erase(pending.begin() + static_cast<std::ptrdiff_t>(i));
            nextStartAt = 0;  // a failed attempt starts the next one at once
        }
    }
    return fwd_err::kConnectFailed;
}

std::string DialTcp(EgressKind egress, const std::string& nodeId, const std::string& host, int port,
                    TunnelSource* tunnel, const DialCancel& cancel, UniqueSocket* out) {
    if (egress == EgressKind::Direct) return ConnectDirect(host, port, cancel, out);
    if (!tunnel) return tunnel_err::kNeedsGhost;
    TunnelResult t = tunnel->Open(egress, nodeId, Proto::Tcp, host, port);
    if (!t.code.empty()) return t.code;
    if (!t.sock) return fwd_err::kInternal;
    *out = std::move(t.sock);
    return std::string();
}

}  // namespace pf
