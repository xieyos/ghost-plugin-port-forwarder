// Name resolution for direct rules that a rule's stop can interrupt.
//
// GetAddrInfoW blocks for as long as the resolver takes (seconds for a name no server
// answers), and nothing can wake it: a connection thread inside it outlives its rule's stop
// as a straggler. ResolveHost uses GetAddrInfoExW asynchronously instead and waits for
// either the answer or `stopEvent`; on the stop it cancels the lookup (GetAddrInfoExCancel)
// and returns `cancelled`. Where the asynchronous form is not available (it answers
// WSAEINVAL / WSAEOPNOTSUPP), it falls back to GetAddrInfoW -- the thread may then be a
// straggler again, which forward_tcp.h / forward_udp.h already allow for.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>

#include <string>
#include <vector>

namespace pf {

namespace resolve_err {
constexpr const char* kCancelled = "cancelled";
}  // namespace resolve_err

struct ResolvedAddr {
    int family = AF_UNSPEC;
    sockaddr_storage addr = {};
    int len = 0;
};

// Resolves host:port for `socktype` (SOCK_STREAM / SOCK_DGRAM), in the resolver's order.
// "" and at least one address; or fwd_err::kResolveFailed ("resolve_failed") /
// resolve_err::kCancelled. `stopEvent` may be null (not interruptible).
std::string ResolveHost(const std::string& host, int port, int socktype, HANDLE stopEvent,
                        std::vector<ResolvedAddr>* out);

}  // namespace pf
