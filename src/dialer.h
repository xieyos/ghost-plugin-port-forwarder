// Opening the far end of a TCP connection, the way an egress says: directly, or through a
// Ghost upstream node. Every TCP connection the plugin makes to somewhere else goes through
// DialTcp -- today a TCP rule's remote; with the SSH and FRP tunnels, also the connection
// to an SSH server or to frps, which take the same three egress kinds.
//
//   direct      the host is resolved here (asynchronously, so a stop cancels the lookup:
//               resolve.h), and the addresses are tried the RFC 8305 way -- families
//               interleaved, the next attempt kStaggerDelayMs after the previous (at once
//               when it failed), the first to connect wins, and kDirectConnectTimeoutMs
//               cover the whole set.
//   via a node  Ghost builds the connection through the user's upstream node and hands the
//               socket over (TunnelSource::Open). Its code is the answer.
//
// There is no fallback from a node to a direct connection, ever: a caller that says
// "through my proxy" must not send the user's traffic out from the real address because the
// proxy was down. DialTcp has no path that does it.
#pragma once

#include "rules.h"
#include "tunnel_source.h"
#include "unique_socket.h"

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <string>

namespace pf {

constexpr DWORD kDirectConnectTimeoutMs = 2000;
constexpr DWORD kStaggerDelayMs = 250;  // RFC 8305's "Connection Attempt Delay"

// How a dial is told to give up. The caller signals both together: `stop` is checked
// between waits of at most kPollSliceMs, `stopEvent` ends a name lookup in progress.
// Either may be null (then that wait is not interruptible).
struct DialCancel {
    const std::atomic<bool>* stop = nullptr;
    HANDLE stopEvent = nullptr;
};

// Connects to host:port directly (see above). "" and a connected, non-blocking socket in
// `out`; or resolve_failed, cancelled (the lookup was stopped) or connect_failed. A stop
// during the connect attempts answers connect_failed.
std::string ConnectDirect(const std::string& host, int port, const DialCancel& cancel, UniqueSocket* out);

// One TCP connection to host:port over `egress`. "" and a connected socket in `out`, or a
// code: ConnectDirect's for Direct; for Active/Node needs_ghost when `tunnel` is null (the
// standalone mode), otherwise TunnelSource::Open's code -- and internal_error when Open
// answered success without a socket. `egress` and `nodeId` go to Open as given.
//
// The socket from a node is in whatever blocking mode the adoption left it; the direct one
// is non-blocking. Callers set the mode they need.
std::string DialTcp(EgressKind egress, const std::string& nodeId, const std::string& host, int port,
                    TunnelSource* tunnel, const DialCancel& cancel, UniqueSocket* out);

}  // namespace pf
