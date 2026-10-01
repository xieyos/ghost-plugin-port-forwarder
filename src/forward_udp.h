// One UDP forwarding rule at run time: a listening UDP socket and ONE poll thread that
// serves it and every session's remote socket (WSAPoll, in slices of kPollSliceMs; the
// stop flag, Ghost's availability and session idleness are checked after every slice).
//
// Sessions. A session is one client, keyed by its full source address (IPv4 address AND
// port: two programs on one machine are two sessions, and a reply goes back to exactly the
// address the session's datagrams came from). At most kMaxUdpSessionsPerRule per rule; a
// datagram from a new client over that is dropped and counted (lastError session_limit).
//
// The remote end of a session, opened on a short-lived worker thread so that the poll
// thread never blocks (name resolution and a tunnel request both can):
//   direct     remote.host is resolved here (asynchronously, so a stop cancels the lookup:
//              resolve.h) and a UDP socket is connected to the first address a socket can
//              be created for.
//   via a node Ghost relays the session through the user's upstream node and hands over
//              one end of a connected loopback UDP pair (TunnelSource::Open, proto udp;
//              spec-plugin-api.md section 10.4). One association per session.
//              FAIL CLOSED: any failure drops the session's datagrams; a via-node rule
//              never creates a direct socket, ever.
// While the remote end is being opened the session queues at most kUdpQueueMaxDatagrams
// datagrams / kUdpQueueMaxBytes bytes; more are dropped and counted.
//
// A failed open is remembered for kUdpOpenFailureCacheMs per rule: until then a datagram
// from a client without a session is dropped and counted at once, without a request -- a
// node that refuses UDP must not turn every datagram into a call to Ghost. Sessions whose
// open is already in flight are not affected. (Direct opens are cached the same way: a name
// that does not resolve is not looked up again for every datagram.)
//
// A session ends:
//   * when it saw no datagram in either direction for the rule's udpIdleSec -- or, for a
//     relayed session, for Ghost's idleTimeoutMs less one second, if that is shorter (Ghost
//     tears the relay down then, and a datagram sent into a torn-down relay is lost);
//   * on WSAECONNRESET from its remote socket (lastError remote_reset): for a relayed
//     session that is Ghost's "the relay is gone" signal, for a direct one an ICMP "port
//     unreachable" from the destination. The client's next datagram opens a new session.
//   * when the rule stops.
// A session whose open is in flight is not reclaimed for idleness; its open ends it or
// makes it usable.
//
// Datagrams client -> remote larger than a relay's maxPayload are dropped and counted
// (Ghost would drop them silently). Replies are sent from the listening socket to the
// session's client address. A datagram that cannot be sent at once (a full buffer) is
// dropped and counted: UDP does not queue.
//
// The listening socket: SO_EXCLUSIVEADDRUSE, not inheritable, and SIO_UDP_CONNRESET /
// SIO_UDP_NETRESET off -- otherwise an ICMP error caused by a reply to a client that has
// gone away would make the next receive on the listener fail, for every client. Any other
// receive error on it (out of buffers) is recorded as internal_error and the poll thread
// waits one slice before it reads again: the listener stays readable, and retrying at once
// would spin.
//
// Threads and stopping: as forward_tcp.h. The poll thread is joined; open workers are
// detached and tracked, own what they use through a shared_ptr, and a worker that outlives
// WaitStopped's deadline (a straggler) closes whatever socket its open returns.
//
// Counters (stats.h): udpSessions = sessions open now (including those being opened);
// totalConnections = sessions created; bytesUp/bytesDown = payload bytes sent each way;
// droppedDatagrams = every datagram not forwarded, for any reason.
//
// What is never logged: client addresses and per-session destinations.
#pragma once

#include "forward_common.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>

namespace pf {

constexpr size_t kMaxUdpSessionsPerRule = 64;
constexpr size_t kUdpQueueMaxDatagrams = 32;
constexpr size_t kUdpQueueMaxBytes = 64 * 1024;
constexpr uint32_t kUdpOpenFailureCacheMs = 10000;
// Reclaim a relayed session this long before Ghost's own idle timeout would tear it down.
constexpr uint32_t kUdpRelayIdleMarginMs = 1000;

namespace testing {
// Test seam: the next `count` receives on every UDP rule's listener fail with `wsaError`
// without taking the datagram, as a real WSAENOBUFS would. 0 turns it off.
void InjectUdpListenErrors(int count, int wsaError);
}  // namespace testing

struct UdpShared;  // forward_udp.cpp

class UdpForwarder final : public Forwarder {
public:
    UdpForwarder(const Rule& rule, ForwardContext ctx);
    // SignalStop, then joins the poll thread (workers are detached and own what they use).
    ~UdpForwarder() override;
    UdpForwarder(const UdpForwarder&) = delete;
    UdpForwarder& operator=(const UdpForwarder&) = delete;

    void Start() override;
    void SignalStop() override;
    bool WaitStopped(uint64_t deadlineTick) override;
    RuleStatus Snapshot() const override;
    // Open workers still running.
    int ThreadsAlive() const override;
    const Rule& rule() const override;

private:
    std::shared_ptr<UdpShared> s_;
    std::thread poll_;
};

}  // namespace pf
