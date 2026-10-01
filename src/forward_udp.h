// One UDP forwarding rule at run time: a listening UDP socket and ONE poll thread that
// serves it and every session's remote socket (WSAPoll, in slices of kPollSliceMs; the
// stop flag, Ghost's availability and session idleness are checked after every slice).
//
// Sessions. A session is one client source address (IPv4 address AND port: two programs on
// one machine are two sessions) as seen at one local address -- on a 0.0.0.0 listener of a
// multi-homed machine the destination address of the datagram (IP_PKTINFO) is part of the
// key, and replies are sent from it (WSASendMsg with IN_PKTINFO; where Windows refuses that
// source, e.g. 127.0.0.2, from whatever address routing picks). At most
// kMaxUdpSessionsPerRule per rule; a datagram from a new client over that is dropped and
// counted (lastError session_limit).
//
// The remote end of a session, opened on a short-lived worker thread so that the poll
// thread never blocks (name resolution and a tunnel request both can):
//   direct     remote.host is resolved here (asynchronously, so a stop cancels the lookup:
//              resolve.h). The addresses are ordered -- families interleaved; for
//              "localhost" IPv4 first; the address the rule's last answered session used
//              first of all -- and a UDP socket (bound to port 0 exclusively) is connected
//              to the first one. A UDP connect sends nothing, so a dead address only shows
//              as WSAECONNRESET (an ICMP "port unreachable"). Until the first reply the
//              session keeps what it sent (within the queue's bounds); a reset before any
//              reply moves it to the next address, which gets those datagrams again.
//   via a node Ghost relays the session through the user's upstream node and hands over
//              one end of a connected loopback UDP pair (TunnelSource::Open, proto udp;
//              spec-plugin-api.md section 10.4). One association per session. The plugin
//              holds at most ForwardContext::udpRelayMax relays (Ghost's per-plugin limit)
//              across all rules; a new client over that is refused locally (session_limit),
//              without a request.
//              FAIL CLOSED: any failure drops the session's datagrams; a via-node rule
//              never creates a direct socket, ever.
// While the remote end is being opened the session queues at most kUdpQueueMaxDatagrams
// datagrams / kUdpQueueMaxBytes bytes; more are dropped and counted.
//
// Failed opens. A failure that says something about the node or the name
// (IsCacheableOpenFailure: upstream_*, permission_denied, tunnel_unsupported,
// resolve_failed) is remembered per rule, 1 s after the first failure, doubling to 10 s:
// until then a datagram from a client without a session is dropped and counted at once,
// without a request -- a node that refuses UDP must not turn every datagram into a call to
// Ghost. Capacity and transport answers (tunnel_limit, rate_limited, ghost_unreachable, ...)
// are not: they say nothing about the next request. A successful open clears the cache.
//
// Per client, a session that ended before its remote end ever answered (its open failed,
// or the destination reset it) holds that client back 1 s, doubling to 10 s: its datagrams
// meanwhile are dropped and counted, instead of each costing a thread, a lookup or a
// request. A reply clears it. At most kUdpClientBackoffEntries clients are remembered.
//
// A session ends:
//   * when it saw no datagram actually sent or received, in either direction, for the rule's
//     udpIdleSec -- or, for a relayed session, for Ghost's idleTimeoutMs less one second, if
//     that is shorter (Ghost tears the relay down then, and a datagram sent into a torn-down
//     relay is lost);
//   * on WSAECONNRESET from its remote socket (lastError remote_reset) that no failover
//     answers: for a relayed session that is Ghost's "the relay is gone" signal, for a
//     direct one an ICMP "port unreachable" from the last address. The client's next
//     datagram opens a new session.
//   * when the rule stops.
// A session whose open is in flight is not reclaimed for idleness; its open ends it or
// makes it usable.
//
// Datagrams client -> remote larger than a relay's maxPayload are dropped and counted
// (Ghost would drop them silently). A datagram that cannot be sent at once (a full buffer)
// is dropped and counted: UDP does not queue.
//
// Sockets: the listener has SO_EXCLUSIVEADDRUSE, is not inheritable, and has
// SIO_UDP_CONNRESET / SIO_UDP_NETRESET off -- otherwise an ICMP error caused by a reply to a
// client that has gone away would make the next receive on the listener fail, for every
// client. A session's remote socket (direct or adopted) has them on, explicitly. Listener
// and remote sockets get a kUdpSocketBufferBytes receive buffer. Any other receive error on
// the listener (out of buffers), and an error condition that no receive clears, is recorded
// as internal_error and followed by a one-slice pause: the listener stays readable, and
// retrying at once would spin.
//
// Threads and stopping: as forward_tcp.h. The poll thread is joined; open workers are
// detached and tracked, own what they use through a shared_ptr, and a worker that outlives
// WaitStopped's deadline (a straggler) closes whatever socket its open returns.
//
// Counters (stats.h): udpSessions = sessions open now (including those being opened);
// totalConnections = sessions created; bytesUp/bytesDown = payload bytes sent each way
// (datagrams sent again after a failover count again); droppedDatagrams = every datagram not
// forwarded, for any reason.
//
// What is never logged: client addresses and per-session destinations.
#pragma once

#include "forward_common.h"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>

namespace pf {

constexpr size_t kMaxUdpSessionsPerRule = 64;
constexpr size_t kUdpQueueMaxDatagrams = 32;
constexpr size_t kUdpQueueMaxBytes = 64 * 1024;
constexpr uint32_t kUdpFailureCacheMinMs = 1000;
constexpr uint32_t kUdpFailureCacheMaxMs = 10000;
constexpr uint32_t kUdpClientBackoffMinMs = 1000;
constexpr uint32_t kUdpClientBackoffMaxMs = 10000;
constexpr size_t kUdpClientBackoffEntries = 256;
constexpr size_t kUdpSocketBufferBytes = 1024 * 1024;
// Reclaim a relayed session this long before Ghost's own idle timeout would tear it down.
constexpr uint32_t kUdpRelayIdleMarginMs = 1000;

// Whether a failed open says something about the node or the name, and is therefore
// remembered for the rule (see above).
bool IsCacheableOpenFailure(const std::string& code);

namespace testing {
// Test seam: the next `count` receives on every UDP rule's listener fail with `wsaError`
// without taking the datagram, as a real WSAENOBUFS would. 0 turns it off.
void InjectUdpListenErrors(int count, int wsaError);
// Test seam: whether "localhost" is tried IPv4 first (default true). Off, the resolver's
// order stands -- on most machines ::1 first -- so a test can make a session fail over.
void SetUdpLocalhostIpv4First(bool on);
// Failovers to a next address, in this process, so far.
uint64_t UdpFailovers();
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
