// One TCP forwarding rule at run time: a listener, an accept thread, and one pump thread
// per connection.
//
// The remote end of a connection:
//   direct     remote.host is resolved here (asynchronously, so a stop cancels the lookup:
//              resolve.h), and the addresses are tried the RFC 8305 way -- families
//              interleaved, the next attempt 250 ms after the previous (at once when it
//              failed), the first to connect wins, and 2 s cover the whole set.
//   via a node Ghost builds the connection through the user's upstream node and hands the
//              socket over (TunnelSource::Open). ANY failure there closes the client's
//              connection and records the code as lastError. There is no fallback to a
//              direct connection, ever: a rule that says "through my proxy" must not send
//              the user's traffic out from the real address because the proxy was down.
//
// The pump: both sockets non-blocking, select() in slices of kPollSliceMs (the stop flag is
// checked after every slice), one 64 KB buffer per direction. Half-close is forwarded: when
// one side ends its sending (EOF) and everything it sent has been delivered, the other side
// gets shutdown(SD_SEND); the connection is closed only when both directions have ended
// that way, on a stop, or on an error. shutdown(SD_SEND) is only ever the answer to a real
// EOF. On an error of one side (a reset, a failed send), what is buffered for the other
// (healthy) side is first handed to it, best effort within one slice (detail::FlushBuffered),
// and the healthy side is then closed ABORTIVELY (SO_LINGER {1, 0}): it sees a reset, not an
// EOF that would claim the stream was complete. Best effort means exactly that -- an abortive
// close discards whatever the healthy side's kernel had not yet transmitted.
//
// Accept errors other than "nothing to take" / "reset before taken" (out of buffers, out of
// handles) are recorded as internal_error and the accept thread then waits one slice: the
// listener stays readable, and retrying at once would spin.
//
// Limits: maxConnections per rule and a global limit (1024) shared by every rule; a
// connection over either is closed as soon as it is accepted and counted as rejected.
//
// Via-node rules do not listen at all while a tunnel is impossible: status needs_ghost
// (standalone), permission_missing, or ghost_unavailable (Ghost answered 401 -- detected
// before the listener opens and within one poll slice while it is open).
//
// Threads and stopping (see also engine.h): the accept thread is joined. Connection threads
// are detached but tracked: SignalStop() makes every pump end within one slice and cancels
// a name lookup in progress, but a thread can also be blocked where no flag reaches it -- in
// a tunnel request (the engine's final Stop aborts those through TunnelSource::Shutdown, but
// a 429 backoff inside it is not woken, and Apply() does not abort anything: the client is
// shared by every rule), or in GetAddrInfoW where the asynchronous lookup is unavailable.
// WaitStopped() waits for them only until its deadline. A thread still running after that ("a straggler") owns everything it touches
// through a shared_ptr -- rule, stats, tunnel source, log function, a Winsock reference --
// and closes its sockets when its call returns. Nothing it uses can be freed under it.
//
// What is never logged: client addresses and per-connection destinations.
#pragma once

#include "forward_common.h"

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <thread>

namespace pf {

constexpr DWORD kDirectConnectTimeoutMs = 2000;
constexpr DWORD kStaggerDelayMs = 250;  // RFC 8305's "Connection Attempt Delay"
constexpr size_t kPumpBufferBytes = 64 * 1024;

namespace detail {
// Sends data[0, len) to `dst` (non-blocking) within `budgetMs` or until `*stop`. `sent`
// receives the bytes handed to the kernel. True when all of it was. Never shuts anything
// down: the caller decides how the connection ends.
bool FlushBuffered(SOCKET dst, const char* data, size_t len, DWORD budgetMs, const std::atomic<bool>* stop,
                   size_t* sent);
}  // namespace detail

namespace testing {
// Test seam: the next `count` accepts of every TCP rule fail with `wsaError` without taking
// the pending connection, as a real WSAENOBUFS would. 0 turns it off.
void InjectAcceptErrors(int count, int wsaError);
}  // namespace testing

struct TcpShared;  // forward_tcp.cpp

class TcpForwarder final : public Forwarder {
public:
    TcpForwarder(const Rule& rule, ForwardContext ctx);
    // SignalStop, then joins the accept thread. Connection threads are detached and own what
    // they use; nothing waits for them here.
    ~TcpForwarder() override;
    TcpForwarder(const TcpForwarder&) = delete;
    TcpForwarder& operator=(const TcpForwarder&) = delete;

    // Opens the listener and the accept thread, or sets the status that says why not.
    void Start() override;
    // Every thread of this rule ends what it is doing: the listener closes, every pump
    // closes both its sockets within one poll slice, a name lookup is cancelled. A thread
    // inside a tunnel request is not reached (see above). Returns at once.
    void SignalStop() override;
    // Joins the accept thread and waits for the connection threads until `deadlineTick`
    // (GetTickCount64). True when none is left.
    bool WaitStopped(uint64_t deadlineTick) override;

    RuleStatus Snapshot() const override;
    // Connection threads still running (after WaitStopped: the stragglers).
    int ThreadsAlive() const override;
    const Rule& rule() const override;

private:
    std::shared_ptr<TcpShared> s_;
    std::thread accept_;
};

}  // namespace pf
