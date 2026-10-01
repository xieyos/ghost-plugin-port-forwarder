// One TCP forwarding rule at run time: a listener, an accept thread, and one pump thread
// per connection.
//
// The remote end of a connection:
//   direct     remote.host is resolved here (GetAddrInfoW) and every address is tried in
//              turn with a 2 s connect timeout.
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
// that way, or at once on an error or a stop.
//
// Limits: maxConnections per rule and a global limit (1024) shared by every rule; a
// connection over either is closed as soon as it is accepted and counted as rejected.
//
// Via-node rules do not listen at all while a tunnel is impossible: status needs_ghost
// (standalone), permission_missing, or ghost_unavailable (Ghost answered 401 -- detected
// before the listener opens and within one poll slice while it is open).
//
// Threads and stopping (see also engine.h): the accept thread is joined. Connection threads
// are detached but tracked: SignalStop() makes every pump end within one slice, but a thread
// can also be blocked where no flag reaches it -- in GetAddrInfoW, or in a tunnel request
// (the engine's final Stop aborts those through TunnelSource::Shutdown, but a 429 backoff
// inside it is not woken, and Apply() does not abort anything: the client is shared by
// every rule). WaitStopped() waits for them only until its
// deadline. A thread still running after that ("a straggler") owns everything it touches
// through a shared_ptr -- rule, stats, tunnel source, log function, a Winsock reference --
// and closes its sockets when its call returns. Nothing it uses can be freed under it.
//
// What is never logged: client addresses and per-connection destinations.
#pragma once

#include "applog.h"
#include "rules.h"
#include "stats.h"
#include "tunnel_source.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace pf {

// A rule's state as the page shows it.
namespace rule_status {
constexpr const char* kListening = "listening";
constexpr const char* kDisabled = "disabled";
constexpr const char* kStopped = "stopped";
constexpr const char* kBindFailed = "bind_failed";       // detail: "WSA error <n>" (+ a hint for 10013)
constexpr const char* kInvalid = "invalid";              // detail: the validation code
constexpr const char* kNotSupported = "not_supported";   // a rule kind this build cannot run
constexpr const char* kNeedsGhost = tunnel_err::kNeedsGhost;
constexpr const char* kPermissionMissing = tunnel_err::kPermissionMissing;
constexpr const char* kGhostUnavailable = api_err::kGhostUnavailable;
}  // namespace rule_status

// lastError codes of our own (tunnel failures carry Ghost's or the client's code as is).
namespace fwd_err {
constexpr const char* kResolveFailed = "resolve_failed";      // GetAddrInfoW found nothing
constexpr const char* kConnectFailed = "connect_failed";      // no address accepted within the timeout
constexpr const char* kConnectionLimit = "connection_limit";  // maxConnections or the global limit
constexpr const char* kBindFailed = "bind_failed";
constexpr const char* kInternal = "internal_error";           // a socket call that should not fail did
}  // namespace fwd_err

constexpr int kGlobalMaxConnections = 1024;
constexpr DWORD kDirectConnectTimeoutMs = 2000;
constexpr size_t kPumpBufferBytes = 64 * 1024;
constexpr DWORD kPollSliceMs = 250;

using LogFn = std::function<void(LogLevel, const std::string&, const LogFields&)>;

struct RuleStatus {
    std::string id;
    std::string status;  // rule_status
    std::string detail;
    StatsSnapshot stats;
};

// What every forwarder of one engine shares.
struct ForwardContext {
    std::shared_ptr<TunnelSource> tunnel;  // null = standalone
    LogFn log;                             // may be empty
    std::shared_ptr<std::atomic<int>> globalConnections;  // null = a private counter
    int globalMax = kGlobalMaxConnections;
};

// The detail text for a bind failure.
std::string BindFailureDetail(int wsaError);

struct TcpShared;  // forward_tcp.cpp

class TcpForwarder {
public:
    TcpForwarder(const Rule& rule, ForwardContext ctx);
    // SignalStop + WaitStopped with a 3 s budget.
    ~TcpForwarder();
    TcpForwarder(const TcpForwarder&) = delete;
    TcpForwarder& operator=(const TcpForwarder&) = delete;

    // Opens the listener and the accept thread, or sets the status that says why not.
    void Start();
    // Every thread of this rule ends what it is doing: the listener closes, every pump
    // closes both its sockets within one poll slice. Returns at once.
    void SignalStop();
    // Joins the accept thread and waits for the connection threads until `deadlineTick`
    // (GetTickCount64). True when none is left.
    bool WaitStopped(uint64_t deadlineTick);

    RuleStatus Snapshot() const;
    // Connection threads still running (after WaitStopped: the stragglers).
    int ThreadsAlive() const;
    const Rule& rule() const;

private:
    std::shared_ptr<TcpShared> s_;
    std::thread accept_;
};

}  // namespace pf
