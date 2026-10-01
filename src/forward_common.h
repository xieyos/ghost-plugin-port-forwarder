// What the TCP and the UDP forwarders share: the statuses and error codes the page shows,
// the context an engine hands every forwarder, and the interface the engine drives them
// through (forward_tcp.h, forward_udp.h).
#pragma once

#include "applog.h"
#include "clock.h"
#include "rules.h"
#include "stats.h"
#include "tunnel_source.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

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
constexpr const char* kSessionLimit = "session_limit";        // UDP: a new client over the per-rule cap
constexpr const char* kRemoteReset = "remote_reset";          // UDP: WSAECONNRESET on a session's remote socket
}  // namespace fwd_err

constexpr int kGlobalMaxConnections = 1024;
// Ghost keeps at most 32 UDP relays per plugin (spec-limits.md 7.2); asking for a 33rd only
// earns a tunnel_limit answer, so the plugin counts its own and refuses locally.
constexpr int kMaxUdpRelaysPerPlugin = 32;
constexpr DWORD kPollSliceMs = 250;

// A LogFn must keep alive whatever it calls. A straggler thread (forward_tcp.h) copies only
// the std::function and may run after the engine and its owner are gone, so a LogFn that
// writes to an AppLog captures a shared_ptr<AppLog> -- never a raw pointer or a reference.
// AppLog itself keeps a raw GhostApi* (applog.h): the same rule applies one level down,
// whoever owns the AppLog keeps that GhostApi alive at least as long.
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
    // UDP relays (via-node sessions) open or being opened, across every rule of the engine.
    // null = a private counter.
    std::shared_ptr<std::atomic<int>> udpRelays;
    int udpRelayMax = kMaxUdpRelaysPerPlugin;
    // What UDP rules measure session idleness and the failed-open cache with. Null =
    // DefaultClock(). Read only by a UDP rule's poll thread, which its forwarder joins, so
    // the clock need only outlive the engine.
    Clock* clock = nullptr;
};

// The detail text for a bind failure. The 10013 hint names the netsh command for the
// rule's protocol.
std::string BindFailureDetail(int wsaError, Proto proto = Proto::Tcp);

// One running rule, as the engine drives it.
class Forwarder {
public:
    virtual ~Forwarder() = default;
    // Opens the listener and its thread, or sets the status that says why not.
    virtual void Start() = 0;
    // Every thread of this rule ends what it is doing. Returns at once.
    virtual void SignalStop() = 0;
    // Joins the rule's own thread and waits for its detached workers until `deadlineTick`
    // (GetTickCount64). True when none is left.
    virtual bool WaitStopped(uint64_t deadlineTick) = 0;
    virtual RuleStatus Snapshot() const = 0;
    // Detached threads still running (after WaitStopped: the stragglers).
    virtual int ThreadsAlive() const = 0;
    virtual const Rule& rule() const = 0;
};

}  // namespace pf
