// The rule engine: the running forwarders for the current rule set -- a TcpForwarder
// (forward_tcp.h) for each enabled TCP rule, a UdpForwarder (forward_udp.h) for each
// enabled UDP rule.
//
// Apply(rules) matches rules by id. A rule whose every field is unchanged (Rule's
// operator==) and that is listening keeps its forwarder -- its listener, its open
// connections and its counters survive. One that is not listening (bind_failed, a via-node
// rule waiting for Ghost) is started again: applying the same rules is how a failed bind is
// retried. A rule that changed, was disabled or was removed is stopped, which closes all of
// its connections (UDP: its sessions); a new or changed enabled rule is started with fresh counters. Rules are
// stopped before any is started, so a rule that moved to a port another rule just left can
// bind it.
//
// The engine expects rules that passed validation (rules.h). It still checks each rule with
// ValidateStoredRule and shows a failure as status "invalid" (detail: the code) instead of
// running it; a repeated id is "invalid" / duplicate_id.
//
// Stop() is final and bounded by stopBudgetMs, 2 s, counted from the moment it is called:
// the host allows the whole process 3 s to exit after its stop event, and the UI server and
// the log's last batch come after it. Stop() first -- before it takes the engine's lock --
// ends the tunnel source's waits and aborts its requests on the wire
// (TunnelSource::Shutdown -- a tunnel request Ghost is slow to answer returns at once), and
// flags the stop: an Apply() running on another thread then ends its own wait for stopped
// forwarders early and starts nothing more, so the two waits never add up. Then it signals
// every forwarder (including those an earlier Apply() left behind), joins the accept
// threads and waits for connection threads until the budget is spent. A connection thread can still be blocked where nothing reaches it:
// in name resolution, or in a 429 backoff inside the API client. Such a thread is left
// running: it owns what it uses through shared_ptrs (see forward_tcp.h) and closes its
// sockets when its call returns. Joining it instead would make Stop() as slow as the
// resolver. StragglerThreads() counts them (UDP rules: open workers, which block the same
// way); the process may exit with them running.
#pragma once

#include "forward_tcp.h"
#include "forward_udp.h"
#include "rules.h"
#include "tunnel_source.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pf {

constexpr DWORD kEngineStopBudgetMs = 2000;
// How often Apply(), while waiting for stopped forwarders, looks whether Stop() was called.
constexpr DWORD kApplyWaitSliceMs = 50;

struct EngineOptions {
    std::shared_ptr<TunnelSource> tunnel;  // null = standalone (via-node rules: needs_ghost)
    LogFn log;
    int globalMaxConnections = kGlobalMaxConnections;
    DWORD stopBudgetMs = kEngineStopBudgetMs;
    // UDP session idleness and the failed-open cache (forward_udp.h). Null = DefaultClock().
    // Must outlive the engine.
    Clock* clock = nullptr;
};

class Engine {
public:
    explicit Engine(EngineOptions opts);
    ~Engine();  // Stop()
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Does nothing after Stop().
    void Apply(const std::vector<Rule>& rules);

    // One entry per rule of the last Apply, in its order. Empty after Stop().
    std::vector<RuleStatus> Snapshot() const;

    void Stop();

    // Connection threads of stopped forwarders that were still running when their stop
    // budget ran out (and have not finished since).
    int StragglerThreads() const;
    // Connections open right now, across every rule.
    int GlobalConnections() const { return globalConnections_->load(); }

private:
    struct Entry {
        Rule rule;
        std::unique_ptr<Forwarder> fwd;  // null when the rule does not run
        std::string status;              // used when fwd is null
        std::string detail;
    };

    // Signals `forwarders`, then waits for them all until `deadlineTick` (GetTickCount64) --
    // or, when `interruptible`, until Stop() is requested; those with threads left over move
    // to retired_.
    void StopForwarders(std::vector<std::unique_ptr<Forwarder>> forwarders, uint64_t deadlineTick,
                        bool interruptible);
    void PruneRetired() const;

    ForwardContext ctx_;
    DWORD stopBudgetMs_;
    std::shared_ptr<std::atomic<int>> globalConnections_;

    std::atomic<bool> stopRequested_{false};  // set by Stop() before it takes mu_

    mutable std::mutex mu_;
    bool stopped_ = false;
    std::vector<Entry> entries_;
    mutable std::vector<std::unique_ptr<Forwarder>> retired_;
};

}  // namespace pf
