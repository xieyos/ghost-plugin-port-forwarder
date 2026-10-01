// The rule engine: the running forwarders for the current rule set.
//
// Apply(rules) matches rules by id. A rule whose every field is unchanged (Rule's
// operator==) keeps its forwarder -- its listener, its open connections and its counters
// survive. A rule that changed, was disabled or was removed is stopped, which closes all of
// its connections; a new or changed enabled rule is started with fresh counters. Rules are
// stopped before any is started, so a rule that moved to a port another rule just left can
// bind it.
//
// The engine expects rules that passed validation (rules.h). It still checks each rule with
// ValidateStoredRule and shows a failure as status "invalid" (detail: the code) instead of
// running it; a repeated id is "invalid" / duplicate_id.
//
// Stop() is final and bounded by stopBudgetMs, 2 s: the host allows the whole process 3 s
// to exit after its stop event, and the UI server and the log's last batch come after it.
// Stop() ends the tunnel source's waits (TunnelSource::Shutdown), signals every forwarder,
// joins the accept threads and waits for connection threads until the budget is spent. A
// connection thread can be blocked where no flag reaches it -- in name resolution, or
// waiting for Ghost's answer to a tunnel request, which may take Ghost up to 10 s and must
// not be abandoned (the answer may carry a socket already duplicated into this process).
// Such a thread is left running: it owns what it uses through shared_ptrs (see
// forward_tcp.h) and closes its sockets when its call returns. Joining it instead would
// make Stop() take as long as Ghost does. StragglerThreads() counts them; the process may
// exit with them running.
#pragma once

#include "forward_tcp.h"
#include "rules.h"
#include "tunnel_source.h"

#include <windows.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pf {

constexpr DWORD kEngineStopBudgetMs = 2000;

struct EngineOptions {
    std::shared_ptr<TunnelSource> tunnel;  // null = standalone (via-node rules: needs_ghost)
    LogFn log;
    int globalMaxConnections = kGlobalMaxConnections;
    DWORD stopBudgetMs = kEngineStopBudgetMs;
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
        std::unique_ptr<TcpForwarder> tcp;  // null when the rule does not run
        std::string status;                 // used when tcp is null
        std::string detail;
    };

    // Signals `forwarders`, then waits for them all within one budget; those with threads
    // left over move to retired_.
    void StopForwarders(std::vector<std::unique_ptr<TcpForwarder>> forwarders, DWORD budgetMs);
    void PruneRetired() const;

    ForwardContext ctx_;
    DWORD stopBudgetMs_;
    std::shared_ptr<std::atomic<int>> globalConnections_;

    mutable std::mutex mu_;
    bool stopped_ = false;
    std::vector<Entry> entries_;
    mutable std::vector<std::unique_ptr<TcpForwarder>> retired_;
};

}  // namespace pf
