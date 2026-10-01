#include "engine.h"

#include <set>
#include <utility>

namespace pf {

Engine::Engine(EngineOptions opts)
    : stopBudgetMs_(opts.stopBudgetMs), globalConnections_(std::make_shared<std::atomic<int>>(0)) {
    ctx_.tunnel = std::move(opts.tunnel);
    ctx_.log = std::move(opts.log);
    ctx_.globalConnections = globalConnections_;
    ctx_.globalMax = opts.globalMaxConnections;
    ctx_.clock = opts.clock;
}

Engine::~Engine() { Stop(); }

void Engine::StopForwarders(std::vector<std::unique_ptr<Forwarder>> forwarders, DWORD budgetMs) {
    // Every forwarder is told first, so that their connections close in parallel and one
    // budget covers them all.
    for (auto& f : forwarders) f->SignalStop();
    const uint64_t deadline = GetTickCount64() + budgetMs;
    for (auto& f : forwarders) {
        if (!f->WaitStopped(deadline)) retired_.push_back(std::move(f));
    }
}

void Engine::PruneRetired() const {
    std::vector<std::unique_ptr<Forwarder>> keep;
    for (auto& f : retired_) {
        if (f->ThreadsAlive() > 0) keep.push_back(std::move(f));
    }
    retired_.swap(keep);
}

void Engine::Apply(const std::vector<Rule>& rules) {
    std::lock_guard<std::mutex> lock(mu_);
    if (stopped_) return;

    // 1. Keep the forwarders of unchanged rules; everything else that runs is stopped.
    std::vector<Entry> old;
    old.swap(entries_);
    std::vector<std::unique_ptr<Forwarder>> toStop;
    std::vector<Entry> next;
    next.reserve(rules.size());
    std::set<std::string> seen;
    for (const Rule& r : rules) {
        Entry e;
        e.rule = r;
        if (!seen.insert(r.id).second) {
            e.status = rule_status::kInvalid;
            e.detail = rule_err::kDuplicateId;
            next.push_back(std::move(e));
            continue;
        }
        for (Entry& o : old) {
            if (o.fwd && o.rule.id == r.id && o.rule == r) {
                e.fwd = std::move(o.fwd);
                break;
            }
        }
        next.push_back(std::move(e));
    }
    for (Entry& o : old) {
        if (o.fwd) toStop.push_back(std::move(o.fwd));
    }
    StopForwarders(std::move(toStop), stopBudgetMs_);

    // 2. Start what is new or changed.
    for (Entry& e : next) {
        if (e.fwd || !e.status.empty()) continue;
        if (!e.rule.enabled) {
            e.status = rule_status::kDisabled;
            continue;
        }
        const std::string bad = ValidateStoredRule(e.rule);
        if (!bad.empty()) {
            e.status = rule_status::kInvalid;
            e.detail = bad;
            continue;
        }
        if (e.rule.proto == Proto::Udp) {
            e.fwd = std::make_unique<UdpForwarder>(e.rule, ctx_);
        } else {
            e.fwd = std::make_unique<TcpForwarder>(e.rule, ctx_);
        }
        e.fwd->Start();
    }
    entries_.swap(next);
    PruneRetired();
}

std::vector<RuleStatus> Engine::Snapshot() const {
    std::lock_guard<std::mutex> lock(mu_);
    std::vector<RuleStatus> out;
    out.reserve(entries_.size());
    for (const Entry& e : entries_) {
        if (e.fwd) {
            out.push_back(e.fwd->Snapshot());
            continue;
        }
        RuleStatus s;
        s.id = e.rule.id;
        s.status = e.status;
        s.detail = e.detail;
        out.push_back(std::move(s));
    }
    return out;
}

void Engine::Stop() {
    std::lock_guard<std::mutex> lock(mu_);
    if (stopped_) return;
    stopped_ = true;
    // Ends tunnel slot waits and plugin_not_running retries at once; a request already on
    // the wire is not abandoned (see engine.h).
    if (ctx_.tunnel) {
        try {
            ctx_.tunnel->Shutdown();
        } catch (...) {
        }
    }
    std::vector<std::unique_ptr<Forwarder>> all;
    for (Entry& e : entries_) {
        if (e.fwd) all.push_back(std::move(e.fwd));
    }
    entries_.clear();
    StopForwarders(std::move(all), stopBudgetMs_);
    PruneRetired();
}

int Engine::StragglerThreads() const {
    std::lock_guard<std::mutex> lock(mu_);
    PruneRetired();
    int n = 0;
    for (const auto& f : retired_) n += f->ThreadsAlive();
    return n;
}

}  // namespace pf
