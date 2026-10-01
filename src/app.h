// The application: the rules file, the engine that runs the rules, and the page's API.
//
// The page talks only to this process (spec-manifest.md 5: the iframe is another origin than
// Ghost and never sees a Ghost token); this process talks to Ghost.
//
// Routes, all under the UI server's /<prefix>/ (ui_server.h has the transport checks):
//
//   GET  ""                      index.html     GET app.js, app.css: the page
//   GET  api/state               rules with status and counters, mode, store state
//   GET  api/nodes[?refresh=1]   Ghost's upstream nodes (standalone: none, code needs_ghost)
//   POST api/rules               a new rule (any id in the body is ignored; one is drawn here)
//   POST api/rules/<id>          the whole rule, replaced
//   POST api/rules/<id>/enable | disable | delete
//   POST api/quit                standalone: exit; hosted: 403 -- the host owns our lifetime
//
// Every write is judged here, never trusted from the page: ValidateRuleChange against this
// machine's addresses as they are now (a new or moved listen address must be one of them; a
// rule that is only enabled, disabled or renamed keeps the stored check), then ValidateSet
// on the whole new list, then RuleStore::Save. Only after the file is written is the engine
// re-applied, so what runs is always what is on disk. Writes are serialized (one
// read-modify-save-apply at a time).
//
// Errors answer {"error":"<code>"} (and "ruleId" when a set check names a rule):
//   400  a rule_err code, bad_body (not a JSON object)
//   404  rule_not_found, not_found
//   405  method_not_allowed
//   403  quit_not_allowed (hosted)
//   409  store_locked -- the rules file could not be read cleanly at start (see
//        rule_store.h) and nothing will be written until it can; Conflict, because the
//        request is fine and the state of the store is what refuses it
//   500  io_error, rng_failed, bad_data_dir
//   503  starting (rules not loaded yet), stopping
#pragma once

#include "engine.h"
#include "forward_common.h"
#include "rule_store.h"
#include "rules.h"
#include "tunnel_client.h"
#include "tunnel_source.h"
#include "ui_assets.h"
#include "ui_server.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace pf {

namespace app_err {
constexpr const char* kBadBody = "bad_body";                  // 400: the body is not a JSON object
constexpr const char* kRuleNotFound = "rule_not_found";       // 404
constexpr const char* kQuitNotAllowed = "quit_not_allowed";   // 403: hosted
constexpr const char* kStarting = "starting";                 // 503
constexpr const char* kStopping = "stopping";                 // 503
}  // namespace app_err

struct AppOptions {
    bool hosted = false;
    std::wstring dataDir;
    std::string lang;        // the handshake's; "" standalone (the page uses the browser's)
    bool permitted = false;  // upstream.connect granted
    // Both null standalone: via-node rules show needs_ghost, api/nodes is empty.
    std::shared_ptr<TunnelClient> nodes;
    std::shared_ptr<TunnelSource> tunnel;
    LogFn log;  // may be empty
    // This machine's IPv4 addresses for listen.addr. Null = EnumerateLocalIPv4.
    std::function<std::vector<std::string>()> localAddrs;
    // Standalone: asked to exit (POST api/quit). Null = refused (hosted).
    std::function<void()> onQuit;
    // The page's files. Null = LoadEmbeddedUiAsset.
    std::function<bool(const std::string&, UiAsset*)> assets;
    Clock* clock = nullptr;
    DWORD engineStopBudgetMs = kEngineStopBudgetMs;
};

class App {
public:
    explicit App(AppOptions opts);
    ~App();  // Stop()
    App(const App&) = delete;
    App& operator=(const App&) = delete;

    // RuleStore::Load. After this the API answers (before it: 503 starting). The caller logs
    // the result.
    LoadResult LoadRules();
    // Engine::Apply of the loaded rules.
    void StartEngine();

    // The UI server's handler.
    UiResponse Handle(const UiRequest& req);

    // Refuses writes from now on, then Engine::Stop (bounded by engineStopBudgetMs).
    void Stop();

    std::vector<Rule> Rules() const;
    std::vector<RuleStatus> Snapshot() const;

private:
    UiResponse State();
    UiResponse Nodes(const std::string& query);
    UiResponse AddRule(const std::string& body);
    UiResponse ReplaceRule(const std::string& id, const std::string& body);
    UiResponse SetEnabled(const std::string& id, bool enabled);
    UiResponse DeleteRule(const std::string& id);
    UiResponse Quit();
    UiResponse Asset(const std::string& name);

    // ValidateSet + Save + Apply, under writeMu_. `what` and `rule` name the change for the log.
    UiResponse Commit(std::vector<Rule> next, const char* what, const Rule& rule);
    // 503 when the API cannot write now, else an empty status (0).
    int RefuseWrite(UiResponse* out) const;
    std::vector<std::string> LocalAddrs(bool fresh);
    void Log(LogLevel level, const std::string& text, const LogFields& fields = {}) const;

    AppOptions opts_;
    RuleStore store_;
    std::unique_ptr<Engine> engine_;

    std::mutex writeMu_;
    mutable std::mutex stateMu_;
    std::vector<Rule> rules_;
    bool loaded_ = false;
    LoadResult load_;
    std::vector<std::string> addrCache_;
    uint64_t addrAt_ = 0;
    bool haveAddrs_ = false;
    std::atomic<bool> stopping_{false};
};

}  // namespace pf
