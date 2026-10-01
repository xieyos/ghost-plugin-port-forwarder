#include "app.h"

#include "build_info.h"
#include "json_util.h"
#include "local_addrs.h"
#include "util_str.h"

#include <exception>
#include <utility>

namespace pf {

namespace {

constexpr uint64_t kAddrCacheMs = 10000;

UiResponse JsonResponse(int status, const json& body) {
    UiResponse r;
    r.status = status;
    r.body = DumpSafe(body);
    return r;
}

UiResponse Err(int status, const std::string& code, const std::string& ruleId = std::string()) {
    json j = json::object();
    j["error"] = code;
    if (!ruleId.empty()) j["ruleId"] = ruleId;
    return JsonResponse(status, j);
}

// The HTTP status for a code RuleStore::Save answers with (rule_err codes are 400).
int StatusForStoreCode(const std::string& code) {
    if (code == store_err::kStoreLocked) return 409;
    if (code == store_err::kIoError || code == store_err::kRngFailed || code == store_err::kBadDataDir) return 500;
    return 400;
}

const char* LoadStatusName(LoadStatus s) {
    switch (s) {
        case LoadStatus::Ok:
            return "ok";
        case LoadStatus::Missing:
            return "missing";
        case LoadStatus::Corrupt:
            return "corrupt";
        case LoadStatus::Unreadable:
        default:
            return "unreadable";
    }
}

json StatsToJson(const StatsSnapshot& s) {
    json j = json::object();
    j["activeConnections"] = s.activeConnections;
    j["totalConnections"] = s.totalConnections;
    j["rejectedConnections"] = s.rejectedConnections;
    j["bytesUp"] = s.bytesUp;
    j["bytesDown"] = s.bytesDown;
    j["udpSessions"] = s.udpSessions;
    j["droppedDatagrams"] = s.droppedDatagrams;
    if (s.lastError.code.empty()) {
        j["lastError"] = nullptr;
    } else {
        j["lastError"] = json{{"code", s.lastError.code}, {"at", s.lastError.atUnixMs}, {"count", s.lastError.count}};
    }
    return j;
}

// The file name only: the page has no use for the full path.
std::string FileNameOf(const std::wstring& path) {
    const size_t slash = path.find_last_of(L"\\/");
    return WideToUtf8(slash == std::wstring::npos ? path : path.substr(slash + 1));
}

}  // namespace

App::App(AppOptions opts) : opts_(std::move(opts)), store_(opts_.dataDir) {
    EngineOptions eo;
    eo.tunnel = opts_.tunnel;
    eo.log = opts_.log;
    eo.clock = opts_.clock;
    eo.stopBudgetMs = opts_.engineStopBudgetMs;
    engine_ = std::make_unique<Engine>(std::move(eo));
}

App::~App() { Stop(); }

void App::Log(LogLevel level, const std::string& text, const LogFields& fields) const {
    if (!opts_.log) return;
    try {
        opts_.log(level, text, fields);
    } catch (...) {
    }
}

LoadResult App::LoadRules() {
    LoadResult r = store_.Load();
    std::lock_guard<std::mutex> lock(stateMu_);
    rules_ = r.rules;
    load_ = r;
    load_.rules.clear();
    loaded_ = true;
    return r;
}

void App::StartEngine() {
    std::lock_guard<std::mutex> w(writeMu_);
    if (stopping_.load()) return;
    engine_->Apply(Rules());
}

void App::Stop() {
    stopping_.store(true);
    engine_->Stop();
}

std::vector<Rule> App::Rules() const {
    std::lock_guard<std::mutex> lock(stateMu_);
    return rules_;
}

std::vector<RuleStatus> App::Snapshot() const { return engine_->Snapshot(); }

std::vector<std::string> App::LocalAddrs(bool fresh) {
    const uint64_t now = GetTickCount64();
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        if (!fresh && haveAddrs_ && now - addrAt_ < kAddrCacheMs) return addrCache_;
    }
    std::vector<std::string> addrs = opts_.localAddrs ? opts_.localAddrs() : EnumerateLocalIPv4();
    std::lock_guard<std::mutex> lock(stateMu_);
    addrCache_ = addrs;
    addrAt_ = now;
    haveAddrs_ = true;
    return addrs;
}

int App::RefuseWrite(UiResponse* out) const {
    if (stopping_.load()) {
        *out = Err(503, app_err::kStopping);
        return out->status;
    }
    std::lock_guard<std::mutex> lock(stateMu_);
    if (!loaded_) {
        *out = Err(503, app_err::kStarting);
        return out->status;
    }
    return 0;
}

UiResponse App::Handle(const UiRequest& req) {
    const std::string& p = req.path;
    const bool get = req.method == "GET";
    const bool post = req.method == "POST";

    if (p.empty() || p == "app.js" || p == "app.css") {
        if (!get) return Err(405, ui_err::kMethodNotAllowed);
        return Asset(p.empty() ? std::string("index.html") : p);
    }
    if (p.compare(0, 4, "api/") != 0) return Err(404, ui_err::kNotFound);

    if (p == "api/quit") {
        if (!post) return Err(405, ui_err::kMethodNotAllowed);
        return Quit();
    }
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        if (!loaded_) return Err(503, app_err::kStarting);
    }
    if (p == "api/state") {
        if (!get) return Err(405, ui_err::kMethodNotAllowed);
        return State();
    }
    if (p == "api/nodes") {
        if (!get) return Err(405, ui_err::kMethodNotAllowed);
        return Nodes(req.query);
    }
    if (p == "api/rules") {
        if (!post) return Err(405, ui_err::kMethodNotAllowed);
        return AddRule(req.body);
    }
    const std::string rulesPrefix = "api/rules/";
    if (p.compare(0, rulesPrefix.size(), rulesPrefix) == 0) {
        const std::string rest = p.substr(rulesPrefix.size());
        const size_t slash = rest.find('/');
        const std::string id = rest.substr(0, slash);
        const std::string action = slash == std::string::npos ? std::string() : rest.substr(slash + 1);
        if (!IsRuleIdShaped(id)) return Err(404, app_err::kRuleNotFound);
        if (slash != std::string::npos && action != "enable" && action != "disable" && action != "delete") {
            return Err(404, ui_err::kNotFound);
        }
        if (!post) return Err(405, ui_err::kMethodNotAllowed);
        if (slash == std::string::npos) return ReplaceRule(id, req.body);
        if (action == "delete") return DeleteRule(id);
        return SetEnabled(id, action == "enable");
    }
    return Err(404, ui_err::kNotFound);
}

UiResponse App::Asset(const std::string& name) {
    UiAsset a;
    const bool ok = opts_.assets ? opts_.assets(name, &a) : LoadEmbeddedUiAsset(name, &a);
    if (!ok) return Err(404, ui_err::kNotFound);
    UiResponse r;
    r.contentType = a.contentType;
    r.body = std::move(a.bytes);
    return r;
}

UiResponse App::State() {
    const std::vector<Rule> rules = Rules();
    const std::vector<RuleStatus> statuses = engine_->Snapshot();
    json out = json::object();
    out["version"] = PF_VERSION;
    out["hosted"] = opts_.hosted;
    out["lang"] = opts_.lang;
    out["permitted"] = opts_.permitted;
    std::string ghost = tunnel_err::kNeedsGhost;
    if (opts_.tunnel) {
        try {
            ghost = opts_.tunnel->Availability();
        } catch (...) {
            ghost = api_err::kGhostUnavailable;
        }
    }
    out["ghost"] = ghost;  // "" = tunnels can be requested
    out["canQuit"] = static_cast<bool>(opts_.onQuit);
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        json store = json::object();
        store["status"] = LoadStatusName(load_.status);
        store["code"] = load_.code;
        store["corrupt"] = load_.corrupt;
        store["corruptFile"] = FileNameOf(load_.corruptPath);
        store["locked"] = !store_.MayOverwrite();
        out["store"] = store;
    }
    json addrs = json::array();
    for (const std::string& a : LocalAddrs(false)) addrs.push_back(a);
    out["localAddrs"] = addrs;

    json list = json::array();
    for (const Rule& r : rules) {
        json j = RuleToJson(r);
        bool found = false;
        for (const RuleStatus& s : statuses) {
            if (s.id != r.id) continue;
            j["status"] = s.status;
            j["detail"] = s.detail;
            j["stats"] = StatsToJson(s.stats);
            found = true;
            break;
        }
        if (!found) {
            // Saved but not applied yet (a write is applying it right now).
            j["status"] = rule_status::kStopped;
            j["detail"] = "";
            j["stats"] = StatsToJson(StatsSnapshot());
        }
        list.push_back(std::move(j));
    }
    out["rules"] = list;
    return JsonResponse(200, out);
}

UiResponse App::Nodes(const std::string& query) {
    json out = json::object();
    json nodes = json::array();
    out["active"] = nullptr;
    if (!opts_.nodes) {
        out["code"] = tunnel_err::kNeedsGhost;
        out["nodes"] = nodes;
        return JsonResponse(200, out);
    }
    const NodeList list = opts_.nodes->ListNodes(query == "refresh=1");
    out["code"] = list.code;
    if (list.ok()) {
        if (list.hasActive) out["active"] = list.active;
        for (const NodeInfo& n : list.nodes) {
            nodes.push_back(json{{"id", n.id},       {"name", n.name},   {"type", n.type},
                                 {"active", n.active}, {"valid", n.valid}, {"udp", n.udp}});
        }
    }
    out["nodes"] = nodes;
    return JsonResponse(200, out);
}

UiResponse App::Commit(std::vector<Rule> next, const char* what, const Rule& rule) {
    std::string offending;
    std::string code = ValidateSet(next, &offending);
    if (!code.empty()) return Err(400, code, offending);
    std::string detail;
    if (!store_.Save(next, &code, &detail)) {
        if (StatusForStoreCode(code) != 400) {
            Log(LogLevel::Warn, "saving the rules failed: " + code + (detail.empty() ? "" : " (" + detail + ")"));
        }
        return Err(StatusForStoreCode(code), code);
    }
    {
        std::lock_guard<std::mutex> lock(stateMu_);
        rules_ = next;
    }
    Log(LogLevel::Info, std::string("rule ") + what + ": " + rule.name,
        {{"rule", rule.id}, {"proto", ProtoName(rule.proto)}, {"egress", EgressKindName(rule.egress)}});
    engine_->Apply(next);
    json ok = json::object();
    ok["ok"] = true;
    ok["id"] = rule.id;
    return JsonResponse(200, ok);
}

UiResponse App::AddRule(const std::string& body) {
    UiResponse refused;
    if (RefuseWrite(&refused)) return refused;
    const json j = ParseJsonNoThrow(body);
    if (!j.is_object()) return Err(400, app_err::kBadBody);
    Rule r;
    std::string code = ParseRule(j, &r);
    if (!code.empty()) return Err(400, code);
    r.id = NewRuleId();  // the page never chooses ids
    if (r.id.empty()) return Err(500, store_err::kRngFailed);

    std::lock_guard<std::mutex> w(writeMu_);
    if (RefuseWrite(&refused)) return refused;
    code = ValidateRuleChange(nullptr, r, LocalAddrs(true));
    if (!code.empty()) return Err(400, code);
    std::vector<Rule> next = Rules();
    next.push_back(r);
    return Commit(std::move(next), "added", r);
}

UiResponse App::ReplaceRule(const std::string& id, const std::string& body) {
    UiResponse refused;
    if (RefuseWrite(&refused)) return refused;
    const json j = ParseJsonNoThrow(body);
    if (!j.is_object()) return Err(400, app_err::kBadBody);
    Rule after;
    std::string code = ParseRule(j, &after);
    if (!code.empty()) return Err(400, code);
    after.id = id;  // the path names the rule; an id in the body is ignored

    std::lock_guard<std::mutex> w(writeMu_);
    if (RefuseWrite(&refused)) return refused;
    std::vector<Rule> next = Rules();
    for (Rule& r : next) {
        if (r.id != id) continue;
        code = ValidateRuleChange(&r, after, LocalAddrs(true));
        if (!code.empty()) return Err(400, code);
        r = after;
        return Commit(std::move(next), "changed", after);
    }
    return Err(404, app_err::kRuleNotFound);
}

UiResponse App::SetEnabled(const std::string& id, bool enabled) {
    UiResponse refused;
    if (RefuseWrite(&refused)) return refused;
    std::lock_guard<std::mutex> w(writeMu_);
    if (RefuseWrite(&refused)) return refused;
    std::vector<Rule> next = Rules();
    for (Rule& r : next) {
        if (r.id != id) continue;
        Rule after = r;
        after.enabled = enabled;
        // listen.addr is unchanged, so this is the stored check: a rule whose adapter address
        // went away can still be disabled (and enabling it just fails to bind).
        const std::string code = ValidateRuleChange(&r, after, LocalAddrs(true));
        if (!code.empty()) return Err(400, code);
        r = after;
        return Commit(std::move(next), enabled ? "enabled" : "disabled", after);
    }
    return Err(404, app_err::kRuleNotFound);
}

UiResponse App::DeleteRule(const std::string& id) {
    UiResponse refused;
    if (RefuseWrite(&refused)) return refused;
    std::lock_guard<std::mutex> w(writeMu_);
    if (RefuseWrite(&refused)) return refused;
    std::vector<Rule> next = Rules();
    for (size_t i = 0; i < next.size(); ++i) {
        if (next[i].id != id) continue;
        const Rule removed = next[i];
        next.erase(next.begin() + static_cast<std::ptrdiff_t>(i));
        return Commit(std::move(next), "removed", removed);
    }
    return Err(404, app_err::kRuleNotFound);
}

UiResponse App::Quit() {
    if (!opts_.onQuit) return Err(403, app_err::kQuitNotAllowed);
    try {
        opts_.onQuit();
    } catch (...) {
        return Err(500, ui_err::kInternalError);
    }
    json ok = json::object();
    ok["ok"] = true;
    return JsonResponse(200, ok);
}

}  // namespace pf
