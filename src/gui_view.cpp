#include "gui_view.h"

#include <cstdio>
#include <ctime>
#include <map>
#include <utility>

namespace pf {

namespace {

using Pair = std::pair<const char*, const char*>;  // zh, en

const char* Pick(const Pair& p, GuiLang lang) { return lang == GuiLang::Zh ? p.first : p.second; }

// app.js's CODES, key for key and word for word (test_gui_view compares the two).
const std::map<std::string, Pair>& Codes() {
    static const std::map<std::string, Pair> codes = {
        // rules.h -- rule_err
        {"bad_rule", {"规则格式不对", "The rule is malformed"}},
        {"bad_id", {"规则 ID 不对", "Bad rule id"}},
        {"bad_name", {"名称需为 1–64 个字符，且不含控制字符", "The name must be 1–64 characters, without control characters"}},
        {"bad_enabled", {"“启用”的值不对", "Bad value for “enabled”"}},
        {"bad_proto", {"协议只能是 TCP 或 UDP", "The protocol must be TCP or UDP"}},
        {"bad_listen_addr", {"监听地址必须是 IPv4 地址", "The listen address must be an IPv4 address"}},
        {"listen_addr_not_local", {"监听地址不是本机的地址", "The listen address is not an address of this computer"}},
        {"bad_listen_port", {"监听端口需在 1–65535 之间", "The listen port must be 1–65535"}},
        {"bad_host", {"远端主机需为 IPv4、IPv6 地址或域名", "The remote host must be an IPv4 or IPv6 address or a host name"}},
        {"bad_remote_port", {"远端端口需在 1–65535 之间", "The remote port must be 1–65535"}},
        {"bad_egress", {"出口设置不对", "Bad egress"}},
        {"bad_node_id", {"节点 ID 不对", "Bad node id"}},
        {"bad_limits", {"最大连接数需在 1–1024，UDP 空闲超时需在 5–3600 秒", "Max connections must be 1–1024 and the UDP idle timeout 5–3600 s"}},
        {"bad_lan_ack", {"局域网确认的值不对", "Bad value for the LAN acknowledgement"}},
        {"lan_ack_required", {"监听在非回环地址上，需先勾选局域网风险确认", "Listening beyond this computer needs the LAN warning acknowledged"}},
        {"loop", {"这条规则会转发回它自己的监听端口", "The rule would forward to its own listener"}},
        {"too_many_rules", {"最多 64 条规则", "At most 64 rules"}},
        {"duplicate_id", {"规则 ID 重复", "Two rules share an id"}},
        {"listen_conflict", {"已有启用的规则在同一协议和端口上监听", "Another enabled rule listens on this protocol and port"}},
        {"bad_document", {"规则文件结构不对", "The rules file has the wrong structure"}},
        {"bad_version", {"规则文件版本不受支持", "Unsupported rules file version"}},
        // rule_store.h -- store_err
        {"bad_data_dir", {"数据目录不可用", "The data directory is unusable"}},
        {"io_error", {"读写文件失败", "A file could not be read or written"}},
        {"rng_failed", {"系统随机数生成失败", "The system random number generator failed"}},
        {"too_large", {"规则文件超过 256 KB", "The rules file is larger than 256 KB"}},
        {"bad_json", {"规则文件不是合法的 JSON", "The rules file is not valid JSON"}},
        {"store_locked", {"规则文件未能正常读取，暂不能保存更改", "The rules file was not read cleanly, so nothing can be saved"}},
        // forward_common.h -- rule_status
        {"listening", {"监听中", "Listening"}},
        {"disabled", {"已停用", "Disabled"}},
        {"stopped", {"已停止", "Stopped"}},
        {"invalid", {"规则无效", "Invalid rule"}},
        {"not_supported", {"不支持", "Not supported"}},
        // forward_common.h -- fwd_err
        {"resolve_failed", {"远端域名解析失败", "The remote host name could not be resolved"}},
        {"connect_failed", {"连接远端失败", "The remote host could not be reached"}},
        {"connection_limit", {"达到连接数上限", "The connection limit was reached"}},
        {"bind_failed", {"无法监听该端口", "Cannot listen on this port"}},
        {"internal_error", {"内部错误", "Internal error"}},
        {"session_limit", {"达到 UDP 会话上限", "The UDP session limit was reached"}},
        {"remote_reset", {"UDP 会话被远端或中继关闭", "The UDP session was closed by the relay"}},
        // tunnel_client.h -- tunnel_err
        {"needs_ghost", {"需要 Ghost（独立运行时不可用）", "Needs Ghost (not available standalone)"}},
        {"permission_missing", {"未授予 upstream.connect 权限", "upstream.connect was not granted"}},
        {"tunnel_limit", {"同时建立的隧道太多", "Too many tunnels at once"}},
        {"adopt_failed", {"无法接收 Ghost 交来的连接", "The connection Ghost handed over could not be taken"}},
        // ghost_api.h -- api_err
        {"ghost_unavailable", {"Ghost 已不再接受本插件的令牌", "Ghost no longer accepts this plugin's token"}},
        {"ghost_unreachable", {"连不上 Ghost", "Ghost could not be reached"}},
        {"bad_response", {"Ghost 的答复无法识别", "Ghost's answer could not be understood"}},
        {"rate_limited", {"请求过于频繁", "Too many requests"}},
        {"permission_denied", {"权限被拒绝", "Permission denied"}},
        {"cancelled", {"已取消", "Cancelled"}},
        // Ghost's upstream.tunnel codes (spec-errors.md section 9)
        {"invalid_json", {"请求格式不对", "Malformed request"}},
        {"bad_target", {"Ghost 不接受这个目标地址", "Ghost does not accept this destination"}},
        {"upstream_not_found", {"找不到这个上游节点", "The upstream node does not exist"}},
        {"upstream_invalid", {"上游节点的地址不可用", "The upstream node's address is unusable"}},
        {"upstream_udp_unavailable", {"该节点的 UDP 中继不可用", "The node's UDP relay is unavailable"}},
        {"upstream_unreachable", {"连不上上游节点", "The upstream node could not be reached"}},
        {"upstream_timeout", {"上游节点握手超时", "The upstream node timed out"}},
        {"upstream_auth_failed", {"上游节点拒绝了凭据", "The upstream node refused the credentials"}},
        {"upstream_refused", {"上游节点拒绝了这个目的地", "The upstream node refused the destination"}},
        {"plugin_not_running", {"Ghost 尚未登记本插件在运行", "Ghost has not registered this plugin as running yet"}},
        {"tunnel_unsupported", {"Ghost 无法为本插件建立隧道", "Ghost cannot build tunnels for this plugin"}},
        {"tunnel_failed", {"Ghost 未能建立隧道", "Ghost failed to build the tunnel"}},
        {"tunnel_unavailable", {"Ghost 的隧道功能不可用", "Ghost's tunnels are unavailable"}},
        // ui_server.h -- ui_err (the window does not use HTTP; kept so that every code reads)
        {"bad_request", {"请求格式不对", "Malformed request"}},
        {"bad_host_header", {"请求的主机名不对", "Wrong host name in the request"}},
        {"forbidden_origin", {"请求来源不被接受", "The request's origin is not accepted"}},
        {"bad_content_type", {"请求内容类型不对", "Wrong request content type"}},
        {"not_found", {"找不到", "Not found"}},
        {"method_not_allowed", {"不支持的请求方法", "Method not allowed"}},
        {"request_timeout", {"请求超时", "The request timed out"}},
        {"length_required", {"请求缺少长度", "The request has no length"}},
        {"payload_too_large", {"请求过大", "The request is too large"}},
        {"headers_too_large", {"请求头过大", "The request headers are too large"}},
        {"busy", {"连接太多，请稍后再试", "Too many connections; try again"}},
        // app.h -- app_err
        {"bad_body", {"请求内容不是 JSON 对象", "The request body is not a JSON object"}},
        {"rule_not_found", {"找不到这条规则", "The rule does not exist"}},
        {"quit_not_allowed", {"在 Ghost 中运行时由 Ghost 负责停止", "Inside Ghost, Ghost stops the plugin"}},
        {"starting", {"正在启动", "Starting"}},
        {"stopping", {"正在停止", "Stopping"}},
    };
    return codes;
}

// "{a}" -> value, for every pair.
std::string Fill(std::string s, const std::vector<std::pair<const char*, std::string>>& vars) {
    for (const auto& v : vars) {
        const std::string key = std::string("{") + v.first + "}";
        size_t at = 0;
        while ((at = s.find(key, at)) != std::string::npos) {
            s.replace(at, key.size(), v.second);
            at += v.second.size();
        }
    }
    return s;
}

std::string Str(const json& obj, const char* key) {
    std::string s;
    JsonGetString(obj, key, &s);
    return s;
}

bool Bool(const json& obj, const char* key) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    return it != obj.end() && it->is_boolean() && it->get<bool>();
}

uint64_t U64(const json& obj, const char* key) {
    long long v = 0;
    return JsonGetInt64(obj, key, &v) && v > 0 ? static_cast<uint64_t>(v) : 0;
}

const json& Obj(const json& obj, const char* key) {
    static const json empty = json::object();
    if (!obj.is_object()) return empty;
    auto it = obj.find(key);
    return it != obj.end() && it->is_object() ? *it : empty;
}

// A port or a limit as the page shows it: the integer, or "" when absent.
std::string IntText(const json& obj, const char* key) {
    long long v = 0;
    return JsonGetInt64(obj, key, &v) ? std::to_string(v) : std::string();
}

std::string LocalTime(uint64_t unixMs) {
    const std::time_t t = static_cast<std::time_t>(unixMs / 1000);
    std::tm tm{};
#ifdef _WIN32
    if (localtime_s(&tm, &t) != 0) return std::string();
#else
    if (!localtime_r(&t, &tm)) return std::string();
#endif
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm) == 0) return std::string();
    return buf;
}

std::string EgressText(const json& egress, GuiLang lang) {
    const std::string kind = Str(egress, "kind");
    if (kind == "active") return Pick({"Ghost 激活节点", "Ghost active node"}, lang);
    if (kind == "node") return Pick({"节点：", "Node: "}, lang) + Str(egress, "nodeId");
    return Pick({"直连", "Direct"}, lang);
}

int StatusKind(const std::string& status) {
    if (status == "listening") return 0;
    if (status == "disabled" || status == "stopped") return 1;
    return 2;
}

std::string Trim(const std::string& s) {
    const char* ws = " \t\r\n";
    const size_t b = s.find_first_not_of(ws);
    if (b == std::string::npos) return std::string();
    const size_t e = s.find_last_not_of(ws);
    return s.substr(b, e - b + 1);
}

// The page's num(): an integer when the field holds one, else the field's text.
json NumberField(const std::string& raw) {
    const std::string t = Trim(raw);
    if (t.empty() || t.size() > 18) return json(t);
    for (char c : t) {
        if (c < '0' || c > '9') return json(t);
    }
    return json(std::stoll(t));  // at most 18 digits: always fits
}

}  // namespace

GuiLang GuiLangFromTag(const std::string& tag) {
    return tag.size() >= 2 && (tag[0] == 'z' || tag[0] == 'Z') && (tag[1] == 'h' || tag[1] == 'H') ? GuiLang::Zh
                                                                                                     : GuiLang::En;
}

std::string GuiCodeText(const std::string& code, GuiLang lang) {
    auto it = Codes().find(code);
    return it == Codes().end() ? code : Pick(it->second, lang);
}

std::vector<std::string> GuiKnownCodes() {
    std::vector<std::string> out;
    for (const auto& kv : Codes()) out.push_back(kv.first);
    return out;
}

std::string GuiFormatBytes(uint64_t n) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    if (n < 1024) return std::to_string(n) + " B";
    double v = static_cast<double>(n);
    int i = 0;
    while (v >= 1024 && i < 4) {
        v /= 1024;
        ++i;
    }
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.1f %s", v, units[i]);
    return buf;
}

GuiView BuildGuiView(const json& state, GuiLang lang) {
    GuiView v;
    v.canQuit = Bool(state, "canQuit");

    const json& store = Obj(state, "store");
    if (Bool(store, "corrupt")) {
        const std::string code = GuiCodeText(Str(store, "code"), lang);
        const std::string file = Str(store, "corruptFile");
        v.banners.push_back(
            {file.empty() ? Fill(Pick({"规则文件无效（{c}），且未能另存；在问题解决前不会保存任何更改。",
                                       "The rules file is invalid ({c}) and could not be moved aside; nothing will "
                                       "be saved until that is fixed."},
                                      lang),
                                 {{"c", code}})
                          : Fill(Pick({"规则文件无效（{c}），已另存为 {f}，本次以空规则启动。",
                                       "The rules file was invalid ({c}); it was kept as {f} and the plugin started "
                                       "with no rules."},
                                      lang),
                                 {{"c", code}, {"f", file}}),
             true});
    } else if (Bool(store, "locked")) {
        v.banners.push_back({Fill(Pick({"规则文件未能读取（{c}）；在能读取之前不会保存任何更改。",
                                        "The rules file could not be read ({c}); nothing will be saved until it can."},
                                       lang),
                                  {{"c", GuiCodeText(Str(store, "code"), lang)}}),
                             true});
    }
    if (!Bool(state, "hosted")) {
        v.banners.push_back({Pick({"独立运行，未连接 Ghost：只有直连规则会运行，经 Ghost 节点的规则不会监听。",
                                   "Running standalone, without Ghost: only direct rules run; rules through Ghost "
                                   "nodes do not listen."},
                                  lang),
                             false});
    }

    auto rulesIt = state.is_object() ? state.find("rules") : state.end();
    if (!state.is_object() || rulesIt == state.end() || !rulesIt->is_array()) return v;
    for (const json& r : *rulesIt) {
        if (!r.is_object()) continue;
        GuiRuleRow row;
        row.id = Str(r, "id");
        row.enabled = Bool(r, "enabled");
        row.name = Str(r, "name");
        const std::string proto = Str(r, "proto");
        row.proto = proto == "udp" ? "UDP" : proto == "tcp" ? "TCP" : proto;
        const json& listen = Obj(r, "listen");
        const json& remote = Obj(r, "remote");
        std::string host = Str(remote, "host");
        // An IPv6 literal is written in brackets before its port, so that "::1:80" is not
        // read as one address.
        if (host.find(':') != std::string::npos) host = "[" + host + "]";
        row.route = Str(listen, "addr") + ":" + IntText(listen, "port") + "  →  " + host + ":" + IntText(remote, "port");
        row.egress = EgressText(Obj(r, "egress"), lang);
        const std::string status = Str(r, "status");
        row.status = GuiCodeText(status, lang);
        const std::string detail = Str(r, "detail");
        row.statusDetail = detail.empty() ? std::string() : GuiCodeText(detail, lang);
        row.statusKind = StatusKind(status);

        const json& st = Obj(r, "stats");
        if (proto == "udp") {
            row.conns = Fill(Pick({"{s} 会话", "{s} sessions"}, lang), {{"s", std::to_string(U64(st, "udpSessions"))}});
            const uint64_t dropped = U64(st, "droppedDatagrams");
            if (dropped) {
                row.connsSub = Fill(Pick({"丢弃 {d} 个数据报", "{d} datagrams dropped"}, lang), {{"d", std::to_string(dropped)}});
            }
        } else {
            row.conns = Fill(Pick({"{a} 活动 / {t} 累计", "{a} active / {t} total"}, lang),
                             {{"a", std::to_string(U64(st, "activeConnections"))},
                              {"t", std::to_string(U64(st, "totalConnections"))}});
            const uint64_t rejected = U64(st, "rejectedConnections");
            if (rejected) {
                row.connsSub = Fill(Pick({"拒绝 {r}", "{r} rejected"}, lang), {{"r", std::to_string(rejected)}});
            }
        }
        row.up = GuiFormatBytes(U64(st, "bytesUp"));
        row.down = GuiFormatBytes(U64(st, "bytesDown"));
        const json& le = Obj(st, "lastError");
        const std::string leCode = Str(le, "code");
        if (!leCode.empty()) {
            row.lastError = GuiCodeText(leCode, lang);
            const uint64_t count = U64(le, "count");
            if (count > 1) row.lastError += " × " + std::to_string(count);
            const uint64_t at = U64(le, "at");
            if (at) row.lastErrorAt = LocalTime(at);
        }
        v.rows.push_back(std::move(row));
    }
    return v;
}

std::vector<GuiChoice> GuiListenChoices(const json& localAddrs, const std::string& current, GuiLang lang) {
    std::vector<GuiChoice> out;
    out.push_back({"127.0.0.1", Pick({"127.0.0.1（仅本机）", "127.0.0.1 (this computer only)"}, lang)});
    out.push_back({"0.0.0.0", Pick({"0.0.0.0（所有网卡）", "0.0.0.0 (every network adapter)"}, lang)});
    bool found = current.empty() || current == "127.0.0.1" || current == "0.0.0.0";
    if (localAddrs.is_array()) {
        for (const json& a : localAddrs) {
            if (!a.is_string()) continue;
            const std::string s = a.get<std::string>();
            if (s == "127.0.0.1" || s == "0.0.0.0") continue;
            out.push_back({s, s});
            if (s == current) found = true;
        }
    }
    if (!found) {
        out.push_back({current, current + " " + Pick({"（本机已没有这个地址）", "(no longer an address of this computer)"}, lang)});
    }
    return out;
}

std::vector<GuiChoice> GuiEgressChoices(const json& egress, GuiLang lang) {
    std::vector<GuiChoice> out;
    out.push_back({"direct", Pick({"直连", "Direct"}, lang)});
    const std::string kind = Str(egress, "kind");
    const char* needs = Pick({"（需要 Ghost）", "(needs Ghost)"}, lang);
    if (kind == "active") {
        out.push_back({"active", std::string(Pick({"跟随 Ghost 当前激活节点", "Follow Ghost's active node"}, lang)) + " " + needs});
    } else if (kind == "node") {
        const std::string id = Str(egress, "nodeId");
        out.push_back({"node:" + id, Pick({"节点：", "Node: "}, lang) + id + " " + needs});
    }
    return out;
}

GuiForm GuiFormFromRule(const json* rule) {
    GuiForm f;
    if (!rule || !rule->is_object()) {
        f.listenAddr = "127.0.0.1";
        f.egress = "direct";
        f.maxConnections = "128";
        f.udpIdleSec = "60";
        return f;
    }
    const json& r = *rule;
    f.name = Str(r, "name");
    f.udp = Str(r, "proto") == "udp";
    const json& listen = Obj(r, "listen");
    const json& remote = Obj(r, "remote");
    f.listenAddr = Str(listen, "addr");
    if (f.listenAddr.empty()) f.listenAddr = "127.0.0.1";
    f.listenPort = IntText(listen, "port");
    f.remoteHost = Str(remote, "host");
    f.remotePort = IntText(remote, "port");
    const json& egress = Obj(r, "egress");
    const std::string kind = Str(egress, "kind");
    f.egress = kind == "active" ? "active" : kind == "node" ? "node:" + Str(egress, "nodeId") : "direct";
    const json& limits = Obj(r, "limits");
    f.maxConnections = IntText(limits, "maxConnections");
    if (f.maxConnections.empty()) f.maxConnections = "128";
    f.udpIdleSec = IntText(limits, "udpIdleSec");
    if (f.udpIdleSec.empty()) f.udpIdleSec = "60";
    // "enabled" absent means enabled (the page's r.enabled !== false).
    auto en = r.find("enabled");
    f.enabled = en == r.end() || !en->is_boolean() || en->get<bool>();
    f.lanAck = Bool(r, "lanAck");
    return f;
}

json GuiFormToRule(const GuiForm& form) {
    json egress = json::object();
    if (form.egress == "active") {
        egress["kind"] = "active";
    } else if (form.egress.compare(0, 5, "node:") == 0) {
        egress["kind"] = "node";
        egress["nodeId"] = form.egress.substr(5);
    } else {
        egress["kind"] = "direct";
    }
    json j = json::object();
    j["name"] = form.name;
    j["enabled"] = form.enabled;
    j["proto"] = form.udp ? "udp" : "tcp";
    j["listen"] = json{{"addr", form.listenAddr}, {"port", NumberField(form.listenPort)}};
    j["remote"] = json{{"host", Trim(form.remoteHost)}, {"port", NumberField(form.remotePort)}};
    j["egress"] = std::move(egress);
    j["limits"] = json{{"maxConnections", NumberField(form.maxConnections)}, {"udpIdleSec", NumberField(form.udpIdleSec)}};
    j["lanAck"] = form.listenAddr != "127.0.0.1" && form.lanAck;
    return j;
}

}  // namespace pf
