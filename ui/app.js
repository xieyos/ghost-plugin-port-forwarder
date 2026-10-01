// Port Forwarder management page.
//
// Rules of this file (a source-level test enforces the first two):
//   * Text reaches the DOM only through textContent / element creation -- never as markup.
//     Rule names, host names and node names are typed by people and other programs.
//   * Only relative URLs ("api/state"): the page lives under a random path prefix and must
//     never name an origin.
//   * No alert/confirm/prompt and no popups: inside Ghost the page is a sandboxed iframe
//     (scripts, same-origin and forms only), where those do nothing. Confirmation is in-page.
//   * The page judges nothing for real: every write is validated again by the plugin.
"use strict";

(function () {
  // ---- Strings -------------------------------------------------------------------------
  var STRINGS = {
    title: ["端口转发", "Port Forwarder"],
    add_rule: ["新增规则", "Add rule"],
    stop: ["停止", "Stop"],
    stop_confirm: ["再点一次以停止", "Click again to stop"],
    stopped: ["已停止，可以关闭此页面。", "Stopped. You can close this page."],
    mode_hosted: ["Ghost 插件", "Ghost plugin"],
    mode_standalone: ["独立运行", "Standalone"],
    new_rule: ["新增规则", "New rule"],
    edit_rule: ["编辑规则", "Edit rule"],
    f_name: ["名称", "Name"],
    f_proto: ["协议", "Protocol"],
    f_listen_addr: ["监听地址", "Listen address"],
    f_listen_port: ["监听端口", "Listen port"],
    f_remote_host: ["远端主机", "Remote host"],
    f_remote_port: ["远端端口", "Remote port"],
    f_egress: ["出口", "Egress"],
    f_max_conn: ["最大连接数", "Max connections"],
    f_udp_idle: ["UDP 空闲超时（秒）", "UDP idle timeout (s)"],
    f_enabled: ["启用", "Enabled"],
    addr_loopback: ["127.0.0.1（仅本机）", "127.0.0.1 (this computer only)"],
    addr_any: ["0.0.0.0（所有网卡）", "0.0.0.0 (every network adapter)"],
    addr_gone: ["（本机已没有这个地址）", "(no longer an address of this computer)"],
    lan_warning: [
      "监听在非回环地址上：局域网内任何人都能经这个端口访问远端地址；出口经 Ghost 节点时，还能借用你的上游代理。Windows 防火墙可能会弹出提示，请只允许专用网络。插件每次升级后路径会变，防火墙可能会再次提示。",
      "This rule listens beyond this computer: anyone on your local network can reach the remote address through this port and, when the egress is a Ghost node, use your upstream proxy. Windows Firewall may ask about it; allow private networks only. The plugin's path changes with every upgrade, so Windows may ask again."
    ],
    lan_ack: ["我已了解上述风险", "I understand"],
    save: ["保存", "Save"],
    cancel: ["取消", "Cancel"],
    edit: ["编辑", "Edit"],
    enable: ["启用", "Enable"],
    disable: ["停用", "Disable"],
    "delete": ["删除", "Delete"],
    delete_confirm: ["确定删除？", "Delete this rule?"],
    yes: ["删除", "Delete"],
    no: ["取消", "Cancel"],
    col_name: ["名称", "Name"],
    col_proto: ["协议", "Protocol"],
    col_route: ["监听 → 远端", "Listen → Remote"],
    col_egress: ["出口", "Egress"],
    col_status: ["状态", "Status"],
    col_conns: ["连接", "Connections"],
    col_traffic: ["流量", "Traffic"],
    col_error: ["最近错误", "Last error"],
    no_rules: ["还没有规则。", "No rules yet."],
    eg_direct: ["直连", "Direct"],
    eg_active: ["跟随 Ghost 当前激活节点", "Follow Ghost's active node"],
    eg_active_short: ["Ghost 激活节点", "Ghost active node"],
    eg_node: ["节点：", "Node: "],
    eg_invalid: ["（不可用）", "(unusable)"],
    eg_no_udp: ["（不支持 UDP）", "(no UDP)"],
    eg_missing: ["（找不到该节点）", "(node not found)"],
    eg_needs_ghost: ["（需要 Ghost）", "(needs Ghost)"],
    eg_hint_udp: [
      "这个节点不支持 UDP：经它的 UDP 规则会失败（不会改走直连）。",
      "This node has no UDP relay: a UDP rule through it will fail (it never falls back to direct)."
    ],
    eg_hint_udp_name: [
      "部分节点的 UDP 中继不支持以域名作为目的地：如果一直收不到回包，请把远端主机改成 IP 地址。",
      "Some nodes cannot relay UDP to a host name: if no replies ever arrive, use the remote host's IP address instead."
    ],
    eg_hint_invalid: ["这个节点当前不可用：经它的连接会失败（不会改走直连）。",
      "This node is unusable right now: connections through it will fail (never direct instead)."],
    eg_hint_ghost: ["经 Ghost 节点的规则只在 Ghost 中运行时有效。", "Rules through Ghost nodes only run inside Ghost."],
    conns_tcp: ["{a} 活动 / {t} 累计", "{a} active / {t} total"],
    conns_rejected: ["拒绝 {r}", "{r} rejected"],
    conns_udp: ["{s} 会话", "{s} sessions"],
    conns_dropped: ["丢弃 {d} 个数据报", "{d} datagrams dropped"],
    times: ["× {n}", "× {n}"],
    b_standalone: [
      "独立运行，未连接 Ghost：只有直连规则会运行，经 Ghost 节点的规则不会监听。",
      "Running standalone, without Ghost: only direct rules run; rules through Ghost nodes do not listen."
    ],
    b_no_permission: [
      "Ghost 未授予 upstream.connect 权限：经节点的规则不会运行。",
      "Ghost did not grant upstream.connect: rules through nodes do not run."
    ],
    b_ghost_gone: [
      "Ghost 已不再接受本插件的令牌：经节点的规则已停止。请在 Ghost 中重新启用插件。",
      "Ghost no longer accepts this plugin's token: rules through nodes have stopped. Re-enable the plugin in Ghost."
    ],
    b_corrupt: [
      "规则文件无效（{c}），已另存为 {f}，本次以空规则启动。",
      "The rules file was invalid ({c}); it was kept as {f} and the plugin started with no rules."
    ],
    b_corrupt_kept: [
      "规则文件无效（{c}），且未能另存；在问题解决前不会保存任何更改。",
      "The rules file is invalid ({c}) and could not be moved aside; nothing will be saved until that is fixed."
    ],
    b_locked: [
      "规则文件未能读取（{c}）；在能读取之前不会保存任何更改。",
      "The rules file could not be read ({c}); nothing will be saved until it can."
    ],
    b_starting: ["正在启动…", "Starting…"],
    b_offline: ["插件没有响应。", "The plugin is not responding."],
    saved: ["已保存", "Saved"],
    unknown_error: ["错误：", "Error: "]
  };

  // Every code the plugin (or Ghost, through it) can show, by origin. Unknown codes are
  // shown as they are.
  var CODES = {
    // rules.h -- rule_err
    bad_rule: ["规则格式不对", "The rule is malformed"],
    bad_id: ["规则 ID 不对", "Bad rule id"],
    bad_name: ["名称需为 1–64 个字符，且不含控制字符", "The name must be 1–64 characters, without control characters"],
    bad_enabled: ["“启用”的值不对", "Bad value for “enabled”"],
    bad_proto: ["协议只能是 TCP 或 UDP", "The protocol must be TCP or UDP"],
    bad_listen_addr: ["监听地址必须是 IPv4 地址", "The listen address must be an IPv4 address"],
    listen_addr_not_local: ["监听地址不是本机的地址", "The listen address is not an address of this computer"],
    bad_listen_port: ["监听端口需在 1–65535 之间", "The listen port must be 1–65535"],
    bad_host: ["远端主机需为 IPv4、IPv6 地址或域名", "The remote host must be an IPv4 or IPv6 address or a host name"],
    bad_remote_port: ["远端端口需在 1–65535 之间", "The remote port must be 1–65535"],
    bad_egress: ["出口设置不对", "Bad egress"],
    bad_node_id: ["节点 ID 不对", "Bad node id"],
    bad_limits: ["最大连接数需在 1–1024，UDP 空闲超时需在 5–3600 秒", "Max connections must be 1–1024 and the UDP idle timeout 5–3600 s"],
    bad_lan_ack: ["局域网确认的值不对", "Bad value for the LAN acknowledgement"],
    lan_ack_required: ["监听在非回环地址上，需先勾选局域网风险确认", "Listening beyond this computer needs the LAN warning acknowledged"],
    loop: ["这条规则会转发回它自己的监听端口", "The rule would forward to its own listener"],
    too_many_rules: ["最多 64 条规则", "At most 64 rules"],
    duplicate_id: ["规则 ID 重复", "Two rules share an id"],
    listen_conflict: ["已有启用的规则在同一协议和端口上监听", "Another enabled rule listens on this protocol and port"],
    bad_document: ["规则文件结构不对", "The rules file has the wrong structure"],
    bad_version: ["规则文件版本不受支持", "Unsupported rules file version"],
    // rule_store.h -- store_err
    bad_data_dir: ["数据目录不可用", "The data directory is unusable"],
    io_error: ["读写文件失败", "A file could not be read or written"],
    rng_failed: ["系统随机数生成失败", "The system random number generator failed"],
    too_large: ["规则文件超过 256 KB", "The rules file is larger than 256 KB"],
    bad_json: ["规则文件不是合法的 JSON", "The rules file is not valid JSON"],
    store_locked: ["规则文件未能正常读取，暂不能保存更改", "The rules file was not read cleanly, so nothing can be saved"],
    // forward_common.h -- rule_status
    listening: ["监听中", "Listening"],
    disabled: ["已停用", "Disabled"],
    stopped: ["已停止", "Stopped"],
    invalid: ["规则无效", "Invalid rule"],
    not_supported: ["不支持", "Not supported"],
    // forward_common.h -- fwd_err
    resolve_failed: ["远端域名解析失败", "The remote host name could not be resolved"],
    connect_failed: ["连接远端失败", "The remote host could not be reached"],
    connection_limit: ["达到连接数上限", "The connection limit was reached"],
    bind_failed: ["无法监听该端口", "Cannot listen on this port"],
    internal_error: ["内部错误", "Internal error"],
    session_limit: ["达到 UDP 会话上限", "The UDP session limit was reached"],
    remote_reset: ["UDP 会话被远端或中继关闭", "The UDP session was closed by the relay"],
    // tunnel_client.h -- tunnel_err
    needs_ghost: ["需要 Ghost（独立运行时不可用）", "Needs Ghost (not available standalone)"],
    permission_missing: ["未授予 upstream.connect 权限", "upstream.connect was not granted"],
    tunnel_limit: ["同时建立的隧道太多", "Too many tunnels at once"],
    adopt_failed: ["无法接收 Ghost 交来的连接", "The connection Ghost handed over could not be taken"],
    // ghost_api.h -- api_err
    ghost_unavailable: ["Ghost 已不再接受本插件的令牌", "Ghost no longer accepts this plugin's token"],
    ghost_unreachable: ["连不上 Ghost", "Ghost could not be reached"],
    bad_response: ["Ghost 的答复无法识别", "Ghost's answer could not be understood"],
    rate_limited: ["请求过于频繁", "Too many requests"],
    permission_denied: ["权限被拒绝", "Permission denied"],
    cancelled: ["已取消", "Cancelled"],
    // Ghost's upstream.tunnel codes (spec-errors.md section 9)
    invalid_json: ["请求格式不对", "Malformed request"],
    bad_target: ["Ghost 不接受这个目标地址", "Ghost does not accept this destination"],
    upstream_not_found: ["找不到这个上游节点", "The upstream node does not exist"],
    upstream_invalid: ["上游节点的地址不可用", "The upstream node's address is unusable"],
    upstream_udp_unavailable: ["该节点的 UDP 中继不可用", "The node's UDP relay is unavailable"],
    upstream_unreachable: ["连不上上游节点", "The upstream node could not be reached"],
    upstream_timeout: ["上游节点握手超时", "The upstream node timed out"],
    upstream_auth_failed: ["上游节点拒绝了凭据", "The upstream node refused the credentials"],
    upstream_refused: ["上游节点拒绝了这个目的地", "The upstream node refused the destination"],
    plugin_not_running: ["Ghost 尚未登记本插件在运行", "Ghost has not registered this plugin as running yet"],
    tunnel_unsupported: ["Ghost 无法为本插件建立隧道", "Ghost cannot build tunnels for this plugin"],
    tunnel_failed: ["Ghost 未能建立隧道", "Ghost failed to build the tunnel"],
    tunnel_unavailable: ["Ghost 的隧道功能不可用", "Ghost's tunnels are unavailable"],
    // ui_server.h -- ui_err
    bad_request: ["请求格式不对", "Malformed request"],
    bad_host: ["请求的主机名不对", "Wrong host name in the request"],
    forbidden_origin: ["请求来源不被接受", "The request's origin is not accepted"],
    bad_content_type: ["请求内容类型不对", "Wrong request content type"],
    not_found: ["找不到", "Not found"],
    method_not_allowed: ["不支持的请求方法", "Method not allowed"],
    request_timeout: ["请求超时", "The request timed out"],
    length_required: ["请求缺少长度", "The request has no length"],
    payload_too_large: ["请求过大", "The request is too large"],
    headers_too_large: ["请求头过大", "The request headers are too large"],
    busy: ["连接太多，请稍后再试", "Too many connections; try again"],
    // app.h -- app_err
    bad_body: ["请求内容不是 JSON 对象", "The request body is not a JSON object"],
    rule_not_found: ["找不到这条规则", "The rule does not exist"],
    quit_not_allowed: ["在 Ghost 中运行时由 Ghost 负责停止", "Inside Ghost, Ghost stops the plugin"],
    starting: ["正在启动", "Starting"],
    stopping: ["正在停止", "Stopping"]
  };

  var lang = 1;  // 0 = zh, 1 = en
  function pickLang(tag) {
    lang = /^zh/i.test(tag || "") ? 0 : 1;
    document.documentElement.lang = lang === 0 ? "zh" : "en";
  }
  function t(key, vars) {
    var e = STRINGS[key];
    var s = e ? e[lang] : key;
    if (vars) {
      Object.keys(vars).forEach(function (k) { s = s.split("{" + k + "}").join(String(vars[k])); });
    }
    return s;
  }
  function codeText(code) {
    if (!code) return "";
    var e = Object.prototype.hasOwnProperty.call(CODES, code) ? CODES[code] : null;
    return e ? e[lang] : code;
  }

  // ---- DOM helpers ------------------------------------------------------------------------
  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined && text !== null) e.textContent = String(text);
    return e;
  }
  function button(text, cls, onClick) {
    var b = el("button", cls, text);
    b.type = "button";
    b.addEventListener("click", onClick);
    return b;
  }
  function applyStaticStrings() {
    document.querySelectorAll("[data-i18n]").forEach(function (n) {
      n.textContent = t(n.getAttribute("data-i18n"));
    });
    document.title = t("title");
  }

  var toastTimer = 0;
  function toast(text, isError) {
    var n = $("toast");
    n.textContent = text;
    n.className = isError ? "toast error" : "toast";
    n.hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { n.hidden = true; }, isError ? 6000 : 2500);
  }

  function formatBytes(n) {
    n = Number(n) || 0;
    var units = ["B", "KB", "MB", "GB", "TB"];
    var i = 0;
    while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
    return (i === 0 ? String(n) : n.toFixed(1)) + " " + units[i];
  }

  // ---- Talking to the plugin ---------------------------------------------------------------
  function getJson(path) {
    return fetch(path, { cache: "no-store", credentials: "same-origin" }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        return { status: r.status, body: body || {} };
      });
    });
  }
  function postJson(path, obj) {
    return fetch(path, {
      method: "POST",
      cache: "no-store",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(obj || {})
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (body) {
        return { status: r.status, body: body || {} };
      });
    });
  }
  function errorOf(res) {
    var code = res && res.body && typeof res.body.error === "string" ? res.body.error : "";
    return code ? codeText(code) : t("unknown_error") + (res ? res.status : "?");
  }

  // ---- State --------------------------------------------------------------------------------
  var state = null;          // the last api/state answer
  var nodes = { list: [], active: null, code: "" };
  var langChosen = false;
  var pendingDelete = {};    // rule id -> true while its inline confirmation shows
  var rows = {};             // rule id -> { tr, cells, actionKey }
  var editing = null;        // null, or { id: "" for a new rule, rule: the stored rule }
  var stopped = false;
  var quitArmed = 0;

  function ghostReady() { return state && state.hosted && state.ghost === ""; }

  function nodeName(id) {
    for (var i = 0; i < nodes.list.length; i++) if (nodes.list[i].id === id) return nodes.list[i].name;
    return id;
  }

  function egressText(r) {
    var e = r.egress || {};
    if (e.kind === "active") return t("eg_active_short");
    if (e.kind === "node") return t("eg_node") + nodeName(e.nodeId);
    return t("eg_direct");
  }

  function statusClass(st) {
    if (st === "listening") return "st-listening";
    if (st === "disabled" || st === "stopped") return "st-idle";
    return "st-problem";
  }

  function renderBanners() {
    var box = $("banners");
    box.replaceChildren();
    function add(text, isError) { box.appendChild(el("div", isError ? "banner error" : "banner", text)); }
    if (!state) return;
    var s = state.store || {};
    if (s.corrupt) {
      add(s.corruptFile ? t("b_corrupt", { c: codeText(s.code), f: s.corruptFile })
                        : t("b_corrupt_kept", { c: codeText(s.code) }), true);
    } else if (s.locked) {
      add(t("b_locked", { c: codeText(s.code) }), true);
    }
    if (!state.hosted) add(t("b_standalone"), false);
    else if (!state.permitted) add(t("b_no_permission"), false);
    else if (state.ghost === "ghost_unavailable") add(t("b_ghost_gone"), true);
  }

  function makeRow(id) {
    var tr = el("tr");
    var cells = {};
    ["name", "proto", "route", "egress", "status", "conns", "traffic", "error", "actions"].forEach(function (k) {
      var td = el("td");
      if (k === "conns" || k === "traffic") td.className = "num";
      if (k === "actions") td.className = "actions-cell";
      cells[k] = td;
      tr.appendChild(td);
    });
    tr.setAttribute("data-rule-id", id);
    return { tr: tr, cells: cells, actionKey: "" };
  }

  function setCell(td, main, sub, cls) {
    td.replaceChildren();
    var m = el("span", cls || "", main);
    td.appendChild(m);
    if (sub) td.appendChild(el("span", "sub", sub));
  }

  // The rule with `id` in the latest api/state answer, or null. The row buttons below are
  // rebuilt only when their own key changes, so they hold nothing but the id: a button that
  // closed over the rule object of its last rebuild would open the editor on a stale copy,
  // and saving that form would silently revert whatever changed since.
  function currentRule(id) {
    var list = (state && state.rules) || [];
    for (var i = 0; i < list.length; i++) if (list[i].id === id) return list[i];
    return null;
  }

  function editRule(id) {
    var cur = currentRule(id);
    if (cur) openEditor(cur);
  }

  function toggleRule(id) {
    var cur = currentRule(id);
    if (cur) write("api/rules/" + id + (cur.enabled ? "/disable" : "/enable"), {});
  }

  function renderActions(row, r) {
    var id = r.id;
    var key = (r.enabled ? "1" : "0") + (pendingDelete[id] ? "d" : "") + lang;
    if (row.actionKey === key) return;
    row.actionKey = key;
    var td = row.cells.actions;
    td.replaceChildren();
    if (pendingDelete[id]) {
      td.appendChild(el("span", "muted", t("delete_confirm")));
      td.appendChild(button(t("yes"), "small danger", function () {
        delete pendingDelete[id];
        write("api/rules/" + id + "/delete", {});
      }));
      td.appendChild(button(t("no"), "small", function () {
        delete pendingDelete[id];
        render();
      }));
      return;
    }
    td.appendChild(button(t("edit"), "small", function () { editRule(id); }));
    td.appendChild(button(r.enabled ? t("disable") : t("enable"), "small", function () { toggleRule(id); }));
    td.appendChild(button(t("delete"), "small danger", function () {
      pendingDelete[id] = true;
      render();
    }));
  }

  function renderRules() {
    var tbody = $("ruleRows");
    var list = (state && state.rules) || [];
    var seen = {};
    list.forEach(function (r, i) {
      seen[r.id] = true;
      var row = rows[r.id];
      if (!row) { row = makeRow(r.id); rows[r.id] = row; }
      var c = row.cells;
      setCell(c.name, r.name);
      setCell(c.proto, String(r.proto || "").toUpperCase());
      var listen = r.listen || {}, remote = r.remote || {};
      setCell(c.route, listen.addr + ":" + listen.port + " → " + remote.host + ":" + remote.port);
      setCell(c.egress, egressText(r));
      var detail = r.detail ? codeText(r.detail) : "";
      setCell(c.status, codeText(r.status), detail, statusClass(r.status));
      var st = r.stats || {};
      if (r.proto === "udp") {
        setCell(c.conns, t("conns_udp", { s: st.udpSessions || 0 }),
                st.droppedDatagrams ? t("conns_dropped", { d: st.droppedDatagrams }) : "");
      } else {
        setCell(c.conns, t("conns_tcp", { a: st.activeConnections || 0, t: st.totalConnections || 0 }),
                st.rejectedConnections ? t("conns_rejected", { r: st.rejectedConnections }) : "");
      }
      setCell(c.traffic, "↑ " + formatBytes(st.bytesUp), "↓ " + formatBytes(st.bytesDown));
      var le = st.lastError;
      if (le && le.code) {
        var when = le.at ? new Date(Number(le.at)).toLocaleString() : "";
        setCell(c.error, codeText(le.code) + (le.count > 1 ? " " + t("times", { n: le.count }) : ""), when,
                "st-problem");
      } else {
        setCell(c.error, "");
      }
      renderActions(row, r);
      if (tbody.children[i] !== row.tr) tbody.insertBefore(row.tr, tbody.children[i] || null);
    });
    Object.keys(rows).forEach(function (id) {
      if (!seen[id]) {
        if (rows[id].tr.parentNode) rows[id].tr.parentNode.removeChild(rows[id].tr);
        delete rows[id];
        delete pendingDelete[id];
      }
    });
    $("empty").hidden = list.length !== 0;
  }

  function render() {
    if (!state) return;
    $("mode").textContent = state.hosted ? t("mode_hosted") : t("mode_standalone");
    $("quitBtn").hidden = !state.canQuit || stopped;
    renderBanners();
    renderRules();
  }

  // ---- Polling ---------------------------------------------------------------------------------
  function showOnly(bannerKey, isError) {
    var box = $("banners");
    box.replaceChildren(el("div", isError ? "banner error" : "banner", t(bannerKey)));
  }

  function poll() {
    if (stopped) return;
    getJson("api/state").then(function (res) {
      if (res.status === 503 && res.body.error === "starting") {
        showOnly("b_starting", false);
        return;
      }
      if (res.status !== 200) {
        showOnly("b_offline", true);
        return;
      }
      state = res.body;
      if (!langChosen) {
        pickLang(typeof state.lang === "string" && state.lang ? state.lang : navigator.language);
        langChosen = true;
        applyStaticStrings();
      }
      render();
    }).catch(function () {
      showOnly("b_offline", true);
    }).then(function () {
      if (!stopped) setTimeout(poll, 2000);
    });
  }

  var nodesAt = 0;
  function refreshNodes(force) {
    if (!ghostReady()) {
      nodes = { list: [], active: null, code: state ? state.ghost : "" };
      return Promise.resolve();
    }
    if (!force && Date.now() - nodesAt < 10000) return Promise.resolve();
    nodesAt = Date.now();
    return getJson("api/nodes" + (force ? "?refresh=1" : "")).then(function (res) {
      var b = res.body || {};
      nodes = {
        list: Array.isArray(b.nodes) ? b.nodes : [],
        active: typeof b.active === "string" ? b.active : null,
        code: typeof b.code === "string" ? b.code : ""
      };
    }).catch(function () {});
  }

  // ---- Writes ------------------------------------------------------------------------------------
  function write(path, body) {
    return postJson(path, body).then(function (res) {
      if (res.status === 200) {
        toast(t("saved"), false);
      } else {
        toast(errorOf(res), true);
      }
      return res;
    }).catch(function () {
      toast(t("b_offline"), true);
      return { status: 0, body: {} };
    }).then(function (res) {
      return getJson("api/state").then(function (s) {
        if (s.status === 200) { state = s.body; render(); }
        return res;
      }, function () { return res; });
    });
  }

  // ---- The editor ----------------------------------------------------------------------------------
  function option(value, text, disabled) {
    var o = el("option", "", text);
    o.value = value;
    o.disabled = !!disabled;
    return o;
  }

  function fillListenAddrs(current) {
    var sel = $("fListenAddr");
    sel.replaceChildren();
    sel.appendChild(option("127.0.0.1", t("addr_loopback")));
    sel.appendChild(option("0.0.0.0", t("addr_any")));
    var addrs = (state && Array.isArray(state.localAddrs)) ? state.localAddrs : [];
    var found = current === "127.0.0.1" || current === "0.0.0.0";
    addrs.forEach(function (a) {
      if (typeof a !== "string") return;
      sel.appendChild(option(a, a));
      if (a === current) found = true;
    });
    if (current && !found) sel.appendChild(option(current, current + " " + t("addr_gone")));
    sel.value = current || "127.0.0.1";
  }

  function egressValue(r) {
    var e = (r && r.egress) || { kind: "direct" };
    if (e.kind === "active") return "active";
    if (e.kind === "node") return "node:" + e.nodeId;
    return "direct";
  }

  function fillEgress(current) {
    var sel = $("fEgress");
    var proto = $("fProto").value;
    var ready = ghostReady();
    sel.replaceChildren();
    sel.appendChild(option("direct", t("eg_direct")));
    var activeText = t("eg_active");
    if (ready && nodes.active) activeText += " (" + nodeName(nodes.active) + ")";
    if (!ready) activeText += " " + t("eg_needs_ghost");
    // An option that cannot work is disabled, always -- also when it is what the rule says.
    // That option stays selected (a script may select a disabled option) with a hint under
    // the list: switching the rule to "direct" behind the user's back would be worse. Once
    // the user picks something else, it cannot be picked again.
    sel.appendChild(option("active", activeText, !ready));
    var found = current === "direct" || current === "active";
    nodes.list.forEach(function (n) {
      if (!n || typeof n.id !== "string") return;
      var v = "node:" + n.id;
      var text = t("eg_node") + n.name + " (" + n.type + ")";
      var off = false;
      if (!n.valid) { text += " " + t("eg_invalid"); off = true; }
      else if (proto === "udp" && !n.udp) { text += " " + t("eg_no_udp"); off = true; }
      if (v === current) found = true;
      sel.appendChild(option(v, text, off));
    });
    if (!found && current.indexOf("node:") === 0) {
      sel.appendChild(option(current, t("eg_node") + current.slice(5) + " " +
                             (ready ? t("eg_missing") : t("eg_needs_ghost")), true));
    }
    sel.value = current;
    updateEgressHint();
  }

  function updateEgressHint() {
    var hint = $("egressHint");
    var v = $("fEgress").value;
    var text = "";
    if (v !== "direct" && !ghostReady()) {
      text = t("eg_hint_ghost");
    } else if (v === "active" || v.indexOf("node:") === 0) {
      // "Follow the active node" is judged by the node that is active now.
      var id = v === "active" ? nodes.active : v.slice(5);
      nodes.list.forEach(function (n) {
        if (n.id !== id) return;
        if (!n.valid) text = t("eg_hint_invalid");
        else if ($("fProto").value === "udp" && !n.udp) text = t("eg_hint_udp");
      });
    }
    // spec-plugin-api.md section 10.4: some SOCKS5 relays do not take a host name (ATYP 3)
    // as a UDP destination. Nothing fails visibly -- replies just never come.
    if (text === "" && v !== "direct" && $("fProto").value === "udp" && isHostName($("fRemoteHost").value.trim())) {
      text = t("eg_hint_udp_name");
    }
    hint.textContent = text;
    hint.hidden = text === "";
  }

  // Neither an IPv4 nor an IPv6 literal (the server judges the full grammar).
  function isHostName(h) {
    return h !== "" && h.indexOf(":") < 0 && !/^[0-9.]+$/.test(h);
  }

  function updateProtoRows() {
    var udp = $("fProto").value === "udp";
    $("fMaxConnRow").hidden = udp;
    $("fUdpIdleRow").hidden = !udp;
  }

  function updateLanWarn() {
    $("lanWarn").hidden = $("fListenAddr").value === "127.0.0.1";
  }

  function openEditor(rule) {
    editing = { id: rule ? rule.id : "", rule: rule || null };
    var r = rule || {
      name: "", enabled: true, proto: "tcp",
      listen: { addr: "127.0.0.1", port: "" }, remote: { host: "", port: "" },
      egress: { kind: "direct" }, limits: { maxConnections: 128, udpIdleSec: 60 }, lanAck: false
    };
    $("editorTitle").textContent = rule ? t("edit_rule") : t("new_rule");
    $("fName").value = r.name || "";
    $("fProto").value = r.proto === "udp" ? "udp" : "tcp";
    fillListenAddrs((r.listen || {}).addr || "127.0.0.1");
    $("fListenPort").value = (r.listen || {}).port || "";
    $("fRemoteHost").value = (r.remote || {}).host || "";
    $("fRemotePort").value = (r.remote || {}).port || "";
    var limits = r.limits || {};
    $("fMaxConn").value = limits.maxConnections || 128;
    $("fUdpIdle").value = limits.udpIdleSec || 60;
    $("fEnabled").checked = r.enabled !== false;
    $("fLanAck").checked = !!r.lanAck;
    $("formError").hidden = true;
    updateProtoRows();
    updateLanWarn();
    var current = egressValue(r);
    fillEgress(current);
    $("editor").hidden = false;
    $("fName").focus();
    refreshNodes(true).then(function () {
      if (editing && $("editor").hidden === false) fillEgress($("fEgress").value || current);
    });
  }

  function closeEditor() {
    editing = null;
    $("editor").hidden = true;
  }

  // A number field: the integer it holds, or its raw text so that the plugin answers with the
  // field's own error code.
  function num(id) {
    var raw = $(id).value.trim();
    var n = Number(raw);
    return raw !== "" && Number.isInteger(n) ? n : raw;
  }

  function formRule() {
    var eg = $("fEgress").value;
    var egress = { kind: "direct" };
    if (eg === "active") egress = { kind: "active" };
    else if (eg.indexOf("node:") === 0) egress = { kind: "node", nodeId: eg.slice(5) };
    return {
      name: $("fName").value,
      enabled: $("fEnabled").checked,
      proto: $("fProto").value,
      listen: { addr: $("fListenAddr").value, port: num("fListenPort") },
      remote: { host: $("fRemoteHost").value.trim(), port: num("fRemotePort") },
      egress: egress,
      limits: { maxConnections: num("fMaxConn"), udpIdleSec: num("fUdpIdle") },
      lanAck: $("fListenAddr").value !== "127.0.0.1" && $("fLanAck").checked
    };
  }

  function showFormError(text) {
    var p = $("formError");
    p.textContent = text;
    p.hidden = false;
  }

  function submitForm(ev) {
    ev.preventDefault();
    if (!editing) return;
    var rule = formRule();
    if (rule.listen.addr !== "127.0.0.1" && !rule.lanAck) {
      showFormError(codeText("lan_ack_required"));
      return;
    }
    var path = editing.id ? "api/rules/" + editing.id : "api/rules";
    postJson(path, rule).then(function (res) {
      if (res.status === 200) {
        closeEditor();
        toast(t("saved"), false);
        return getJson("api/state").then(function (s) {
          if (s.status === 200) { state = s.body; render(); }
        });
      }
      showFormError(errorOf(res));
    }).catch(function () {
      showFormError(t("b_offline"));
    });
  }

  // ---- Stop (standalone only) ----------------------------------------------------------------
  function onQuit() {
    var b = $("quitBtn");
    if (!quitArmed) {
      b.textContent = t("stop_confirm");
      quitArmed = setTimeout(function () { quitArmed = 0; b.textContent = t("stop"); }, 3000);
      return;
    }
    clearTimeout(quitArmed);
    quitArmed = 0;
    postJson("api/quit", {}).then(function (res) {
      if (res.status === 200) {
        stopped = true;
        document.body.classList.add("stopped");
        b.hidden = true;
        $("addBtn").disabled = true;
        closeEditor();
        showOnly("stopped", false);
      } else {
        toast(errorOf(res), true);
      }
    }).catch(function () { toast(t("b_offline"), true); });
  }

  // ---- Start --------------------------------------------------------------------------------------
  function start() {
    pickLang(navigator.language);
    applyStaticStrings();
    $("addBtn").addEventListener("click", function () { openEditor(null); });
    $("cancelBtn").addEventListener("click", closeEditor);
    $("quitBtn").addEventListener("click", onQuit);
    $("ruleForm").addEventListener("submit", submitForm);
    $("fProto").addEventListener("change", function () {
      updateProtoRows();
      fillEgress($("fEgress").value);
      updateEgressHint();
    });
    $("fListenAddr").addEventListener("change", updateLanWarn);
    $("fEgress").addEventListener("change", updateEgressHint);
    $("fRemoteHost").addEventListener("input", updateEgressHint);
    poll();
    setInterval(function () { if (state && !stopped) refreshNodes(false).then(render); }, 10000);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start);
  else start();
})();
