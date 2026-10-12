// Unit: what the standalone window shows and sends (gui_view.h), without a window.
//
//   * The window can name every code the page can: each key of app.js's CODES table has its
//     own text in GuiCodeText (test_ui_source keeps that table level with the plugin's code
//     namespaces), in both languages. "bad_host" reads as the rule's error.
//   * api/state becomes rows and banners: routes (an IPv6 remote in brackets), egress,
//     statuses and their kind, TCP and UDP counters, the last error with its count; the
//     standalone banner, the damaged-rules-file banners. Mistyped fields read as empty.
//   * The editor: a rule's fields and the defaults of a new one; the body it sends (numbers
//     as integers, anything else as typed so that the plugin names the field; lanAck only off
//     loopback); the listen and egress choices (a vanished address and a via-node egress stay
//     on the list, marked).
//
// argv[1] = the ui directory (app.js).

#include "gui_view.h"
#include "test_support.h"

#include <cstdio>
#include <regex>
#include <set>
#include <string>
#include <vector>

using pf::GuiLang;
using pf::json;

namespace {

std::wstring g_ui;

std::string ReadAll(const std::wstring& path) {
    std::string text;
    FILE* f = nullptr;
    if (_wfopen_s(&f, path.c_str(), L"rb") != 0 || !f) return text;
    char buf[8192];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    fclose(f);
    return text;
}

// The keys of `var CODES = { ... };` in app.js.
std::vector<std::string> PageCodes(const std::string& js) {
    std::vector<std::string> out;
    const size_t b = js.find("var CODES = {");
    if (b == std::string::npos) return out;
    const size_t e = js.find("\n  };", b);
    if (e == std::string::npos) return out;
    const std::string body = js.substr(b, e - b);
    const std::regex key(R"re(\n\s+"?([a-z_]+)"?: \[)re");
    for (auto it = std::sregex_iterator(body.begin(), body.end(), key); it != std::sregex_iterator(); ++it) {
        out.push_back((*it)[1].str());
    }
    return out;
}

void CodesMatchThePage() {
    const std::vector<std::string> page = PageCodes(ReadAll(g_ui + L"\\app.js"));
    CHECK_MSG(page.size() > 50, "app.js's CODES table was read");
    const std::vector<std::string> known = pf::GuiKnownCodes();
    const std::set<std::string> knownSet(known.begin(), known.end());
    for (const std::string& code : page) {
        CHECK_MSG(knownSet.count(code) == 1, ("the window has no text for " + code).c_str());
        CHECK_MSG(pf::GuiCodeText(code, GuiLang::Zh) != code, ("no Chinese text for " + code).c_str());
        CHECK_MSG(pf::GuiCodeText(code, GuiLang::En) != code, ("no English text for " + code).c_str());
    }
    CHECK(pf::GuiCodeText("bad_host", GuiLang::En).find("remote host") != std::string::npos);
    CHECK(pf::GuiCodeText("listening", GuiLang::Zh) == "监听中");
    CHECK_MSG(pf::GuiCodeText("WSA error 10048", GuiLang::En) == "WSA error 10048", "an unknown code shows as is");
}

void Language() {
    CHECK(pf::GuiLangFromTag("zh-CN") == GuiLang::Zh);
    CHECK(pf::GuiLangFromTag("zh-Hant-TW") == GuiLang::Zh);
    CHECK(pf::GuiLangFromTag("ZH") == GuiLang::Zh);
    CHECK(pf::GuiLangFromTag("en-US") == GuiLang::En);
    CHECK(pf::GuiLangFromTag("") == GuiLang::En);
    CHECK(pf::GuiLangFromTag("z") == GuiLang::En);
}

void Bytes() {
    CHECK(pf::GuiFormatBytes(0) == "0 B");
    CHECK(pf::GuiFormatBytes(1023) == "1023 B");
    CHECK(pf::GuiFormatBytes(1536) == "1.5 KB");
    CHECK(pf::GuiFormatBytes(18874368) == "18.0 MB");
    CHECK(pf::GuiFormatBytes(5ULL * 1024 * 1024 * 1024 * 1024 * 1024) == "5120.0 TB");
}

json Stats(long long active, long long total, long long up, long long down, long long sessions) {
    return json{{"activeConnections", active}, {"totalConnections", total}, {"rejectedConnections", 0},
                {"bytesUp", up},             {"bytesDown", down},         {"udpSessions", sessions},
                {"droppedDatagrams", 0},     {"lastError", nullptr}};
}

json State() {
    json tcp = {{"id", "r_0000000000000001"},
                {"name", "rdp"},
                {"enabled", true},
                {"proto", "tcp"},
                {"listen", {{"addr", "127.0.0.1"}, {"port", 13389}}},
                {"remote", {{"host", "10.0.0.5"}, {"port", 3389}}},
                {"egress", {{"kind", "direct"}}},
                {"limits", {{"maxConnections", 128}, {"udpIdleSec", 60}}},
                {"lanAck", false},
                {"status", "listening"},
                {"detail", ""},
                {"stats", Stats(2, 57, 1536, 18874368, 0)}};
    tcp["stats"]["rejectedConnections"] = 4;
    tcp["stats"]["lastError"] = {{"code", "connect_failed"}, {"at", 1760262000000LL}, {"count", 3}};
    json udp = {{"id", "r_0000000000000002"},
                {"name", "dns"},
                {"enabled", true},
                {"proto", "udp"},
                {"listen", {{"addr", "0.0.0.0"}, {"port", 5353}}},
                {"remote", {{"host", "2001:db8::1"}, {"port", 53}}},
                {"egress", {{"kind", "node"}, {"nodeId", "hk-01"}}},
                {"limits", {{"maxConnections", 128}, {"udpIdleSec", 60}}},
                {"lanAck", true},
                {"status", "needs_ghost"},
                {"detail", ""},
                {"stats", Stats(0, 0, 0, 0, 3)}};
    udp["stats"]["droppedDatagrams"] = 7;
    json off = {{"id", "r_0000000000000003"}, {"name", "old"},     {"enabled", false},
                {"proto", "tcp"},             {"status", "disabled"}, {"egress", {{"kind", "active"}}}};
    return json{{"hosted", false},
                {"canQuit", true},
                {"store", {{"status", "ok"}, {"code", ""}, {"corrupt", false}, {"corruptFile", ""}, {"locked", false}}},
                {"localAddrs", {"192.168.1.8"}},
                {"rules", {tcp, udp, off, 42}}};
}

void ViewOfState() {
    const pf::GuiView v = pf::BuildGuiView(State(), GuiLang::En);
    CHECK(v.canQuit);
    CHECK(v.banners.size() == 1);
    if (v.banners.size() == 1) {
        CHECK(!v.banners[0].error);
        CHECK(v.banners[0].text.find("standalone") != std::string::npos);
    }
    CHECK_MSG(v.rows.size() == 3, "three rules (a non-object entry is skipped)");
    if (v.rows.size() != 3) return;

    const pf::GuiRuleRow& t = v.rows[0];
    CHECK(t.id == "r_0000000000000001" && t.name == "rdp" && t.enabled);
    CHECK(t.proto == "TCP");
    CHECK(t.route == "127.0.0.1:13389  →  10.0.0.5:3389");
    CHECK(t.egress == "Direct");
    CHECK(t.status == "Listening" && t.statusKind == 0 && t.statusDetail.empty());
    CHECK(t.conns == "2 active / 57 total");
    CHECK(t.connsSub == "4 rejected");
    CHECK(t.up == "1.5 KB" && t.down == "18.0 MB");
    CHECK(t.lastError == "The remote host could not be reached × 3");
    CHECK_MSG(t.lastErrorAt.size() == 19, ("a local time, YYYY-MM-DD HH:MM:SS: " + t.lastErrorAt).c_str());

    const pf::GuiRuleRow& u = v.rows[1];
    CHECK(u.proto == "UDP");
    CHECK_MSG(u.route == "0.0.0.0:5353  →  [2001:db8::1]:53", u.route.c_str());
    CHECK(u.egress == "Node: hk-01");
    CHECK(u.statusKind == 2);
    CHECK(u.status == "Needs Ghost (not available standalone)");
    CHECK(u.conns == "3 sessions" && u.connsSub == "7 datagrams dropped");
    CHECK(u.lastError.empty() && u.lastErrorAt.empty());

    const pf::GuiRuleRow& o = v.rows[2];
    CHECK(!o.enabled && o.statusKind == 1 && o.status == "Disabled");
    CHECK(o.egress == "Ghost active node");
    CHECK_MSG(o.route == ":  →  :", "missing listen and remote read as empty");
    CHECK(o.conns == "0 active / 0 total" && o.up == "0 B");

    const pf::GuiView zh = pf::BuildGuiView(State(), GuiLang::Zh);
    CHECK(zh.rows.size() == 3 && zh.rows[0].conns == "2 活动 / 57 累计" && zh.rows[0].egress == "直连");
}

void StoreBanners() {
    json s = State();
    s["store"] = {{"corrupt", true}, {"code", "bad_json"}, {"corruptFile", "rules.json.corrupt-20261012"}};
    pf::GuiView v = pf::BuildGuiView(s, GuiLang::En);
    CHECK(v.banners.size() == 2);
    if (v.banners.size() == 2) {
        CHECK(v.banners[0].error);
        CHECK(v.banners[0].text.find("rules.json.corrupt-20261012") != std::string::npos);
        CHECK(v.banners[0].text.find("not valid JSON") != std::string::npos);
    }
    s["store"] = {{"corrupt", true}, {"code", "bad_json"}, {"corruptFile", ""}};
    v = pf::BuildGuiView(s, GuiLang::En);
    CHECK(!v.banners.empty() && v.banners[0].text.find("could not be moved aside") != std::string::npos);
    s["store"] = {{"locked", true}, {"code", "io_error"}};
    v = pf::BuildGuiView(s, GuiLang::Zh);
    CHECK(!v.banners.empty() && v.banners[0].error && v.banners[0].text.find("读写文件失败") != std::string::npos);
    s["hosted"] = true;
    s["store"] = json::object();
    CHECK_MSG(pf::BuildGuiView(s, GuiLang::En).banners.empty(), "no standalone banner when hosted");

    CHECK_MSG(pf::BuildGuiView(json("not an object"), GuiLang::En).rows.empty(), "a non-object state shows nothing");
    CHECK(pf::BuildGuiView(json{{"rules", "x"}}, GuiLang::En).rows.empty());
}

void FormRoundTrip() {
    const pf::GuiForm fresh = pf::GuiFormFromRule(nullptr);
    CHECK(fresh.name.empty() && !fresh.udp && fresh.enabled && !fresh.lanAck);
    CHECK(fresh.listenAddr == "127.0.0.1" && fresh.egress == "direct");
    CHECK(fresh.maxConnections == "128" && fresh.udpIdleSec == "60");
    CHECK(fresh.listenPort.empty() && fresh.remotePort.empty());

    const json udp = State()["rules"][1];
    const pf::GuiForm f = pf::GuiFormFromRule(&udp);
    CHECK(f.name == "dns" && f.udp && f.enabled && f.lanAck);
    CHECK(f.listenAddr == "0.0.0.0" && f.listenPort == "5353");
    CHECK(f.remoteHost == "2001:db8::1" && f.remotePort == "53");
    CHECK(f.egress == "node:hk-01");

    const json body = pf::GuiFormToRule(f);
    CHECK(body["proto"] == "udp" && body["enabled"] == true && body["lanAck"] == true);
    CHECK(body["listen"]["addr"] == "0.0.0.0" && body["listen"]["port"] == 5353);
    CHECK(body["remote"]["port"].is_number_integer());
    CHECK(body["egress"] == json({{"kind", "node"}, {"nodeId", "hk-01"}}));
    CHECK(body["limits"]["maxConnections"] == 128 && body["limits"]["udpIdleSec"] == 60);
    CHECK_MSG(!body.contains("id"), "the body never names an id");

    pf::GuiForm typed = fresh;
    typed.name = " spaced ";
    typed.remoteHost = "  example.com ";
    typed.listenPort = " 8080 ";
    typed.remotePort = "80x";
    typed.maxConnections = "";
    typed.udpIdleSec = "-5";
    typed.lanAck = true;  // ticked, then the address went back to loopback
    const json b = pf::GuiFormToRule(typed);
    CHECK_MSG(b["name"] == " spaced ", "the name is sent as typed (the plugin judges it)");
    CHECK(b["remote"]["host"] == "example.com");
    CHECK(b["listen"]["port"] == 8080);
    CHECK_MSG(b["remote"]["port"] == "80x", "not an integer: sent as typed, so the plugin names the field");
    CHECK(b["limits"]["maxConnections"] == "");
    CHECK(b["limits"]["udpIdleSec"] == "-5");
    CHECK_MSG(b["lanAck"] == false, "lanAck only off loopback");
    CHECK(b["egress"] == json({{"kind", "direct"}}));
    typed.listenPort = "1234567890123456789";  // 19 digits: not taken as a number
    CHECK(pf::GuiFormToRule(typed)["listen"]["port"].is_string());
    typed.egress = "active";
    CHECK(pf::GuiFormToRule(typed)["egress"] == json({{"kind", "active"}}));
}

void Choices() {
    const json addrs = {"192.168.1.8", "127.0.0.1", 7};
    std::vector<pf::GuiChoice> c = pf::GuiListenChoices(addrs, "127.0.0.1", GuiLang::En);
    CHECK_MSG(c.size() == 3, "loopback, any, and the one other address once");
    if (c.size() == 3) {
        CHECK(c[0].value == "127.0.0.1" && c[1].value == "0.0.0.0" && c[2].value == "192.168.1.8");
        CHECK(c[2].label == "192.168.1.8");
    }
    c = pf::GuiListenChoices(addrs, "10.9.9.9", GuiLang::En);
    CHECK(c.size() == 4 && c.back().value == "10.9.9.9" &&
          c.back().label.find("no longer an address") != std::string::npos);
    c = pf::GuiListenChoices(json(), "", GuiLang::Zh);
    CHECK(c.size() == 2 && c[0].label == "127.0.0.1（仅本机）");

    std::vector<pf::GuiChoice> e = pf::GuiEgressChoices(json{{"kind", "direct"}}, GuiLang::En);
    CHECK_MSG(e.size() == 1 && e[0].value == "direct", "standalone, a new egress can only be direct");
    e = pf::GuiEgressChoices(json{{"kind", "active"}}, GuiLang::En);
    CHECK(e.size() == 2 && e[1].value == "active" && e[1].label.find("needs Ghost") != std::string::npos);
    e = pf::GuiEgressChoices(json{{"kind", "node"}, {"nodeId", "hk-01"}}, GuiLang::Zh);
    CHECK(e.size() == 2 && e[1].value == "node:hk-01" && e[1].label.find("需要 Ghost") != std::string::npos);
    CHECK(pf::GuiEgressChoices(json(), GuiLang::En).size() == 1);
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: test_gui_view <ui directory>\n");
        return 2;
    }
    g_ui = argv[1];
    for (auto& ch : g_ui)
        if (ch == L'/') ch = L'\\';
    CodesMatchThePage();
    Language();
    Bytes();
    ViewOfState();
    StoreBanners();
    FormRoundTrip();
    Choices();
    return pf_test::TestExitCode();
}
