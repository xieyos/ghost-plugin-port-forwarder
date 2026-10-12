// What the native window shows, worked out from the same JSON the page reads (app.h): the
// window is one more client of App::Handle, so every write is judged by the same code as the
// page's and the window holds no rule logic of its own -- only text.
//
// Everything here is plain C++ (no Slint, no Win32 beyond the clock), so that it can be
// tested without a window; gui.cpp copies the result into the window's models.
#pragma once

#include "json_util.h"

#include <cstdint>
#include <string>
#include <vector>

namespace pf {

enum class GuiLang { Zh, En };

// The language of the window: Chinese when the user's UI language is Chinese, else English
// (the page does the same with navigator.language).
GuiLang GuiLangFromTag(const std::string& tag);

// The text for a code the plugin answers with (app.js's CODES table, same wording). An
// unknown code is shown as it is.
std::string GuiCodeText(const std::string& code, GuiLang lang);
// Every code GuiCodeText knows, for the test that keeps it level with the page.
std::vector<std::string> GuiKnownCodes();

// "1.5 KB": the page's formatBytes.
std::string GuiFormatBytes(uint64_t n);

// A rule as one row of the list.
struct GuiRuleRow {
    std::string id;
    bool enabled = false;
    std::string name;
    std::string proto;   // "TCP" / "UDP"
    std::string route;   // "127.0.0.1:8080 -> example.com:80"
    std::string egress;  // "Direct", "Ghost active node", "Node: <id>"
    std::string status;  // the status code as text
    std::string statusDetail;
    int statusKind = 0;  // 0 listening, 1 idle (disabled, stopped), 2 a problem
    std::string conns;
    std::string connsSub;
    std::string up;    // "1.5 KB"
    std::string down;
    std::string lastError;  // "" when none
    std::string lastErrorAt;
};

struct GuiBanner {
    std::string text;
    bool error = false;
};

struct GuiView {
    std::vector<GuiBanner> banners;
    std::vector<GuiRuleRow> rows;
    bool canQuit = false;
};

// api/state's body as the window shows it. Missing or mistyped fields read as empty: the
// state comes from this process, but the window must not throw on it either way.
GuiView BuildGuiView(const json& state, GuiLang lang);

// One entry of a drop-down: what is sent, and what is shown.
struct GuiChoice {
    std::string value;
    std::string label;
};

// The listen addresses to offer: loopback, any, then this machine's (api/state localAddrs).
// A current address that is none of them stays on the list, marked as gone (the page's
// fillListenAddrs).
std::vector<GuiChoice> GuiListenChoices(const json& localAddrs, const std::string& current, GuiLang lang);

// The egresses to offer standalone: direct, and the rule's own egress when it is not direct
// (marked as needing Ghost) so that editing a rule's name does not quietly make it direct.
// Values: "direct", "active", "node:<id>".
std::vector<GuiChoice> GuiEgressChoices(const json& egress, GuiLang lang);

// The editor's fields as typed.
struct GuiForm {
    std::string name;
    bool udp = false;
    std::string listenAddr;
    std::string listenPort;
    std::string remoteHost;
    std::string remotePort;
    std::string egress;  // a GuiChoice value
    std::string maxConnections;
    std::string udpIdleSec;
    bool enabled = true;
    bool lanAck = false;
};

// The form a rule fills (a new rule: rule is null).
GuiForm GuiFormFromRule(const json* rule);

// The body of POST api/rules[/<id>]. A number field that is not an integer is sent as its
// text, so that the plugin answers with that field's own error code (the page's num()).
json GuiFormToRule(const GuiForm& form);

}  // namespace pf
