// Unit, source level: what the page's files must never contain, and that the page can name
// every code the plugin answers with.
//
//   * app.js puts text into the DOM only as text: no innerHTML, outerHTML,
//     insertAdjacentHTML, document.write, eval, new Function, string timers, or style
//     attributes (the CSP would block those anyway; the rule is that they are never written).
//     No alert/confirm/prompt/window.open: inside Ghost's sandboxed iframe they do nothing.
//   * Only relative URLs: no "http:"/"https:"/"//" origin anywhere in the page's files, and
//     no fetch of an absolute path.
//   * index.html has no inline script, no inline event handler and no style attribute (the
//     CSP, default-src 'self', would refuse them -- the page would silently not work).
//   * Every code in the plugin's code namespaces (rule_err, store_err, fwd_err, rule_status,
//     tunnel_err, api_err, ui_err, app_err) and every upstream.tunnel code of
//     spec-errors.md section 9 has an entry in app.js's CODES table.
//
// argv[1] = the ui directory, argv[2] = the src directory.

#include "test_support.h"

#include <cstdio>
#include <regex>
#include <string>
#include <vector>

namespace {

std::wstring g_ui, g_src;

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

// The quoted values of `constexpr const char* k... = "..."` lines between
// "namespace <ns> {" and the next "}  // namespace <ns>".
std::vector<std::string> CodesIn(const std::string& header, const std::string& ns) {
    std::vector<std::string> out;
    const std::string open = "namespace " + ns + " {";
    const std::string close = "}  // namespace " + ns;
    const size_t b = header.find(open);
    if (b == std::string::npos) return out;
    const size_t e = header.find(close, b);
    if (e == std::string::npos) return out;
    const std::string body = header.substr(b, e - b);
    const std::regex line(R"(constexpr const char\* k\w+ = \"([a-z_]+)\")");
    for (auto it = std::sregex_iterator(body.begin(), body.end(), line); it != std::sregex_iterator(); ++it) {
        out.push_back((*it)[1].str());
    }
    return out;
}

void AppJsWritesOnlyText(const std::string& js) {
    CHECK_MSG(js.size() > 1000, "app.js was read");
    const char* forbidden[] = {
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function",
        "setTimeout(\"", "setInterval(\"", "setTimeout('", "setInterval('", "alert(", "confirm(", "prompt(",
        "window.open", "setAttribute(\"style\"", "setAttribute('style'", "cssText", "srcdoc", "javascript:",
        "http:", "https:", "fetch(\"/", "fetch('/", "\"//", "'//"};
    for (const char* f : forbidden) {
        CHECK_MSG(js.find(f) == std::string::npos, (std::string("app.js contains ") + f).c_str());
    }
    // It does use the safe way, so the check above is not vacuous.
    CHECK(js.find("textContent") != std::string::npos);
    CHECK(js.find("fetch(path") != std::string::npos);
}

// The body of `function <name>(` up to its matching closing brace ("" if not found).
std::string FunctionBody(const std::string& js, const std::string& name) {
    const size_t at = js.find("function " + name + "(");
    if (at == std::string::npos) return std::string();
    const size_t open = js.find('{', at);
    if (open == std::string::npos) return std::string();
    int depth = 0;
    for (size_t i = open; i < js.size(); ++i) {
        if (js[i] == '{') ++depth;
        if (js[i] == '}' && --depth == 0) return js.substr(open, i - open + 1);
    }
    return std::string();
}

size_t Count(const std::string& s, const std::string& what) {
    size_t n = 0;
    for (size_t at = s.find(what); at != std::string::npos; at = s.find(what, at + 1)) ++n;
    return n;
}

// The row buttons are rebuilt only when their own key changes; a button that closed over the
// rule object of its last rebuild would open the editor on a stale copy, and saving it would
// silently revert whatever changed since. So: the editor is opened with null (a new rule) or
// with the rule looked up by id at click time, and the row's buttons hold only the id.
void EditorOpensTheCurrentRule(const std::string& js) {
    CHECK_EQ(Count(js, "openEditor("), static_cast<size_t>(3));  // the definition and two calls
    CHECK(js.find("openEditor(null)") != std::string::npos);
    const std::string edit = FunctionBody(js, "editRule");
    const size_t lookup = edit.find("= currentRule(id)");
    CHECK_MSG(lookup != std::string::npos, "editRule looks the rule up by id");
    CHECK_MSG(edit.find("openEditor(cur)") != std::string::npos && edit.find("openEditor(cur)") > lookup,
              "editRule opens the looked-up rule");
    const std::string toggle = FunctionBody(js, "toggleRule");
    CHECK_MSG(toggle.find("= currentRule(id)") != std::string::npos, "toggleRule reads enabled at click time");
    const std::string current = FunctionBody(js, "currentRule");
    CHECK_MSG(current.find("state.rules") != std::string::npos, "currentRule reads the latest state");
    const std::string actions = FunctionBody(js, "renderActions");
    CHECK(actions.find("editRule(id)") != std::string::npos);
    CHECK(actions.find("toggleRule(id)") != std::string::npos);
    CHECK_MSG(actions.find("openEditor") == std::string::npos, "no row button opens the editor directly");
    // Inside the click handlers nothing is read from the row's rule object.
    const std::regex handler(R"(function \(\) \{[^}]*\br\.)");
    CHECK_MSG(!std::regex_search(actions, handler), "a row button's handler reads the stale rule object");
}

void IndexHtmlHasNoInlineCode(const std::string& html) {
    CHECK_MSG(html.size() > 500, "index.html was read");
    const std::regex inlineScript(R"(<script(?![^>]*\bsrc=)[^>]*>)", std::regex::icase);
    CHECK_MSG(!std::regex_search(html, inlineScript), "index.html has an inline <script>");
    const std::regex handler(R"(\son[a-z]+\s*=)", std::regex::icase);
    CHECK_MSG(!std::regex_search(html, handler), "index.html has an inline event handler");
    CHECK_MSG(html.find(" style=") == std::string::npos, "index.html has a style attribute");
    CHECK(html.find("<style") == std::string::npos);
    CHECK(html.find("http:") == std::string::npos && html.find("https:") == std::string::npos);
    CHECK(html.find("<script src=\"app.js\"") != std::string::npos);
    CHECK(html.find("href=\"app.css\"") != std::string::npos);
    CHECK(html.find("<meta name=\"color-scheme\" content=\"light dark\">") != std::string::npos);
}

void CssHasNoUrls(const std::string& css) {
    CHECK_MSG(css.size() > 200, "app.css was read");
    CHECK(css.find("url(") == std::string::npos);
    CHECK(css.find("@import") == std::string::npos);
    CHECK(css.find("prefers-color-scheme: dark") != std::string::npos);
}

void EveryCodeHasText(const std::string& js) {
    struct Source {
        const wchar_t* file;
        const char* ns;
    };
    const Source sources[] = {
        {L"rules.h", "rule_err"},         {L"rule_store.h", "store_err"}, {L"forward_common.h", "fwd_err"},
        {L"forward_common.h", "rule_status"}, {L"tunnel_client.h", "tunnel_err"}, {L"ghost_api.h", "api_err"},
        {L"ui_server.h", "ui_err"},       {L"app.h", "app_err"},
    };
    std::vector<std::string> codes;
    for (const Source& s : sources) {
        const std::vector<std::string> found = CodesIn(ReadAll(g_src + L"\\" + s.file), s.ns);
        CHECK_MSG(!found.empty(), (std::string("codes found in namespace ") + s.ns).c_str());
        codes.insert(codes.end(), found.begin(), found.end());
    }
    // rule_status aliases three codes of other namespaces; they are covered through those.
    // Ghost's own codes for upstream.tunnel (spec-errors.md section 9) and invalid_json.
    const char* ghost[] = {"invalid_json",        "bad_target",          "upstream_not_found",
                           "upstream_invalid",    "upstream_udp_unavailable", "upstream_unreachable",
                           "upstream_timeout",    "upstream_auth_failed", "upstream_refused",
                           "plugin_not_running",  "tunnel_unsupported",  "tunnel_limit",
                           "tunnel_failed",       "tunnel_unavailable"};
    for (const char* g : ghost) codes.push_back(g);

    const size_t table = js.find("var CODES = {");
    CHECK(table != std::string::npos);
    const std::string tail = table == std::string::npos ? std::string() : js.substr(table);
    for (const std::string& c : codes) {
        CHECK_MSG(tail.find("\n    " + c + ": [") != std::string::npos, ("no text for code " + c).c_str());
    }
    CHECK(codes.size() > 60);
}

std::wstring Backslashes(std::wstring p) {
    for (auto& ch : p)
        if (ch == L'/') ch = L'\\';
    return p;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: test_ui_source <ui dir> <src dir>\n");
        return 2;
    }
    g_ui = Backslashes(argv[1]);
    g_src = Backslashes(argv[2]);
    const std::string js = ReadAll(g_ui + L"\\app.js");
    AppJsWritesOnlyText(js);
    IndexHtmlHasNoInlineCode(ReadAll(g_ui + L"\\index.html"));
    CssHasNoUrls(ReadAll(g_ui + L"\\app.css"));
    EveryCodeHasText(js);
    EditorOpensTheCurrentRule(js);
    return pf_test::TestExitCode();
}
