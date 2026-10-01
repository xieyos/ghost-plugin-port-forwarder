// Unit: the handshake (spec-host-protocol.md section 3).
//
// Every rejected row starts from one good handshake and breaks exactly one thing, and the
// assertion names the reason code -- so a row can only pass because the check it is about
// exists, not because some other check happened to trip first.

#include "host_handshake.h"
#include "json_util.h"
#include "test_support.h"

#include <algorithm>
#include <functional>
#include <string>
#include <thread>
#include <vector>

using pf::HostEnv;
using pf::json;

namespace {

const char* kId = "com.qtvz.xieyos.port-forwarder";
const char* kStop = "Local\\GhostPlugin_Stop_00001f40_com.qtvz.xieyos.port-forwarder";

json GoodHandshake() {
    json j = json::object();
    j["v"] = 1;
    j["pluginId"] = kId;
    j["pluginDir"] = "C:\\Users\\me\\AppData\\Local\\GhostProxifier\\plugins\\com.qtvz.xieyos.port-forwarder\\1.0.0";
    j["dataDir"] = "C:\\Users\\me\\AppData\\Local\\GhostProxifier\\plugins\\com.qtvz.xieyos.port-forwarder\\.data";
    j["apiBase"] = "http://127.0.0.1:23551";
    j["token"] = "{6F9619FF-8B86-D011-B42D-00C04FC964FF}";
    j["permissions"] = json::array({"upstream.connect", "log.write"});
    j["settings"] = json::object();
    j["license"] = json{{"licensed", false}, {"trial", false}};
    j["lang"] = "zh";
    j["stopEvent"] = kStop;
    return j;
}

HostEnv GoodEnv() {
    HostEnv e;
    e.hasPluginId = true;
    e.pluginId = kId;
    e.hasStopEvent = true;
    e.stopEvent = kStop;
    return e;
}

struct Row {
    const char* label;
    std::function<void(json&, HostEnv&)> mutate;
    const char* expected;  // "" = accepted
};

void RunRows() {
    const std::vector<Row> rows = {
        {"baseline", [](json&, HostEnv&) {}, ""},
        // v: the integer 1 and nothing else.
        {"v true", [](json& j, HostEnv&) { j["v"] = true; }, "bad_v"},
        {"v 1.0", [](json& j, HostEnv&) { j["v"] = 1.0; }, "bad_v"},
        {"v 2", [](json& j, HostEnv&) { j["v"] = 2; }, "bad_v"},
        {"v \"1\"", [](json& j, HostEnv&) { j["v"] = "1"; }, "bad_v"},
        {"v missing", [](json& j, HostEnv&) { j.erase("v"); }, "bad_v"},
        // pluginId must equal GHOST_PLUGIN_ID.
        {"pluginId differs from env", [](json& j, HostEnv&) { j["pluginId"] = "com.example.other"; }, "bad_plugin_id"},
        {"env pluginId differs", [](json&, HostEnv& e) { e.pluginId = "com.example.other"; }, "bad_plugin_id"},
        {"env has no GHOST_PLUGIN_ID", [](json&, HostEnv& e) { e.hasPluginId = false; e.pluginId.clear(); }, "bad_plugin_id"},
        {"pluginId empty (env too)", [](json& j, HostEnv& e) { j["pluginId"] = ""; e.pluginId = ""; }, "bad_plugin_id"},
        {"pluginId missing", [](json& j, HostEnv&) { j.erase("pluginId"); }, "bad_plugin_id"},
        {"pluginId a number", [](json& j, HostEnv&) { j["pluginId"] = 7; }, "bad_plugin_id"},
        // Directories: present, strings, non-empty.
        {"pluginDir missing", [](json& j, HostEnv&) { j.erase("pluginDir"); }, "bad_plugin_dir"},
        {"pluginDir empty", [](json& j, HostEnv&) { j["pluginDir"] = ""; }, "bad_plugin_dir"},
        {"dataDir missing", [](json& j, HostEnv&) { j.erase("dataDir"); }, "bad_data_dir"},
        {"dataDir empty", [](json& j, HostEnv&) { j["dataDir"] = ""; }, "bad_data_dir"},
        {"dataDir an array", [](json& j, HostEnv&) { j["dataDir"] = json::array({"C:\\x"}); }, "bad_data_dir"},
        // apiBase: exactly http://127.0.0.1:<1..65535>.
        {"apiBase https", [](json& j, HostEnv&) { j["apiBase"] = "https://127.0.0.1:23551"; }, "bad_api_base"},
        {"apiBase HTTP upper case", [](json& j, HostEnv&) { j["apiBase"] = "HTTP://127.0.0.1:23551"; }, "bad_api_base"},
        {"apiBase localhost", [](json& j, HostEnv&) { j["apiBase"] = "http://localhost:23551"; }, "bad_api_base"},
        {"apiBase 127.0.0.2", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.2:23551"; }, "bad_api_base"},
        {"apiBase port 0", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:0"; }, "bad_api_base"},
        {"apiBase port 65536", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:65536"; }, "bad_api_base"},
        {"apiBase port 6 digits", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:123456"; }, "bad_api_base"},
        // Five characters or fewer after the colon, so that only the rule in the label
        // can reject these (a six-character port is already too long).
        {"apiBase leading zero", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:02355"; }, "bad_api_base"},
        {"apiBase no port", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1"; }, "bad_api_base"},
        {"apiBase empty port", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:"; }, "bad_api_base"},
        {"apiBase trailing slash", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:2355/"; }, "bad_api_base"},
        {"apiBase with a path", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:23/a"; }, "bad_api_base"},
        {"apiBase trailing slash, 5-digit port", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:23551/"; }, "bad_api_base"},
        {"apiBase port sign", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:+2355"; }, "bad_api_base"},
        {"apiBase a number", [](json& j, HostEnv&) { j["apiBase"] = 23551; }, "bad_api_base"},
        {"apiBase port 1", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:1"; }, ""},
        {"apiBase port 65535", [](json& j, HostEnv&) { j["apiBase"] = "http://127.0.0.1:65535"; }, ""},
        // token: 1..128 of [0-9A-Za-z{}-].
        {"token with a space", [](json& j, HostEnv&) { j["token"] = "abc def"; }, "bad_token"},
        {"token with a colon", [](json& j, HostEnv&) { j["token"] = "abc:def"; }, "bad_token"},
        {"token with CR LF", [](json& j, HostEnv&) { j["token"] = "abc\r\nX-Evil: 1"; }, "bad_token"},
        {"token non-ASCII", [](json& j, HostEnv&) { j["token"] = "abc\xc3\xa9"; }, "bad_token"},
        {"token 129 chars", [](json& j, HostEnv&) { j["token"] = std::string(129, 'a'); }, "bad_token"},
        {"token empty", [](json& j, HostEnv&) { j["token"] = ""; }, "bad_token"},
        {"token missing", [](json& j, HostEnv&) { j.erase("token"); }, "bad_token"},
        {"token 128 chars", [](json& j, HostEnv&) { j["token"] = std::string(128, 'Z'); }, ""},
        // permissions: an array of strings (empty is fine).
        {"permissions a string", [](json& j, HostEnv&) { j["permissions"] = "upstream.connect"; }, "bad_permissions"},
        {"permissions holds a number", [](json& j, HostEnv&) { j["permissions"] = json::array({"log.write", 5}); }, "bad_permissions"},
        {"permissions missing", [](json& j, HostEnv&) { j.erase("permissions"); }, "bad_permissions"},
        {"permissions null", [](json& j, HostEnv&) { j["permissions"] = nullptr; }, "bad_permissions"},
        {"permissions empty", [](json& j, HostEnv&) { j["permissions"] = json::array(); }, ""},
        // lang: optional, but a string when present.
        {"lang a number", [](json& j, HostEnv&) { j["lang"] = 1; }, "bad_lang"},
        {"lang missing", [](json& j, HostEnv&) { j.erase("lang"); }, ""},
        // stopEvent: non-empty, equal to GHOST_PLUGIN_STOP_EVENT when that exists.
        {"stopEvent empty", [](json& j, HostEnv& e) { j["stopEvent"] = ""; e.stopEvent = ""; }, "bad_stop_event"},
        {"stopEvent missing", [](json& j, HostEnv&) { j.erase("stopEvent"); }, "bad_stop_event"},
        {"stopEvent a number", [](json& j, HostEnv&) { j["stopEvent"] = 3; }, "bad_stop_event"},
        {"stopEvent differs from env", [](json& j, HostEnv&) { j["stopEvent"] = "Local\\Other"; }, "bad_stop_event"},
        {"stopEvent empty, env absent", [](json& j, HostEnv& e) { j["stopEvent"] = ""; e.hasStopEvent = false; e.stopEvent.clear(); }, "bad_stop_event"},
        {"env has no GHOST_PLUGIN_STOP_EVENT", [](json&, HostEnv& e) { e.hasStopEvent = false; e.stopEvent.clear(); }, ""},
        // Unknown fields are ignored; settings/license are not ours to judge.
        {"unknown field", [](json& j, HostEnv&) { j["future"] = json::array({1, 2}); }, ""},
        {"settings a string", [](json& j, HostEnv&) { j["settings"] = "x"; }, ""},
    };

    for (const auto& r : rows) {
        json j = GoodHandshake();
        HostEnv env = GoodEnv();
        r.mutate(j, env);
        pf::Handshake hs;
        const std::string got = pf::ParseHandshake(pf::DumpSafe(j), env, &hs);
        const std::string label = std::string(r.label) + " -> got '" + got + "', want '" + r.expected + "'";
        CHECK_MSG(got == r.expected, label.c_str());
    }
}

void NonObjectLines() {
    const HostEnv env = GoodEnv();
    pf::Handshake hs;
    CHECK(pf::ParseHandshake("not json", env, &hs) == "bad_json");
    CHECK(pf::ParseHandshake("", env, &hs) == "bad_json");
    CHECK(pf::ParseHandshake("[1]", env, &hs) == "bad_json");
    CHECK(pf::ParseHandshake("1", env, &hs) == "bad_json");
    CHECK(pf::ParseHandshake("null", env, &hs) == "bad_json");
    // One line holding two documents is not one handshake.
    const std::string good = pf::DumpSafe(GoodHandshake());
    CHECK(pf::ParseHandshake(good + good, env, &hs) == "bad_json");
}

void FieldsAreExtracted() {
    pf::Handshake hs;
    const std::string err = pf::ParseHandshake(pf::DumpSafe(GoodHandshake()), GoodEnv(), &hs);
    CHECK(err.empty());
    CHECK(hs.pluginId == kId);
    CHECK(hs.apiBase == "http://127.0.0.1:23551");
    CHECK(hs.apiPort == 23551);
    CHECK(hs.token == "{6F9619FF-8B86-D011-B42D-00C04FC964FF}");
    CHECK(hs.stopEvent == kStop);
    CHECK(hs.lang == "zh");
    CHECK(hs.dataDir.find("\\.data") != std::string::npos);
    CHECK(hs.permissions.size() == 2);
    CHECK(hs.HasPermission("upstream.connect"));
    CHECK(hs.HasPermission("log.write"));
    CHECK(!hs.HasPermission("stats.read"));
    CHECK(!hs.HasPermission("log.write "));
    CHECK(!hs.HasPermission(""));

    // A UTF-8 data directory survives intact.
    json j = GoodHandshake();
    j["dataDir"] = "C:\\Users\\\xe7\x94\xa8\xe6\x88\xb7\\.data";
    CHECK(pf::ParseHandshake(pf::DumpSafe(j), GoodEnv(), &hs).empty());
    CHECK(hs.dataDir == "C:\\Users\\\xe7\x94\xa8\xe6\x88\xb7\\.data");
}

void ApiBaseAndToken() {
    uint16_t port = 0;
    CHECK(pf::ParseApiBase("http://127.0.0.1:23551", &port) && port == 23551);
    CHECK(pf::ParseApiBase("http://127.0.0.1:9", &port) && port == 9);
    CHECK(!pf::ParseApiBase("http://127.0.0.1:99999", &port));
    CHECK(!pf::ParseApiBase(" http://127.0.0.1:23551", &port));
    CHECK(!pf::ParseApiBase("http://127.0.0.1:23551 ", &port));
    CHECK(!pf::ParseApiBase("http://127.0.0.1:2355a", &port));
    CHECK(pf::IsTokenShaped("{a-Z_}") == false);
    CHECK(pf::IsTokenShaped("{a-Z}"));
    CHECK(!pf::IsTokenShaped(std::string("ab\0cd", 5)));
}

// --- ReadLine over a real pipe ------------------------------------------------------

struct PipePair {
    HANDLE r = nullptr, w = nullptr;
    PipePair() { CreatePipe(&r, &w, nullptr, 1 << 20); }
    ~PipePair() {
        if (r) CloseHandle(r);
        if (w) CloseHandle(w);
    }
    void CloseWrite() {
        if (w) CloseHandle(w);
        w = nullptr;
    }
};

// Writes `chunks` on a thread (so a small pipe buffer cannot deadlock the test), then
// reads one line. The reader closes its end before joining, which unblocks the writer.
pf::LineResult ReadThroughPipe(const std::vector<std::string>& chunks, bool closeAfter, std::string* line) {
    PipePair p;
    CHECK(p.r && p.w);
    HANDLE w = p.w;
    std::thread writer([w, chunks] {
        for (const auto& c : chunks) {
            DWORD n = 0;
            if (!WriteFile(w, c.data(), static_cast<DWORD>(c.size()), &n, nullptr)) return;
        }
    });
    pf::LineResult res = pf::LineResult::ReadError;
    if (closeAfter) {
        writer.join();
        p.CloseWrite();
        res = pf::ReadLine(p.r, pf::kMaxHandshakeLineBytes, line);
    } else {
        res = pf::ReadLine(p.r, pf::kMaxHandshakeLineBytes, line);
        CloseHandle(p.r);
        p.r = nullptr;
        writer.join();
    }
    return res;
}

void ReadLineCases() {
    std::string line;
    CHECK(ReadThroughPipe({"hello\n"}, false, &line) == pf::LineResult::Ok && line == "hello");
    CHECK(ReadThroughPipe({"he", "l", "lo\r\n", "ignored"}, false, &line) == pf::LineResult::Ok && line == "hello");
    CHECK(ReadThroughPipe({"no newline"}, true, &line) == pf::LineResult::Eof);
    CHECK(ReadThroughPipe({}, true, &line) == pf::LineResult::Eof);

    // The 16 KB boundary, counted without the '\n'.
    const std::string exact(pf::kMaxHandshakeLineBytes, 'a');
    CHECK_MSG(ReadThroughPipe({exact + "\n"}, false, &line) == pf::LineResult::Ok && line.size() == exact.size(),
              "16384 bytes + LF is accepted");
    CHECK_MSG(ReadThroughPipe({exact + "a\n"}, false, &line) == pf::LineResult::TooLong, "16385 bytes + LF is too long");
    // Too long is decided before the newline ever arrives (the writer never sends one).
    CHECK_MSG(ReadThroughPipe({std::string(64 * 1024, 'b')}, false, &line) == pf::LineResult::TooLong,
              "an endless line is rejected without waiting for its end");
}

void ReadHandshakeCases() {
    const HostEnv env = GoodEnv();
    pf::Handshake hs;
    {
        PipePair p;
        const std::string l = pf::DumpSafe(GoodHandshake()) + "\n";
        DWORD n = 0;
        WriteFile(p.w, l.data(), static_cast<DWORD>(l.size()), &n, nullptr);
        CHECK(pf::ReadHandshake(p.r, env, &hs).empty());
        CHECK(hs.pluginId == kId);
    }
    {
        // A good handshake padded past 16 KB by an unknown field is still rejected.
        json j = GoodHandshake();
        j["pad"] = std::string(pf::kMaxHandshakeLineBytes, 'x');
        PipePair p;
        const std::string l = pf::DumpSafe(j) + "\n";
        DWORD n = 0;
        WriteFile(p.w, l.data(), static_cast<DWORD>(l.size()), &n, nullptr);
        CHECK(pf::ReadHandshake(p.r, env, &hs) == "line_too_long");
    }
    {
        // ...and the same padding that fits exactly is accepted.
        json j = GoodHandshake();
        j["pad"] = "";
        const size_t base = pf::DumpSafe(j).size();
        j["pad"] = std::string(pf::kMaxHandshakeLineBytes - base, 'x');
        const std::string l = pf::DumpSafe(j);
        CHECK(l.size() == pf::kMaxHandshakeLineBytes);
        PipePair p;
        const std::string withLf = l + "\n";
        DWORD n = 0;
        WriteFile(p.w, withLf.data(), static_cast<DWORD>(withLf.size()), &n, nullptr);
        CHECK(pf::ReadHandshake(p.r, env, &hs).empty());
    }
    {
        PipePair p;
        p.CloseWrite();
        CHECK(pf::ReadHandshake(p.r, env, &hs) == "no_line");
    }
}

// --- The receipt ---------------------------------------------------------------------

void ReceiptCases() {
    const std::string ok = pf::FormatReceiptOk("");
    CHECK(ok == "{\"v\":1,\"ok\":true}\n");
    const std::string withUrl = pf::FormatReceiptOk("http://127.0.0.1:53211/abc/");
    CHECK(withUrl == "{\"v\":1,\"ok\":true,\"uiUrl\":\"http://127.0.0.1:53211/abc/\"}\n");

    const std::string err = pf::FormatReceiptError("bad_v");
    CHECK(err == "{\"v\":1,\"ok\":false,\"error\":\"bad_v\"}\n");

    // A long error is cut so that the whole line, '\n' included, fits in 4 KB, and the
    // cut never splits a UTF-8 sequence (three-byte CJK characters, mis-aligned on purpose).
    std::string longErr = "x";
    for (int i = 0; i < 4000; ++i) longErr += "\xe7\xab\xaf";
    const std::string cut = pf::FormatReceiptError(longErr);
    CHECK(cut.size() <= pf::kMaxReceiptLineBytes);
    CHECK(cut.size() > pf::kMaxReceiptLineBytes - 8);
    CHECK(!cut.empty() && cut.back() == '\n');
    CHECK(std::count(cut.begin(), cut.end(), '\n') == 1);
    const json back = pf::ParseJsonNoThrow(cut.substr(0, cut.size() - 1));
    CHECK(back.is_object());
    std::string e;
    CHECK(pf::JsonGetString(back, "error", &e) && !e.empty() && longErr.compare(0, e.size(), e) == 0);
    CHECK(e.size() % 3 == 1);  // "x" + whole characters only

    // Characters that need escaping still produce a line that fits and parses.
    const std::string quoted = pf::FormatReceiptError(std::string(5000, '"'));
    CHECK(quoted.size() <= pf::kMaxReceiptLineBytes);
    CHECK(pf::ParseJsonNoThrow(quoted.substr(0, quoted.size() - 1)).is_object());
    // A newline in the error text cannot become a second line.
    const std::string nl = pf::FormatReceiptError("a\nb");
    CHECK(std::count(nl.begin(), nl.end(), '\n') == 1);

    // WriteReceipt writes every byte of exactly one line, and returns without waiting
    // for the reader (nothing reads this pipe until after the call).
    PipePair p;
    CHECK(pf::WriteReceipt(p.w, true, ""));
    p.CloseWrite();
    std::string got;
    CHECK(pf::ReadLine(p.r, 4096, &got) == pf::LineResult::Ok);
    CHECK(got + "\n" == ok);
}

// --- The stop event --------------------------------------------------------------------

std::string UniqueName(const char* tag) {
    return std::string("Local\\pf_test_") + tag + "_" + std::to_string(GetCurrentProcessId()) + "_" +
           std::to_string(GetTickCount64());
}

void StopEventCases() {
    const std::string name = UniqueName("stop");
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, std::wstring(name.begin(), name.end()).c_str());
    CHECK(ev != nullptr);

    {
        pf::StopEvent s;
        CHECK(!s.IsOpen());
        CHECK(!s.WaitFor(0));
        CHECK(!s.Open(name + "x"));  // the name is used verbatim, not "close enough"
        CHECK(!s.IsOpen());
        CHECK(!s.Open(""));
    }
    {
        pf::StopEvent s;
        CHECK(s.Open(name));
        CHECK(s.IsOpen());
        CHECK(!s.WaitFor(0));
        SetEvent(ev);
        CHECK(s.WaitFor(1000));
        // Returns because it is signalled. Guarded: on a closed handle it would (rightly)
        // block forever, and a test must fail rather than hang.
        if (s.IsOpen()) s.WaitForever();
    }
    CloseHandle(ev);
}

}  // namespace

int main() {
    RunRows();
    NonObjectLines();
    FieldsAreExtracted();
    ApiBaseAndToken();
    ReadLineCases();
    ReadHandshakeCases();
    ReceiptCases();
    StopEventCases();
    return pf_test::TestExitCode();
}
