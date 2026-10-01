// Integration: the real port-forwarder.exe, started the way the Ghost plugin host starts
// it -- pipes for stdin/stdout, stderr on NUL, CREATE_NO_WINDOW, exactly these three
// handles inherited, GHOST_PLUGIN_* in the environment -- with a fake Ghost as apiBase and
// a temporary data directory. Hosted: the receipt carries a valid uiUrl, the page is served
// there and may be framed by Ghost only, the stop event ends the process within 3 s.
// Standalone (--no-browser --data-dir): stdin is never read, the page's address is printed,
// the page is served, its Stop button ends the process, and a second instance on the same
// data directory refuses to start.
//
// argv[1] = path of port-forwarder.exe, argv[2] = path of manifest.json.

#include "fake_ghost.h"
#include "http_client.h"
#include "json_util.h"
#include "test_support.h"
#include "util_str.h"

#include <cstdio>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#pragma comment(lib, "version.lib")

using pf::json;

namespace {

const char* kId = "com.qtvz.xieyos.port-forwarder";

std::wstring g_exe;
std::wstring g_manifest;

std::string UniqueName(const char* tag) {
    static int counter = 0;
    return std::string("Local\\pf_test_exe_") + tag + "_" + std::to_string(GetCurrentProcessId()) + "_" +
           std::to_string(++counter) + "_" + std::to_string(GetTickCount64());
}

bool StartsWithNoCase(const std::wstring& s, const wchar_t* prefix) {
    const size_t n = wcslen(prefix);
    return s.size() >= n && _wcsnicmp(s.c_str(), prefix, n) == 0;
}

// Our environment minus every GHOST_PLUGIN_* variable, plus `extra`.
std::wstring BuildEnvBlock(const std::vector<std::pair<std::wstring, std::wstring>>& extra) {
    std::wstring block;
    if (wchar_t* env = GetEnvironmentStringsW()) {
        for (const wchar_t* p = env; *p; p += wcslen(p) + 1) {
            std::wstring entry(p);
            if (StartsWithNoCase(entry, L"GHOST_PLUGIN_")) continue;
            block += entry;
            block.push_back(L'\0');
        }
        FreeEnvironmentStringsW(env);
    }
    for (const auto& kv : extra) {
        block += kv.first + L"=" + kv.second;
        block.push_back(L'\0');
    }
    block.push_back(L'\0');
    return block;
}

class Child {
public:
    ~Child() {
        if (pi_.hProcess) {
            if (WaitForSingleObject(pi_.hProcess, 0) == WAIT_TIMEOUT) TerminateProcess(pi_.hProcess, 99);
            WaitForSingleObject(pi_.hProcess, 5000);
        }
        if (stdinW_) CloseHandle(stdinW_);
        if (stdinPeek_) CloseHandle(stdinPeek_);
        if (reader_.joinable()) reader_.join();  // ends once the child's stdout is closed
        if (stdoutR_) CloseHandle(stdoutR_);
        if (pi_.hThread) CloseHandle(pi_.hThread);
        if (pi_.hProcess) CloseHandle(pi_.hProcess);
    }

    bool Start(const std::vector<std::pair<std::wstring, std::wstring>>& env,
               const std::vector<std::wstring>& args = {}) {
        SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
        HANDLE inR = nullptr, outW = nullptr;
        if (!CreatePipe(&inR, &stdinW_, &sa, 64 * 1024)) return false;
        if (!CreatePipe(&stdoutR_, &outW, &sa, 64 * 1024)) return false;
        SetHandleInformation(stdinW_, HANDLE_FLAG_INHERIT, 0);
        // A non-inheritable copy of the child's stdin read end, only to look at what is
        // still unread in the pipe (PeekNamedPipe); we never read through it.
        if (!DuplicateHandle(GetCurrentProcess(), inR, GetCurrentProcess(), &stdinPeek_, 0, FALSE,
                             DUPLICATE_SAME_ACCESS)) {
            return false;
        }
        SetHandleInformation(stdoutR_, HANDLE_FLAG_INHERIT, 0);
        HANDLE nul = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0,
                                 nullptr);
        if (nul == INVALID_HANDLE_VALUE) return false;

        HANDLE inherit[3] = {inR, outW, nul};
        SIZE_T attrSize = 0;
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
        std::vector<unsigned char> attrBuf(attrSize);
        auto* attrs = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
        bool ok = InitializeProcThreadAttributeList(attrs, 1, 0, &attrSize) &&
                  UpdateProcThreadAttribute(attrs, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherit, sizeof(inherit),
                                            nullptr, nullptr);
        STARTUPINFOEXW si = {};
        si.StartupInfo.cb = sizeof(si);
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = inR;
        si.StartupInfo.hStdOutput = outW;
        si.StartupInfo.hStdError = nul;
        si.lpAttributeList = attrs;

        std::wstring envBlock = BuildEnvBlock(env);
        std::wstring cmd = L"\"" + g_exe + L"\"";
        for (const auto& a : args) cmd += L" \"" + a + L"\"";
        if (ok) {
            ok = CreateProcessW(g_exe.c_str(), cmd.data(), nullptr, nullptr, TRUE,
                                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW,
                                envBlock.data(), nullptr, &si.StartupInfo, &pi_) != FALSE;
        }
        DeleteProcThreadAttributeList(attrs);
        CloseHandle(inR);
        CloseHandle(outW);
        CloseHandle(nul);
        if (!ok) return false;
        started_ = GetTickCount64();

        HANDLE r = stdoutR_;
        reader_ = std::thread([this, r] {
            try {
                char buf[4096];
                DWORD n = 0;
                while (ReadFile(r, buf, sizeof(buf), &n, nullptr) && n > 0) {
                    std::lock_guard<std::mutex> lock(mu_);
                    out_.append(buf, n);
                }
            } catch (...) {
            }
            std::lock_guard<std::mutex> lock(mu_);
            eof_ = true;
        });
        return true;
    }

    // Bytes written to the child's stdin that nobody has read yet.
    DWORD StdinUnread() const {
        DWORD avail = 0;
        if (!PeekNamedPipe(stdinPeek_, nullptr, 0, nullptr, &avail, nullptr)) return 0;
        return avail;
    }

    bool WriteStdin(const std::string& s) {
        DWORD n = 0;
        return WriteFile(stdinW_, s.data(), static_cast<DWORD>(s.size()), &n, nullptr) && n == s.size();
    }

    // The first stdout line (with its '\n') once it arrives within `ms`; "" otherwise.
    std::string FirstLine(DWORD ms) {
        const std::vector<std::string> l = Lines(1, ms);
        return l.empty() ? std::string() : l[0];
    }

    // The first `n` stdout lines (each with its '\n') once they all arrived within `ms`;
    // fewer otherwise.
    std::vector<std::string> Lines(size_t n, DWORD ms) {
        std::vector<std::string> lines;
        WaitUntil_([&] {
            std::lock_guard<std::mutex> lock(mu_);
            lines.clear();
            size_t pos = 0;
            while (lines.size() < n) {
                const size_t nl = out_.find('\n', pos);
                if (nl == std::string::npos) break;
                lines.push_back(out_.substr(pos, nl + 1 - pos));
                pos = nl + 1;
            }
            return lines.size() == n;
        }, ms);
        return lines;
    }

    std::string AllOutputAfterExit(DWORD ms) {
        WaitUntil_([&] {
            std::lock_guard<std::mutex> lock(mu_);
            return eof_;
        }, ms);
        std::lock_guard<std::mutex> lock(mu_);
        return out_;
    }

    ULONGLONG ElapsedMs() const { return GetTickCount64() - started_; }
    bool Running() const { return WaitForSingleObject(pi_.hProcess, 0) == WAIT_TIMEOUT; }

    // True if the process exits within `ms`; the exit code goes to `code`.
    bool ExitsWithin(DWORD ms, DWORD* code) const {
        if (WaitForSingleObject(pi_.hProcess, ms) != WAIT_OBJECT_0) return false;
        GetExitCodeProcess(pi_.hProcess, code);
        return true;
    }

    DWORD pid() const { return pi_.dwProcessId; }

private:
    static bool WaitUntil_(const std::function<bool()>& f, DWORD ms) { return pf_test::WaitUntil(f, ms); }

    PROCESS_INFORMATION pi_ = {};
    HANDLE stdinW_ = nullptr;
    HANDLE stdinPeek_ = nullptr;
    HANDLE stdoutR_ = nullptr;
    std::thread reader_;
    std::mutex mu_;
    std::string out_;
    bool eof_ = false;
    ULONGLONG started_ = 0;
};

// Where the hosted child is pointed: a temporary data directory and a fake Ghost (set in
// wmain). Never Ghost's real control port: a log line must not land in a running Ghost.
std::string g_dataDir;
std::string g_apiBase;

json Handshake(const std::string& stopEvent) {
    json j = json::object();
    j["v"] = 1;
    j["pluginId"] = kId;
    j["pluginDir"] = "C:\\plugins\\com.qtvz.xieyos.port-forwarder\\1.0.0";
    j["dataDir"] = g_dataDir;
    j["apiBase"] = g_apiBase;
    j["token"] = "{11111111-2222-3333-4444-555555555555}";
    j["permissions"] = json::array({"upstream.connect", "log.write"});
    j["settings"] = json::object();
    j["lang"] = "en";
    j["stopEvent"] = stopEvent;
    return j;
}

std::vector<std::pair<std::wstring, std::wstring>> HostedEnv(const std::string& stopEvent) {
    return {
        {L"GHOST_PLUGIN_ID", pf::Utf8ToWide(kId)},
        {L"GHOST_PLUGIN_DIR", L"C:\\plugins\\com.qtvz.xieyos.port-forwarder\\1.0.0"},
        {L"GHOST_PLUGIN_DATA_DIR", pf::Utf8ToWide(g_dataDir)},
        {L"GHOST_PLUGIN_API_BASE", pf::Utf8ToWide(g_apiBase)},
        {L"GHOST_PLUGIN_STOP_EVENT", pf::Utf8ToWide(stopEvent)},
    };
}

// The receipt line -> its uiUrl, checked against the host's rules (spec-host-protocol.md
// 3.2, spec-manifest.md 5, spec-limits.md): "" when anything is off.
std::string UiUrlOfReceipt(const std::string& line) {
    if (line.empty() || line.back() != '\n') return std::string();
    const json r = pf::ParseJsonNoThrow(line.substr(0, line.size() - 1));
    long long v = 0;
    if (!pf::JsonGetInt64(r, "v", &v) || v != 1) return std::string();
    bool ok = false;
    if (!pf::JsonGetBool(r, "ok", &ok) || !ok) return std::string();
    std::string url;
    if (!pf::JsonGetString(r, "uiUrl", &url)) return std::string();
    if (r.size() != 3) return std::string();  // v, ok, uiUrl and nothing else
    static const std::regex shape(R"(^http://127\.0\.0\.1:(\d{1,5})/[0-9a-f]{32}/$)");
    std::smatch m;
    if (!std::regex_match(url, m, shape)) return std::string();
    const int port = std::atoi(m[1].str().c_str());
    if (port < 1 || port > 65535 || port == 80 || port == 23551) return std::string();
    if (url.size() > 2048) return std::string();
    return url;
}

// Hosted, happy path: receipt within 10 s with the page's address, the page there (frameable
// by Ghost only), then a clean exit within 3 s of the stop event.
void HostedHandshakeAndStop(pf_test::FakeGhost& ghost) {
    const std::string name = UniqueName("stop");
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, pf::Utf8ToWide(name).c_str());
    CHECK(ev != nullptr);

    Child c;
    CHECK(c.Start(HostedEnv(name)));
    CHECK(c.WriteStdin(pf::DumpSafe(Handshake(name)) + "\n"));

    const std::string line = c.FirstLine(10000);
    CHECK_MSG(!line.empty(), "a receipt line arrives within 10 s");
    CHECK(c.ElapsedMs() < 10000);
    CHECK(line.size() <= 4096);
    const std::string url = UiUrlOfReceipt(line);
    CHECK_MSG(!url.empty(), line.c_str());

    unsigned short port = 0;
    std::string prefix;
    if (pf_test::SplitUiUrl(url, &port, &prefix)) {
        const pf_test::HttpReply page = pf_test::RawHttp(port, pf_test::BuildRequest("GET", "/" + prefix + "/", port));
        CHECK_MSG(page.status == 200, page.raw.substr(0, 200).c_str());
        CHECK(page.Header("Content-Security-Policy") ==
              "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors " + g_apiBase);
        CHECK(page.body.find("app.js") != std::string::npos);
        // The API answers once the rules are loaded; the language is the handshake's.
        json state;
        CHECK(pf_test::WaitUntil([&] {
            const pf_test::HttpReply r = pf_test::RawHttp(port, pf_test::BuildRequest("GET", "/" + prefix + "/api/state", port));
            state = pf::ParseJsonNoThrow(r.body);
            return r.status == 200;
        }, 5000));
        CHECK(state.is_object() && state["hosted"] == true && state["lang"] == "en" && state["canQuit"] == false);
        // The host owns our lifetime: the page cannot end us.
        const pf_test::HttpReply quit = pf_test::RawHttp(
            port, pf_test::BuildRequest("POST", "/" + prefix + "/api/quit", port, "{}",
                                        "http://127.0.0.1:" + std::to_string(port), "application/json"));
        CHECK(quit.status == 403);
    } else {
        CHECK_MSG(false, "uiUrl splits into port and prefix");
    }

    // It waits for the stop event rather than exiting on its own.
    CHECK_MSG(c.Running(), "still running after the receipt");

    SetEvent(ev);
    DWORD code = 12345;
    CHECK_MSG(c.ExitsWithin(3000, &code), "exits within 3 s of the stop event");
    CHECK_MSG(code == 0, ("exit code " + std::to_string(code)).c_str());
    // Nothing but the receipt was ever written to stdout.
    CHECK(c.AllOutputAfterExit(3000) == line);

    // The log went to Ghost (log.write is granted) -- the start line and, sent before the API
    // was shut down, the stop line -- and never carried the page's secret prefix.
    bool started = false, stopping = false, leaked = false;
    for (const auto& r : ghost.Requests()) {
        if (r.path != "/api/log-ingest") continue;
        if (r.body.find("started (hosted)") != std::string::npos) started = true;
        if (r.body.find("Port Forwarder stopping") != std::string::npos) stopping = true;
        if (!prefix.empty() && r.body.find(prefix) != std::string::npos) leaked = true;
    }
    CHECK_MSG(started, "the start line reached log.write");
    CHECK_MSG(stopping, "the last batch was sent before the API shut down");
    CHECK(!leaked);
    CloseHandle(ev);
}

// Ghost stalls on log.write (answers never come): the process still exits with code 0 within
// the host's 3 s -- the exit deadline aborts the stuck request and the last batch is dropped,
// not waited for.
void HostedStalledLogStillExits(pf_test::FakeGhost& ghost) {
    ghost.SetLogIngestDelayMs(60000);
    const size_t before = ghost.Requests().size();
    const int abandonedBefore = ghost.LogIngestAbandoned();
    const std::string name = UniqueName("stall");
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, pf::Utf8ToWide(name).c_str());
    Child c;
    CHECK(c.Start(HostedEnv(name)));
    CHECK(c.WriteStdin(pf::DumpSafe(Handshake(name)) + "\n"));
    CHECK_MSG(!UiUrlOfReceipt(c.FirstLine(10000)).empty(), "receipt");
    // The start line is on the wire and stuck: the fake has read it and is not answering.
    auto ingests = [&] {
        int n = 0;
        const auto all = ghost.Requests();
        for (size_t i = before; i < all.size(); ++i)
            if (all[i].path == "/api/log-ingest") ++n;
        return n;
    };
    CHECK(pf_test::WaitUntil([&] { return ingests() >= 1; }, 5000));

    const ULONGLONG t0 = GetTickCount64();
    SetEvent(ev);
    DWORD code = 12345;
    const bool exited = c.ExitsWithin(3000, &code);
    CHECK_MSG(exited, ("exits within 3 s although Ghost never answers (" + std::to_string(GetTickCount64() - t0) +
                       " ms)").c_str());
    CHECK_MSG(code == 0, ("exit code " + std::to_string(code)).c_str());
    // The stuck request was abandoned, and the stop line never went out behind it.
    CHECK(pf_test::WaitUntil([&] { return ghost.LogIngestAbandoned() > abandonedBefore; }, 2000));
    const auto all = ghost.Requests();
    for (size_t i = before; i < all.size(); ++i) {
        CHECK_MSG(all[i].body.find("Port Forwarder stopping") == std::string::npos, "the stop line was dropped");
    }
    CHECK(ingests() == 1);
    ghost.SetLogIngestDelayMs(0);
    CloseHandle(ev);
}

// A handshake it cannot accept is declined with ok:false and an exit.
void HostedHandshakeDeclined() {
    const std::string name = UniqueName("declined");
    HANDLE ev = CreateEventW(nullptr, TRUE, FALSE, pf::Utf8ToWide(name).c_str());
    Child c;
    CHECK(c.Start(HostedEnv(name)));
    json hs = Handshake(name);
    hs["v"] = 2;
    CHECK(c.WriteStdin(pf::DumpSafe(hs) + "\n"));

    const std::string line = c.FirstLine(10000);
    CHECK_MSG(!line.empty(), "a receipt line arrives within 10 s");
    const json r = pf::ParseJsonNoThrow(line.substr(0, line.empty() ? 0 : line.size() - 1));
    CHECK(r.is_object() && r.contains("ok") && r["ok"].is_boolean() && !r["ok"].get<bool>());
    std::string err;
    CHECK(pf::JsonGetString(r, "error", &err) && err.find("bad_v") != std::string::npos);
    CHECK(!r.contains("uiUrl"));
    DWORD code = 0;
    CHECK_MSG(c.ExitsWithin(3000, &code), "a declined plugin exits");
    CHECK(code == 1);
    if (ev) CloseHandle(ev);
}

// A stop event that cannot be opened never makes it exit: exiting would be read by the
// host as a crash and get it restarted.
void HostedUnopenableStopEventBlocks() {
    const std::string name = UniqueName("missing");  // never created
    Child c;
    CHECK(c.Start(HostedEnv(name)));
    CHECK(c.WriteStdin(pf::DumpSafe(Handshake(name)) + "\n"));
    const std::string line = c.FirstLine(10000);
    CHECK_MSG(!UiUrlOfReceipt(line).empty(), line.c_str());
    DWORD code = 0;
    CHECK_MSG(!c.ExitsWithin(1500, &code), "keeps running when the stop event cannot be opened");
}

std::vector<std::wstring> StandaloneArgs(const std::wstring& dir) { return {L"--no-browser", L"--data-dir", dir}; }

// "Management page: <url>\n" -> <url>
std::string UrlOfLine(const std::string& line) {
    const std::string head = "Management page: ";
    if (line.compare(0, head.size(), head) != 0) return std::string();
    std::string url = line.substr(head.size());
    while (!url.empty() && (url.back() == '\n' || url.back() == '\r')) url.pop_back();
    return url;
}

// Standalone (no GHOST_PLUGIN_ID): stdin is a pipe that is never written and never
// closed. A plugin that read it would block forever and never print.
void StandaloneDoesNotReadStdin() {
    pf_test::ScopedTempDir dir;
    Child c;
    CHECK(c.Start({}, StandaloneArgs(dir.path())));
    // A few bytes and no newline: a plugin that read stdin line-wise would block before
    // the banner, and one that read whatever is there would empty the pipe.
    const std::string probe = "probe-bytes";
    CHECK(c.WriteStdin(probe));
    const std::string line = c.FirstLine(10000);
    CHECK_MSG(!line.empty(), "prints a line in standalone mode");
    CHECK(line.find("standalone") != std::string::npos);
    CHECK(line.find("\"ok\"") == std::string::npos);  // not a handshake receipt
    CHECK_MSG(c.Running(), "keeps running in standalone mode");
    // After the banner, the bytes stay unread. Bounded: give a reader one second to show
    // itself, rather than checking once and hoping it had not been scheduled yet.
    CHECK_MSG(c.StdinUnread() == probe.size(), "the probe bytes are in the pipe after the banner");
    CHECK_MSG(!pf_test::WaitUntil([&] { return c.StdinUnread() < probe.size(); }, 1000),
              "standalone never reads stdin, not even after the banner");
}

// Standalone: the page at the printed address, framed by no one; a second instance on the
// same data directory refuses; the page's Stop button ends the process.
void StandalonePageAndQuit() {
    pf_test::ScopedTempDir dir;
    Child c;
    CHECK(c.Start({}, StandaloneArgs(dir.path())));
    const std::vector<std::string> lines = c.Lines(2, 10000);
    CHECK_MSG(lines.size() == 2, "banner and address");
    if (lines.size() != 2) return;
    const std::string url = UrlOfLine(lines[1]);
    CHECK_MSG(!url.empty(), lines[1].c_str());
    unsigned short port = 0;
    std::string prefix;
    CHECK(pf_test::SplitUiUrl(url, &port, &prefix));
    CHECK(prefix.size() == 32);

    const pf_test::HttpReply page = pf_test::RawHttp(port, pf_test::BuildRequest("GET", "/" + prefix + "/", port));
    CHECK(page.status == 200);
    CHECK(page.Header("Content-Security-Policy") ==
          "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors 'none'");
    const json state = pf::ParseJsonNoThrow(
        pf_test::RawHttp(port, pf_test::BuildRequest("GET", "/" + prefix + "/api/state", port)).body);
    CHECK(state.is_object() && state["hosted"] == false && state["canQuit"] == true && state["ghost"] == "needs_ghost");

    // One instance per data directory.
    {
        Child second;
        CHECK(second.Start({}, StandaloneArgs(dir.path())));
        DWORD code = 0;
        CHECK_MSG(second.ExitsWithin(5000, &code), "a second instance on the same data directory exits");
        CHECK(code == 1);
        CHECK(second.AllOutputAfterExit(3000).find("already running") != std::string::npos);
    }
    CHECK(c.Running());

    const pf_test::HttpReply quit = pf_test::RawHttp(
        port, pf_test::BuildRequest("POST", "/" + prefix + "/api/quit", port, "{}",
                                    "http://127.0.0.1:" + std::to_string(port), "application/json"));
    CHECK(quit.status == 200);
    DWORD code = 12345;
    CHECK_MSG(c.ExitsWithin(3000, &code), "the Stop button ends a standalone instance within 3 s");
    CHECK(code == 0);
    // Its log is the local file.
    CHECK(GetFileAttributesW((dir.path() + L"\\port-forwarder.log").c_str()) != INVALID_FILE_ATTRIBUTES);
}

// The exe's VERSIONINFO comes from manifest.json, its only source.
void VersionMatchesManifest() {
    std::string text;
    FILE* f = nullptr;
    if (_wfopen_s(&f, g_manifest.c_str(), L"rb") == 0 && f) {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
        fclose(f);
    }
    const json m = pf::ParseJsonNoThrow(text);
    std::string version;
    CHECK(pf::JsonGetString(m, "version", &version));
    unsigned a = 0, b = 0, c = 0;
    CHECK(sscanf_s(version.c_str(), "%u.%u.%u", &a, &b, &c) == 3);

    DWORD ignored = 0;
    const DWORD size = GetFileVersionInfoSizeW(g_exe.c_str(), &ignored);
    CHECK(size > 0);
    std::vector<unsigned char> data(size ? size : 1);
    CHECK(GetFileVersionInfoW(g_exe.c_str(), 0, size, data.data()));
    VS_FIXEDFILEINFO* ffi = nullptr;
    UINT len = 0;
    CHECK(VerQueryValueW(data.data(), L"\\", reinterpret_cast<void**>(&ffi), &len) && ffi);
    if (ffi) {
        CHECK(HIWORD(ffi->dwFileVersionMS) == a);
        CHECK(LOWORD(ffi->dwFileVersionMS) == b);
        CHECK(HIWORD(ffi->dwFileVersionLS) == c);
        CHECK(LOWORD(ffi->dwFileVersionLS) == 0);
    }
    wchar_t* str = nullptr;
    CHECK(VerQueryValueW(data.data(), L"\\StringFileInfo\\040904b0\\FileVersion", reinterpret_cast<void**>(&str),
                         &len) &&
          str);
    if (str) CHECK_MSG(pf::WideToUtf8(str) == version, ("FileVersion string " + pf::WideToUtf8(str)).c_str());
}

std::wstring Backslashes(std::wstring p) {
    for (auto& ch : p)
        if (ch == L'/') ch = L'\\';
    return p;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc < 3) {
        std::fprintf(stderr, "usage: test_main_exe <port-forwarder.exe> <manifest.json>\n");
        return 2;
    }
    g_exe = Backslashes(argv[1]);
    g_manifest = Backslashes(argv[2]);

    pf_test::WinsockScope wsa;
    CHECK(wsa.ok());
    pf_test::FakeGhost ghost;
    CHECK(ghost.Start());
    pf_test::ScopedTempDir dataDir;
    CHECK(dataDir.ok());
    g_dataDir = pf::WideToUtf8(dataDir.path());
    g_apiBase = ghost.apiBase();

    HostedHandshakeAndStop(ghost);
    HostedStalledLogStillExits(ghost);
    HostedHandshakeDeclined();
    HostedUnopenableStopEventBlocks();
    StandaloneDoesNotReadStdin();
    StandalonePageAndQuit();
    VersionMatchesManifest();
    ghost.Stop();
    return pf_test::TestExitCode();
}
