// Integration: the real port-forwarder.exe, started the way the Ghost plugin host starts
// it -- pipes for stdin/stdout, stderr on NUL, CREATE_NO_WINDOW, exactly these three
// handles inherited, GHOST_PLUGIN_* in the environment.
//
// argv[1] = path of port-forwarder.exe, argv[2] = path of manifest.json.

#include "json_util.h"
#include "test_support.h"
#include "util_str.h"

#include <cstdio>
#include <mutex>
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
        if (reader_.joinable()) reader_.join();  // ends once the child's stdout is closed
        if (stdoutR_) CloseHandle(stdoutR_);
        if (pi_.hThread) CloseHandle(pi_.hThread);
        if (pi_.hProcess) CloseHandle(pi_.hProcess);
    }

    bool Start(const std::vector<std::pair<std::wstring, std::wstring>>& env) {
        SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
        HANDLE inR = nullptr, outW = nullptr;
        if (!CreatePipe(&inR, &stdinW_, &sa, 64 * 1024)) return false;
        if (!CreatePipe(&stdoutR_, &outW, &sa, 64 * 1024)) return false;
        SetHandleInformation(stdinW_, HANDLE_FLAG_INHERIT, 0);
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

    bool WriteStdin(const std::string& s) {
        DWORD n = 0;
        return WriteFile(stdinW_, s.data(), static_cast<DWORD>(s.size()), &n, nullptr) && n == s.size();
    }

    // The first stdout line (with its '\n') once it arrives within `ms`; "" otherwise.
    std::string FirstLine(DWORD ms) {
        std::string line;
        WaitUntil_([&] {
            std::lock_guard<std::mutex> lock(mu_);
            const size_t nl = out_.find('\n');
            if (nl == std::string::npos) return false;
            line = out_.substr(0, nl + 1);
            return true;
        }, ms);
        return line;
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

private:
    static bool WaitUntil_(const std::function<bool()>& f, DWORD ms) { return pf_test::WaitUntil(f, ms); }

    PROCESS_INFORMATION pi_ = {};
    HANDLE stdinW_ = nullptr;
    HANDLE stdoutR_ = nullptr;
    std::thread reader_;
    std::mutex mu_;
    std::string out_;
    bool eof_ = false;
    ULONGLONG started_ = 0;
};

json Handshake(const std::string& stopEvent) {
    json j = json::object();
    j["v"] = 1;
    j["pluginId"] = kId;
    j["pluginDir"] = "C:\\plugins\\com.qtvz.xieyos.port-forwarder\\1.0.0";
    j["dataDir"] = "C:\\plugins\\com.qtvz.xieyos.port-forwarder\\.data";
    j["apiBase"] = "http://127.0.0.1:23551";
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
        {L"GHOST_PLUGIN_DATA_DIR", L"C:\\plugins\\com.qtvz.xieyos.port-forwarder\\.data"},
        {L"GHOST_PLUGIN_API_BASE", L"http://127.0.0.1:23551"},
        {L"GHOST_PLUGIN_STOP_EVENT", pf::Utf8ToWide(stopEvent)},
    };
}

// Hosted, happy path: receipt within 10 s, then a clean exit within 3 s of the stop event.
void HostedHandshakeAndStop() {
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
    CHECK_MSG(line == "{\"v\":1,\"ok\":true}\n", line.c_str());
    const json r = pf::ParseJsonNoThrow(line.substr(0, line.empty() ? 0 : line.size() - 1));
    long long v = 0;
    CHECK(pf::JsonGetInt64(r, "v", &v) && v == 1);
    CHECK(r.is_object() && r.contains("ok") && r["ok"].is_boolean() && r["ok"].get<bool>());

    // It waits for the stop event rather than exiting on its own.
    CHECK_MSG(c.Running(), "still running after the receipt");

    SetEvent(ev);
    DWORD code = 12345;
    CHECK_MSG(c.ExitsWithin(3000, &code), "exits within 3 s of the stop event");
    CHECK_MSG(code == 0, ("exit code " + std::to_string(code)).c_str());
    // Nothing but the receipt was ever written to stdout.
    CHECK(c.AllOutputAfterExit(3000) == line);
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
    CHECK_MSG(line == "{\"v\":1,\"ok\":true}\n", line.c_str());
    DWORD code = 0;
    CHECK_MSG(!c.ExitsWithin(1500, &code), "keeps running when the stop event cannot be opened");
}

// Standalone (no GHOST_PLUGIN_ID): stdin is a pipe that is never written and never
// closed. A plugin that read it would block forever and never print.
void StandaloneDoesNotReadStdin() {
    Child c;
    CHECK(c.Start({}));
    const std::string line = c.FirstLine(10000);
    CHECK_MSG(!line.empty(), "prints a line in standalone mode");
    CHECK(line.find("standalone") != std::string::npos);
    CHECK(line.find("\"ok\"") == std::string::npos);  // not a handshake receipt
    CHECK_MSG(c.Running(), "keeps running in standalone mode");
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

    HostedHandshakeAndStop();
    HostedHandshakeDeclined();
    HostedUnopenableStopEventBlocks();
    StandaloneDoesNotReadStdin();
    VersionMatchesManifest();
    return pf_test::TestExitCode();
}
