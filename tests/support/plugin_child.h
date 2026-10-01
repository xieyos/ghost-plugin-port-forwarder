// The real port-forwarder.exe as a child process, started the way the Ghost plugin host
// starts it: pipes for stdin/stdout, stderr on NUL, CREATE_NO_WINDOW, exactly these three
// handles inherited (PROC_THREAD_ATTRIBUTE_HANDLE_LIST), and an environment that is ours minus
// every GHOST_PLUGIN_* variable plus whatever the test passes. stdout is read on a thread so
// that a test can wait for lines with a bound. Shared by test_main_exe and test_end_to_end.
#pragma once

#include "json_util.h"
#include "test_support.h"
#include "util_str.h"

#include <atomic>
#include <cwchar>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <regex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace pf_test {

inline std::string UniqueName(const char* tag) {
    static std::atomic<int> counter{0};
    return std::string("Local\\pf_test_exe_") + tag + "_" + std::to_string(GetCurrentProcessId()) + "_" +
           std::to_string(++counter) + "_" + std::to_string(GetTickCount64());
}

inline bool StartsWithNoCase(const std::wstring& s, const wchar_t* prefix) {
    const size_t n = wcslen(prefix);
    return s.size() >= n && _wcsnicmp(s.c_str(), prefix, n) == 0;
}

// Our environment minus every GHOST_PLUGIN_* variable, plus `extra`.
inline std::wstring BuildEnvBlock(const std::vector<std::pair<std::wstring, std::wstring>>& extra) {
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
    explicit Child(std::wstring exe) : exe_(std::move(exe)) {}
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;

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
        std::wstring cmd = L"\"" + exe_ + L"\"";
        for (const auto& a : args) cmd += L" \"" + a + L"\"";
        if (ok) {
            ok = CreateProcessW(exe_.c_str(), cmd.data(), nullptr, nullptr, TRUE,
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

    std::wstring exe_;
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

// ---- The hosted handshake, and the two ways the plugin says where its page is ----------

constexpr const char* kPluginId = "com.qtvz.xieyos.port-forwarder";

inline pf::json HostedHandshake(const std::string& stopEvent, const std::string& dataDir, const std::string& apiBase,
                                const std::vector<std::string>& permissions = {"upstream.connect", "log.write"}) {
    pf::json j = pf::json::object();
    j["v"] = 1;
    j["pluginId"] = kPluginId;
    j["pluginDir"] = "C:\\plugins\\com.qtvz.xieyos.port-forwarder\\1.0.0";
    j["dataDir"] = dataDir;
    j["apiBase"] = apiBase;
    j["token"] = "{11111111-2222-3333-4444-555555555555}";
    pf::json perms = pf::json::array();
    for (const auto& p : permissions) perms.push_back(p);
    j["permissions"] = perms;
    j["settings"] = pf::json::object();
    j["lang"] = "en";
    j["stopEvent"] = stopEvent;
    return j;
}

inline std::vector<std::pair<std::wstring, std::wstring>> HostedEnv(const std::string& stopEvent,
                                                                 const std::string& dataDir,
                                                                 const std::string& apiBase) {
    return {
        {L"GHOST_PLUGIN_ID", pf::Utf8ToWide(kPluginId)},
        {L"GHOST_PLUGIN_DIR", L"C:\\plugins\\com.qtvz.xieyos.port-forwarder\\1.0.0"},
        {L"GHOST_PLUGIN_DATA_DIR", pf::Utf8ToWide(dataDir)},
        {L"GHOST_PLUGIN_API_BASE", pf::Utf8ToWide(apiBase)},
        {L"GHOST_PLUGIN_STOP_EVENT", pf::Utf8ToWide(stopEvent)},
    };
}

// The receipt line -> its uiUrl, checked against the host's rules (spec-host-protocol.md
// 3.2, spec-manifest.md 5, spec-limits.md): "" when anything is off.
inline std::string UiUrlOfReceipt(const std::string& line) {
    if (line.empty() || line.back() != '\n') return std::string();
    const pf::json r = pf::ParseJsonNoThrow(line.substr(0, line.size() - 1));
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

// "Management page: <url>\n" -> <url>
inline std::string UrlOfLine(const std::string& line) {
    const std::string head = "Management page: ";
    if (line.compare(0, head.size(), head) != 0) return std::string();
    std::string url = line.substr(head.size());
    while (!url.empty() && (url.back() == '\n' || url.back() == '\r')) url.pop_back();
    return url;
}

}  // namespace pf_test
