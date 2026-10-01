// Port Forwarder -- a Ghost Proxifier plugin.
//
// Hosted or standalone is decided by GHOST_PLUGIN_ID alone (spec-host-protocol.md 3.0).
//
// Hosted, in this order:
//   handshake (one line in) -> start the page server -> receipt with uiUrl (one line out) ->
//   load rules.json -> start the log and the engine -> wait for the host's stop event ->
//   stop: engine (2 s budget), page server, log (its last batch), Ghost API -> exit 0.
// The host allows 3 s from its stop event to our exit; ExitDeadline makes that a promise
// rather than a hope (see below).
//
// Standalone (no Ghost; direct rules only, via-node rules show needs_ghost and do not
// listen): data directory %LOCALAPPDATA%\<id>\ or --data-dir <dir>, one instance per data
// directory (a named mutex), the page opened in the default browser unless --no-browser,
// its address printed. Ctrl+C, closing the console window, or the page's Stop button
// (POST api/quit) ends it the same way as the stop event. stdin is never read.

#include "app.h"
#include "applog.h"
#include "build_info.h"
#include "ghost_api.h"
#include "host_handshake.h"
#include "paths.h"
#include "rule_store.h"
#include "tunnel_client.h"
#include "tunnel_source.h"
#include "ui_server.h"
#include "util_str.h"

#include <winsock2.h>
#include <windows.h>
#include <objbase.h>
#include <shellapi.h>

#include <exception>
#include <memory>
#include <string>
#include <thread>

namespace {

// Shutdown is ordered so that each step's waits are bounded, but the last batch of the log
// waits on Ghost; ExitDeadline bounds the whole: at kAbortAtMs after the stop began it
// shuts the Ghost API down (that batch is then cancelled instead of sent), and at
// kKillAtMs it ends the process with exit code 0 regardless -- leaving the host's 3 s budget
// to a stuck call would get the plugin killed and reported as not stopping.
constexpr DWORD kAbortAtMs = 2500;
constexpr DWORD kKillAtMs = 2850;
// How long the console handler holds a close/logoff/shutdown event while main shuts down.
// Windows ends the process when the handler returns and grants about 5 s.
constexpr DWORD kConsoleCloseWaitMs = 4000;

class ExitDeadline {
public:
    explicit ExitDeadline(std::shared_ptr<pf::GhostApi> api) : api_(std::move(api)) {
        done_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!done_) return;
        try {
            thread_ = std::thread([this] {
                if (WaitForSingleObject(done_, kAbortAtMs) != WAIT_TIMEOUT) return;
                try {
                    if (api_) api_->Shutdown();
                } catch (...) {
                }
                if (WaitForSingleObject(done_, kKillAtMs - kAbortAtMs) != WAIT_TIMEOUT) return;
                TerminateProcess(GetCurrentProcess(), 0);
            });
        } catch (...) {
        }
    }
    ~ExitDeadline() {
        if (done_) SetEvent(done_);
        if (thread_.joinable()) thread_.join();
        if (done_) CloseHandle(done_);
    }
    ExitDeadline(const ExitDeadline&) = delete;
    ExitDeadline& operator=(const ExitDeadline&) = delete;

private:
    std::shared_ptr<pf::GhostApi> api_;
    HANDLE done_ = nullptr;
    std::thread thread_;
};

// Standalone: Ctrl+C / Break / close set g_quit; main sets g_shutdownDone when it is done.
HANDLE g_quit = nullptr;
HANDLE g_shutdownDone = nullptr;

BOOL WINAPI OnConsoleCtrl(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
            // main carries on and shuts down; nothing to wait for here.
            if (g_quit) SetEvent(g_quit);
            return TRUE;
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            // The process ends as soon as this returns: hold it, bounded, until main has
            // stopped the listeners and flushed the log.
            if (g_quit) SetEvent(g_quit);
            if (g_shutdownDone) WaitForSingleObject(g_shutdownDone, kConsoleCloseWaitMs);
            return TRUE;
        default:
            return FALSE;
    }
}

pf::LogFn MakeLogFn(const std::shared_ptr<pf::AppLog>& log, const std::shared_ptr<pf::GhostApi>& api) {
    // Captures the AppLog -- and the GhostApi its raw pointer refers to -- by shared_ptr: a
    // straggler thread may log after everything here is gone (forward_common.h).
    return [log, api](pf::LogLevel level, const std::string& text, const pf::LogFields& fields) {
        log->Write(level, text, fields);
    };
}

// The page address is never logged: its prefix is what keeps other local programs out.
void LogStartup(const pf::LogFn& log, const pf::LoadResult& r, bool hosted) {
    const std::string mode = hosted ? "hosted" : "standalone";
    log(pf::LogLevel::Info,
        std::string("Port Forwarder ") + PF_VERSION + " started (" + mode + "), " + std::to_string(r.rules.size()) +
            " rule(s)",
        {});
    if (r.staleTempsRemoved > 0) {
        log(pf::LogLevel::Info, "removed " + std::to_string(r.staleTempsRemoved) + " leftover temporary rules file(s)",
            {});
    }
    if (r.status == pf::LoadStatus::Corrupt) {
        const size_t slash = r.corruptPath.find_last_of(L"\\/");
        const std::string kept =
            pf::WideToUtf8(slash == std::wstring::npos ? r.corruptPath : r.corruptPath.substr(slash + 1));
        log(pf::LogLevel::Warn,
            r.corruptPath.empty()
                ? "rules.json is invalid (" + r.code + ") and could not be moved aside; nothing will be saved"
                : "rules.json was invalid (" + r.code + "); it was kept as " + kept +
                      " and the plugin started with no rules",
            {});
    } else if (r.status == pf::LoadStatus::Unreadable) {
        log(pf::LogLevel::Error, "rules.json could not be read (" + r.code + "); nothing will be saved until it can",
            {{"detail", r.detail}});
    }
}

void ShutDown(pf::App& app, pf::UiServer& ui, pf::AppLog& log, const std::shared_ptr<pf::GhostApi>& api) {
    ExitDeadline deadline(api);
    log.Write(pf::LogLevel::Info, "Port Forwarder stopping");
    app.Stop();  // listeners and connections, within the engine's 2 s
    ui.Stop();
    log.Stop();  // the last batch -- before the API it is sent through is shut down
    if (api) api->Shutdown();
}

int RunHosted() {
    const HANDLE in = GetStdHandle(STD_INPUT_HANDLE);
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);

    pf::Handshake hs;
    const std::string err = pf::ReadHandshake(in, pf::ReadHostEnv(), &hs);
    if (!err.empty()) {
        // The host treats ok:false as "declined" and does not restart us.
        pf::WriteReceipt(out, false, "handshake rejected: " + err);
        return 1;
    }

    // Opened before answering so that a stop requested right after the receipt cannot
    // be missed. If it cannot be opened we still answer ok and then block for good:
    // exiting would look like a crash and get us restarted.
    pf::StopEvent stop;
    stop.Open(hs.stopEvent);

    const bool permitted = hs.HasPermission(pf::kPermUpstreamConnect);
    pf::GhostApiOptions apiOpts;
    apiOpts.apiBase = hs.apiBase;
    apiOpts.token = hs.token;
    auto api = std::make_shared<pf::GhostApi>(apiOpts);
    pf::TunnelClientOptions tco;
    tco.api = api.get();
    tco.permitted = permitted;
    auto client = std::make_shared<pf::TunnelClient>(tco);
    auto tunnel = std::make_shared<pf::ClientTunnelSource>(api, client, permitted);

    const std::wstring dataDir = pf::Utf8ToWide(hs.dataDir);
    pf::AppLogOptions lo;
    lo.api = api.get();
    lo.canWrite = hs.HasPermission(pf::kPermLogWrite);
    lo.localDir = dataDir;
    auto log = std::make_shared<pf::AppLog>(lo);
    const pf::LogFn logFn = MakeLogFn(log, api);

    pf::AppOptions ao;
    ao.hosted = true;
    ao.dataDir = dataDir;
    ao.lang = hs.lang;
    ao.permitted = permitted;
    ao.nodes = client;
    ao.tunnel = tunnel;
    ao.log = logFn;
    auto app = std::make_shared<pf::App>(ao);

    pf::UiServerOptions uo;
    uo.handler = [app](const pf::UiRequest& r) { return app->Handle(r); };
    uo.frameAncestor = hs.apiBase;  // only Ghost's page may frame ours
    pf::UiServer ui(uo);
    std::string uiErr;
    if (!ui.Start(&uiErr) || !pf::IsUiUrlShaped(ui.url())) {
        pf::WriteReceipt(out, false, "management page server: " + (uiErr.empty() ? std::string("bad url") : uiErr));
        return 1;
    }
    pf::WriteReceipt(out, true, ui.url());

    const pf::LoadResult loaded = app->LoadRules();
    log->Start();
    LogStartup(logFn, loaded, true);
    app->StartEngine();

    stop.WaitForever();
    ShutDown(*app, ui, *log, api);
    return 0;
}

struct StandaloneArgs {
    std::wstring dataDir;  // "" = the default
    bool noBrowser = false;
    std::string error;
};

StandaloneArgs ParseArgs(int argc, wchar_t** argv) {
    StandaloneArgs a;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--no-browser") {
            a.noBrowser = true;
        } else if (arg == L"--data-dir") {
            if (i + 1 >= argc || argv[i + 1][0] == L'\0') {
                a.error = "--data-dir needs a directory";
                return a;
            }
            a.dataDir = argv[++i];
        } else {
            a.error = "unknown argument: " + pf::WideToUtf8(arg);
            return a;
        }
    }
    return a;
}

int RunStandalone(int argc, wchar_t** argv) {
    const HANDLE out = GetStdHandle(STD_OUTPUT_HANDLE);
    const StandaloneArgs args = ParseArgs(argc, argv);
    if (!args.error.empty()) {
        pf::WriteLine(out, "port-forwarder: " + args.error +
                               "\nusage: port-forwarder [--data-dir <dir>] [--no-browser]\n");
        return 2;
    }
    const bool isDefault = args.dataDir.empty();
    const std::wstring dataDir = isDefault ? pf::DefaultStandaloneDataDir() : pf::FullPath(args.dataDir);
    std::string dirErr;
    if (dataDir.empty() || !pf::EnsureDirectory(dataDir, &dirErr)) {
        pf::WriteLine(out, "port-forwarder: cannot use the data directory " + pf::WideToUtf8(dataDir) + ": " +
                               (dirErr.empty() ? std::string("no path") : dirErr) + "\n");
        return 1;
    }
    HANDLE mutex = CreateMutexW(nullptr, FALSE, pf::StandaloneMutexName(dataDir, isDefault).c_str());
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) {
        pf::WriteLine(out, "port-forwarder: another standalone instance is already running for " +
                               pf::WideToUtf8(dataDir) + "\n");
        if (mutex) CloseHandle(mutex);
        return 1;
    }

    g_quit = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    g_shutdownDone = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_quit || !g_shutdownDone) return 1;
    SetConsoleCtrlHandler(OnConsoleCtrl, TRUE);

    pf::AppLogOptions lo;
    lo.localDir = dataDir;
    auto log = std::make_shared<pf::AppLog>(lo);
    const pf::LogFn logFn = MakeLogFn(log, nullptr);

    pf::AppOptions ao;
    ao.hosted = false;
    ao.dataDir = dataDir;
    ao.log = logFn;
    ao.onQuit = [] { SetEvent(g_quit); };
    auto app = std::make_shared<pf::App>(ao);

    const pf::LoadResult loaded = app->LoadRules();
    log->Start();

    pf::UiServerOptions uo;
    uo.handler = [app](const pf::UiRequest& r) { return app->Handle(r); };
    // frameAncestor stays "": frame-ancestors 'none'.
    pf::UiServer ui(uo);
    std::string uiErr;
    if (!ui.Start(&uiErr)) {
        pf::WriteLine(out, "port-forwarder: the management page could not start: " + uiErr + "\n");
        ShutDown(*app, ui, *log, nullptr);
        SetEvent(g_shutdownDone);
        CloseHandle(mutex);
        return 1;
    }
    LogStartup(logFn, loaded, false);
    app->StartEngine();

    pf::WriteLine(out, std::string("Port Forwarder ") + PF_VERSION +
                           " -- running standalone, without Ghost. Press Ctrl+C to exit.\n"
                           "Management page: " +
                           ui.url() + "\n");
    if (!args.noBrowser) {
        const HRESULT co = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
        const std::wstring url = pf::Utf8ToWide(ui.url());
        const HINSTANCE h = ShellExecuteW(nullptr, L"open", url.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        if (reinterpret_cast<INT_PTR>(h) <= 32) {
            pf::WriteLine(out, "(could not open a browser; open the address above)\n");
        }
        if (SUCCEEDED(co)) CoUninitialize();
    }

    WaitForSingleObject(g_quit, INFINITE);
    ShutDown(*app, ui, *log, nullptr);
    SetEvent(g_shutdownDone);
    CloseHandle(mutex);
    return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // A Winsock reference for the whole life of the process, never released. Adopted tunnel
    // sockets can outlive every object that took its own reference (the tunnel client, a
    // forwarder); the last WSACleanup must never run under a live socket. The process exit
    // releases it. A failure is not fatal here (the handshake must still be answered); every
    // socket user then reports its own failure.
    WSADATA wsa;
    (void)WSAStartup(MAKEWORD(2, 2), &wsa);
    try {
        // Hosted: the command line is the manifest's args (none); it is not read.
        return pf::IsHosted() ? RunHosted() : RunStandalone(argc, argv);
    } catch (const std::exception&) {
        return 3;
    } catch (...) {
        return 3;
    }
}
