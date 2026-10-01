// Port Forwarder -- a Ghost Proxifier plugin.
//
// Hosted or standalone is decided by GHOST_PLUGIN_ID alone (spec-host-protocol.md 3.0).
// Hosted: one handshake line in, one receipt line out, then run until the host's stop
// event. Standalone: never touch stdin, run until Ctrl+C.

#include "build_info.h"
#include "host_handshake.h"

#include <windows.h>

#include <exception>
#include <string>

namespace {

HANDLE g_consoleStop = nullptr;

BOOL WINAPI OnConsoleCtrl(DWORD type) {
    switch (type) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
            if (g_consoleStop) SetEvent(g_consoleStop);
            return TRUE;
        default:
            return FALSE;
    }
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

    pf::WriteReceipt(out, true, std::string());
    stop.WaitForever();
    return 0;
}

int RunStandalone() {
    g_consoleStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_consoleStop) return 1;
    SetConsoleCtrlHandler(OnConsoleCtrl, TRUE);

    const std::string banner =
        "Port Forwarder " PF_VERSION " -- running standalone, without Ghost. Press Ctrl+C to exit.\n";
    pf::WriteLine(GetStdHandle(STD_OUTPUT_HANDLE), banner);

    WaitForSingleObject(g_consoleStop, INFINITE);
    return 0;
}

}  // namespace

int wmain() {
    try {
        return pf::IsHosted() ? RunHosted() : RunStandalone();
    } catch (const std::exception&) {
        return 3;
    } catch (...) {
        return 3;
    }
}
