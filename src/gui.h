// The standalone window (Slint, src/gui/main_window.slint): the page's rules, statuses and
// editor in a native window, for running without Ghost. Hosted, Ghost shows the page and this
// is never opened.
//
// The window is one more client of the page's API: every read and write goes through
// GuiOptions::call -- App::Handle -- on a worker thread, so that what the window may do is
// exactly what the page may do, judged by the same code, and the window never waits on the
// engine.
//
// This header carries no Slint type: gui.cpp is the only file compiled against Slint (C++20),
// and everything else stays as it is.
#pragma once

#include <functional>
#include <string>

namespace pf {

struct GuiReply {
    int status = 0;
    std::string body;  // JSON
};

// method "GET" or "POST", path as the page names it ("api/state"), body JSON or "".
using GuiCall = std::function<GuiReply(const std::string& method, const std::string& path, const std::string& body)>;

struct GuiOptions {
    GuiCall call;
    std::string version;
    std::string dataDir;  // UTF-8, shown at the bottom of the window
    std::string langTag;  // the user's UI language, e.g. "zh-CN"
};

// Opens the window and runs its event loop on the calling thread until the window is closed,
// File > Exit is chosen, or GuiQuit() is called. Returns once the worker thread has finished
// its last call, so that the caller may stop the App right after.
void RunGui(const GuiOptions& opts);

// From any thread, at any time, any number of times: ends RunGui (before RunGui has opened
// the window, it makes RunGui return without opening it).
void GuiQuit();

}  // namespace pf
