// The one handshake with the Ghost plugin host (spec-host-protocol.md section 3).
//
// Hosted or standalone is decided by one thing only: whether GHOST_PLUGIN_ID exists in
// the environment. Never by whether stdin is readable -- in a terminal stdin is always
// readable and a read would block forever.
//
// Hosted: read one line of JSON from stdin, answer one line on stdout, flush. After that
// line nothing else is ever written to stdout (the host discards it anyway).
#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace pf {

// Names and values as in spec-limits.md:
// kMaxHostLineBytes -- one line the host writes to our stdin is at most 16 KB,
// excluding the '\n'.
constexpr size_t kMaxHostLineBytes = 16 * 1024;
// kMaxHandshakeLineBytes -- our answer (the first stdout line), '\n' included, is at
// most 4 KB; it must be written within 10 s (kHandshakeTimeoutMs) of starting.
constexpr size_t kMaxHandshakeLineBytes = 4 * 1024;
// Tokens go into an HTTP header: 1..128 characters of [0-9A-Za-z{}-].
constexpr size_t kMaxTokenChars = 128;
// lang is a short tag ("zh", "en", "zh-CN"): at most 16 of [A-Za-z0-9_-].
constexpr size_t kMaxLangChars = 16;

struct Handshake {
    std::string pluginId;
    std::string pluginDir;
    std::string dataDir;
    std::string apiBase;   // exactly "http://127.0.0.1:<port>"
    uint16_t apiPort = 0;  // the <port> of apiBase
    std::string token;
    std::vector<std::string> permissions;  // the granted ones
    std::string lang;                      // "" when the host sent none; else 1..16 of [A-Za-z0-9_-]
    std::string stopEvent;                 // the name to open, used verbatim

    bool HasPermission(const std::string& name) const;
};

// What the host also put in our environment. The handshake must agree with it.
struct HostEnv {
    bool hasPluginId = false;
    std::string pluginId;
    bool hasStopEvent = false;
    std::string stopEvent;
};

// GHOST_PLUGIN_ID and GHOST_PLUGIN_STOP_EVENT, read through the W API.
HostEnv ReadHostEnv();

// True when GHOST_PLUGIN_ID exists (even if empty). The only hosted/standalone switch.
bool IsHosted();

// "http://127.0.0.1:<1..65535>" and nothing else: no path, no trailing slash, no
// leading zeros, lower-case scheme, the literal loopback address.
bool ParseApiBase(const std::string& s, uint16_t* port);

// 1..128 characters of [0-9A-Za-z{}-].
bool IsTokenShaped(const std::string& s);

// True when `s` holds a control character (< 0x20, embedded NUL included) or 0x7F.
// Names and paths from the host go to Win32 calls that stop at the first NUL: a name
// with one would be judged in full and used truncated.
bool HasControlChar(const std::string& s);

// An absolute Windows path: "X:\..." with a drive letter, or "\\..." (UNC, \\?\).
bool IsAbsoluteWindowsPath(const std::string& s);

// Validates one handshake line (without its '\n'). pluginDir and dataDir must be
// absolute Windows paths; they, and stopEvent, must hold no control character; lang,
// when present, is 1..16 of [A-Za-z0-9_-]. Returns "" and fills `out` on success,
// otherwise a short reason code:
//   bad_json, bad_v, bad_plugin_id, bad_plugin_dir, bad_data_dir, bad_api_base,
//   bad_token, bad_permissions, bad_lang, bad_stop_event
std::string ParseHandshake(const std::string& line, const HostEnv& env, Handshake* out);

enum class LineResult { Ok, TooLong, Eof, ReadError };

// Reads one '\n'-terminated line with at most `maxBytes` bytes before the '\n' (one
// trailing '\r' is then dropped from the result). Stops as soon as the line is known to
// be too long and never buffers more than maxBytes + 1 bytes. Bytes after the '\n' are
// discarded -- the handshake is the only thing ever read from stdin.
LineResult ReadLine(HANDLE h, size_t maxBytes, std::string* line);

// ReadLine + ParseHandshake. Adds the reason codes line_too_long and no_line.
std::string ReadHandshake(HANDLE in, const HostEnv& env, Handshake* out);

// The receipt line, '\n' included, never longer than kMaxHandshakeLineBytes:
//   ok:    {"v":1,"ok":true}  or  {"v":1,"ok":true,"uiUrl":"..."}
//   error: {"v":1,"ok":false,"error":"..."}  (the text is cut to fit, on a UTF-8
//          boundary)
std::string FormatReceiptOk(const std::string& uiUrl);
std::string FormatReceiptError(const std::string& error);

// Writes the whole line with WriteFile (no user-mode buffer, so nothing is left to
// flush). Returns false if any byte could not be written.
bool WriteLine(HANDLE out, const std::string& line);

// The receipt: FormatReceiptOk(uiUrlOrError) or FormatReceiptError(uiUrlOrError), written
// with WriteLine. Call it exactly once, and write nothing else to stdout afterwards.
bool WriteReceipt(HANDLE out, bool ok, const std::string& uiUrlOrError);

// The stop event. Its name comes from the handshake and is opened verbatim -- it is
// never constructed here: the host may have started us through another process, and a
// name built from our own pid would never match.
class StopEvent {
public:
    StopEvent() = default;
    ~StopEvent();
    StopEvent(const StopEvent&) = delete;
    StopEvent& operator=(const StopEvent&) = delete;

    // OpenEventW(SYNCHRONIZE, FALSE, name). False if it cannot be opened.
    bool Open(const std::string& name);
    bool IsOpen() const { return handle_ != nullptr; }

    // True once the event is signalled within `ms`; false on timeout or if not open.
    bool WaitFor(DWORD ms) const;

    // Returns when the event is signalled. If the event could not be opened this never
    // returns: exiting would look like a crash to the host and get us restarted, while
    // blocking leaves the host's stop timeout to end the process.
    void WaitForever() const;

private:
    HANDLE handle_ = nullptr;
};

}  // namespace pf
