#include "host_handshake.h"

#include "json_util.h"
#include "util_str.h"

#include <algorithm>
#include <cstring>

namespace pf {

bool Handshake::HasPermission(const std::string& name) const {
    return std::find(permissions.begin(), permissions.end(), name) != permissions.end();
}

HostEnv ReadHostEnv() {
    HostEnv e;
    e.hasPluginId = GetEnvUtf8(L"GHOST_PLUGIN_ID", &e.pluginId);
    e.hasStopEvent = GetEnvUtf8(L"GHOST_PLUGIN_STOP_EVENT", &e.stopEvent);
    return e;
}

bool IsHosted() {
    return GetEnvUtf8(L"GHOST_PLUGIN_ID", nullptr);
}

bool ParseApiBase(const std::string& s, uint16_t* port) {
    static const char kPrefix[] = "http://127.0.0.1:";
    const size_t prefixLen = sizeof(kPrefix) - 1;
    if (s.size() <= prefixLen || s.compare(0, prefixLen, kPrefix) != 0) return false;
    const std::string digits = s.substr(prefixLen);
    if (digits.size() > 5 || digits[0] == '0') return false;
    unsigned long value = 0;
    for (char c : digits) {
        if (c < '0' || c > '9') return false;
        value = value * 10 + static_cast<unsigned long>(c - '0');
    }
    if (value < 1 || value > 65535) return false;
    if (port) *port = static_cast<uint16_t>(value);
    return true;
}

bool IsTokenShaped(const std::string& s) {
    if (s.empty() || s.size() > kMaxTokenChars) return false;
    for (unsigned char c : s) {
        const bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '{' ||
                        c == '}' || c == '-';
        if (!ok) return false;
    }
    return true;
}

std::string ParseHandshake(const std::string& line, const HostEnv& env, Handshake* out) {
    const json j = ParseJsonNoThrow(line);
    if (!j.is_object()) return "bad_json";

    long long v = 0;
    if (!JsonGetInt64(j, "v", &v) || v != 1) return "bad_v";

    Handshake hs;
    if (!JsonGetString(j, "pluginId", &hs.pluginId) || hs.pluginId.empty() || !env.hasPluginId ||
        hs.pluginId != env.pluginId) {
        return "bad_plugin_id";
    }
    if (!JsonGetString(j, "pluginDir", &hs.pluginDir) || hs.pluginDir.empty()) return "bad_plugin_dir";
    if (!JsonGetString(j, "dataDir", &hs.dataDir) || hs.dataDir.empty()) return "bad_data_dir";
    if (!JsonGetString(j, "apiBase", &hs.apiBase) || !ParseApiBase(hs.apiBase, &hs.apiPort)) return "bad_api_base";
    if (!JsonGetString(j, "token", &hs.token) || !IsTokenShaped(hs.token)) return "bad_token";
    if (!JsonGetStringArray(j, "permissions", &hs.permissions)) return "bad_permissions";
    if (j.contains("lang") && !JsonGetString(j, "lang", &hs.lang)) return "bad_lang";
    if (!JsonGetString(j, "stopEvent", &hs.stopEvent) || hs.stopEvent.empty()) return "bad_stop_event";
    if (env.hasStopEvent && hs.stopEvent != env.stopEvent) return "bad_stop_event";

    if (out) *out = std::move(hs);
    return std::string();
}

LineResult ReadLine(HANDLE h, size_t maxBytes, std::string* line) {
    std::string buf;
    char chunk[4096];
    for (;;) {
        // buf.size() <= maxBytes here, so at least one byte is requested and the total
        // buffered never exceeds maxBytes + 1.
        const size_t want = std::min(sizeof(chunk), maxBytes + 1 - buf.size());
        DWORD got = 0;
        if (!ReadFile(h, chunk, static_cast<DWORD>(want), &got, nullptr)) {
            const DWORD e = GetLastError();
            return (e == ERROR_BROKEN_PIPE || e == ERROR_HANDLE_EOF) ? LineResult::Eof : LineResult::ReadError;
        }
        if (got == 0) return LineResult::Eof;
        const char* nl = static_cast<const char*>(memchr(chunk, '\n', got));
        if (nl) {
            // Never too long here: `want` stops the reads at maxBytes + 1 bytes, so a
            // newline that was read sits at most at index maxBytes of the line.
            buf.append(chunk, static_cast<size_t>(nl - chunk));
            if (!buf.empty() && buf.back() == '\r') buf.pop_back();
            if (line) *line = std::move(buf);
            return LineResult::Ok;
        }
        buf.append(chunk, got);
        if (buf.size() > maxBytes) return LineResult::TooLong;
    }
}

std::string ReadHandshake(HANDLE in, const HostEnv& env, Handshake* out) {
    std::string line;
    switch (ReadLine(in, kMaxHandshakeLineBytes, &line)) {
        case LineResult::Ok: break;
        case LineResult::TooLong: return "line_too_long";
        case LineResult::Eof:
        case LineResult::ReadError: return "no_line";
    }
    return ParseHandshake(line, env, out);
}

namespace {

// Length of the longest prefix of `s` (at most `limit` bytes) that ends on a UTF-8
// character boundary.
size_t Utf8PrefixLen(const std::string& s, size_t limit) {
    if (limit >= s.size()) return s.size();
    size_t n = limit;
    while (n > 0 && (static_cast<unsigned char>(s[n]) & 0xC0) == 0x80) --n;
    return n;
}

}  // namespace

std::string FormatReceiptOk(const std::string& uiUrl) {
    ordered_json j = ordered_json::object();
    j["v"] = 1;
    j["ok"] = true;
    if (!uiUrl.empty()) j["uiUrl"] = uiUrl;
    std::string line = DumpSafe(j) + "\n";
    if (line.size() > kMaxReceiptLineBytes) {
        // A uiUrl this long would be dropped by the host; answer without one rather than
        // break the line limit.
        line = "{\"v\":1,\"ok\":true}\n";
    }
    return line;
}

std::string FormatReceiptError(const std::string& error) {
    std::string text = error;
    for (;;) {
        ordered_json j = ordered_json::object();
        j["v"] = 1;
        j["ok"] = false;
        j["error"] = text;
        std::string line = DumpSafe(j) + "\n";
        if (line.size() <= kMaxReceiptLineBytes || text.empty()) return line;
        // Escaping can make the line longer than the text; shrink by the overflow (at
        // least one byte) and try again.
        const size_t over = line.size() - kMaxReceiptLineBytes;
        const size_t keep = text.size() > over ? text.size() - over : 0;
        text.resize(Utf8PrefixLen(text, keep));
    }
}

bool WriteLine(HANDLE out, const std::string& line) {
    size_t done = 0;
    while (done < line.size()) {
        DWORD n = 0;
        const DWORD want = static_cast<DWORD>(std::min<size_t>(line.size() - done, 1u << 20));
        if (!WriteFile(out, line.data() + done, want, &n, nullptr) || n == 0) return false;
        done += n;
    }
    // No FlushFileBuffers: WriteFile has no user-mode buffer, so the bytes are already in
    // the pipe when it returns -- the "flush" the protocol asks for is about stdio-style
    // buffering (printf, Python's print). FlushFileBuffers on a pipe would instead block
    // until the host has *read* everything, one more way to hang for nothing.
    return true;
}

bool WriteReceipt(HANDLE out, bool ok, const std::string& uiUrlOrError) {
    return WriteLine(out, ok ? FormatReceiptOk(uiUrlOrError) : FormatReceiptError(uiUrlOrError));
}

StopEvent::~StopEvent() {
    if (handle_) CloseHandle(handle_);
}

bool StopEvent::Open(const std::string& name) {
    if (handle_) {
        CloseHandle(handle_);
        handle_ = nullptr;
    }
    if (name.empty()) return false;
    handle_ = OpenEventW(SYNCHRONIZE, FALSE, Utf8ToWide(name).c_str());
    return handle_ != nullptr;
}

bool StopEvent::WaitFor(DWORD ms) const {
    if (!handle_) return false;
    return WaitForSingleObject(handle_, ms) == WAIT_OBJECT_0;
}

void StopEvent::WaitForever() const {
    if (handle_) {
        while (WaitForSingleObject(handle_, INFINITE) != WAIT_OBJECT_0) {
            // WAIT_FAILED should not happen on a handle we hold; do not spin.
            Sleep(1000);
        }
        return;
    }
    for (;;) Sleep(INFINITE);
}

}  // namespace pf
