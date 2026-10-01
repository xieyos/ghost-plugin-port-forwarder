// The management page's HTTP server: hand-written HTTP/1.1 on 127.0.0.1, one request per
// connection.
//
// Ghost shows the page in an iframe named ghost-plugin-<port> (spec-manifest.md section 5),
// a different origin from Ghost; standalone, the user's browser shows it. Either way any
// other local process can connect to the port, and any web page the user visits can make
// the browser send requests to it. What keeps them out:
//
//   * A random 128-bit path prefix (BCryptGenRandom -> 32 lower-case hex digits). Every
//     route is under /<prefix>/; anything else is 404. uiUrl = http://127.0.0.1:<p>/<prefix>/.
//   * Host must be exactly "127.0.0.1:<p>" (400 otherwise): a DNS-rebinding page reaches
//     the port under its own host name and is refused before anything is looked at.
//   * A POST must carry exactly one Origin, equal to "http://127.0.0.1:<p>", and
//     Content-Type application/json (403 otherwise). A cross-site form cannot send that
//     content type, and a cross-site fetch cannot fake the Origin. A GET that carries an
//     Origin must carry ours too.
//   * The page itself may be framed only by Ghost's page: Content-Security-Policy
//     frame-ancestors <apiBase origin> when hosted, 'none' standalone.
//
// Limits, so that no client can hold the server: request headers <= 16 KB (431), a body <=
// 64 KB (413, judged from Content-Length before a byte of the body is read; chunked bodies
// are refused with 411), at most 16 connections at once (the 17th is answered 503 and
// closed), and the whole request must arrive within 10 s (408) -- a slow client cannot pin
// a thread forever. Every response says Connection: close. Every read and write waits in
// slices of kUiPollSliceMs and looks at the stop flag after each.
//
// Responses always carry: Content-Security-Policy (UiCsp), X-Content-Type-Options: nosniff,
// Referrer-Policy: no-referrer, Cache-Control: no-store.
//
// Threads: one accept thread (joined by Stop) and one detached thread per connection.
// Stop() waits for the connection threads only until kUiStopWaitMs: a handler can be
// blocked in a call this server cannot reach (a node list request to Ghost). Such a thread
// keeps the server's shared state -- and the handler, with whatever it captured -- alive
// through a shared_ptr until it returns, so nothing is freed under it.
#pragma once

#include <winsock2.h>
#include <windows.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <thread>

namespace pf {

constexpr size_t kUiMaxHeaderBytes = 16 * 1024;  // request line + headers + the blank line
constexpr size_t kUiMaxBodyBytes = 64 * 1024;
constexpr int kUiMaxConnections = 16;
constexpr DWORD kUiRequestTimeoutMs = 10000;  // the whole request, headers and body
constexpr DWORD kUiSendTimeoutMs = 10000;     // the whole response
constexpr DWORD kUiStopWaitMs = 500;
constexpr DWORD kUiPollSliceMs = 100;
// spec-limits.md: uiUrl is at most 2048 bytes.
constexpr size_t kMaxUiUrlBytes = 2048;
// Ghost's own control interface; a uiUrl on it (or on 80, which a browser drops from the
// URL so that the iframe's port binding never matches) is refused (spec-manifest.md 5).
constexpr uint16_t kGhostControlPort = 23551;

// Transport-level codes, answered as {"error":"<code>"}. The page localizes them too
// (ui/app.js), though a well-behaved page never sees most of them.
namespace ui_err {
constexpr const char* kBadRequest = "bad_request";              // 400: malformed request line or headers
constexpr const char* kBadHost = "bad_host";                    // 400: Host is not exactly 127.0.0.1:<port>
constexpr const char* kForbiddenOrigin = "forbidden_origin";    // 403: POST without our Origin
constexpr const char* kBadContentType = "bad_content_type";     // 403: POST that is not application/json
constexpr const char* kNotFound = "not_found";                  // 404
constexpr const char* kMethodNotAllowed = "method_not_allowed"; // 405
constexpr const char* kRequestTimeout = "request_timeout";      // 408
constexpr const char* kLengthRequired = "length_required";      // 411: Transfer-Encoding
constexpr const char* kPayloadTooLarge = "payload_too_large";   // 413
constexpr const char* kHeadersTooLarge = "headers_too_large";   // 431
constexpr const char* kInternalError = "internal_error";        // 500: the handler threw
constexpr const char* kBusy = "busy";                           // 503: too many connections
}  // namespace ui_err

struct UiRequest {
    std::string method;  // "GET" or "POST"
    std::string path;    // after "/<prefix>/": "", "app.js", "api/state", ...
    std::string query;   // after '?', undecoded ("" when none)
    std::string body;
};

struct UiResponse {
    int status = 200;
    std::string contentType;  // "" = application/json; charset=utf-8
    std::string body;
};

// Answers every request that passed the server's checks. May throw (answered 500).
using UiHandler = std::function<UiResponse(const UiRequest&)>;

struct UiServerOptions {
    UiHandler handler;
    // The origin allowed to frame the page: Ghost's apiBase, "http://127.0.0.1:<port>".
    // "" (standalone), or anything else, means no one: frame-ancestors 'none'.
    std::string frameAncestor;
    int maxConnections = kUiMaxConnections;
    DWORD requestTimeoutMs = kUiRequestTimeoutMs;
    DWORD sendTimeoutMs = kUiSendTimeoutMs;
    DWORD stopWaitMs = kUiStopWaitMs;
};

// "default-src 'self'; img-src 'self' data:; frame-ancestors <ancestor or 'none'>".
std::string UiCsp(const std::string& frameAncestor);

// The receipt's rule for uiUrl (spec-host-protocol.md 3.2, spec-manifest.md 5, spec-limits.md):
// starts with "http://127.0.0.1:<1..5 digits>/", the port is 1..65535 and neither 80 nor
// 23551, at most 2048 bytes, no control character, space or quote.
bool IsUiUrlShaped(const std::string& url);

// "application/json", case-insensitively, optionally followed by ";" parameters.
bool IsJsonContentType(const std::string& value);

class UiServer {
public:
    explicit UiServer(UiServerOptions opts);
    ~UiServer();  // Stop()
    UiServer(const UiServer&) = delete;
    UiServer& operator=(const UiServer&) = delete;

    // Binds 127.0.0.1:0 (again if the system hands out 80 or 23551), draws the prefix and
    // starts the accept thread. False with a short reason in `error`.
    bool Start(std::string* error);
    // Stops accepting, tells every connection to end, waits at most stopWaitMs for them.
    void Stop();

    uint16_t port() const;
    const std::string& prefix() const;
    // http://127.0.0.1:<port>/<prefix>/  ("" before Start succeeded)
    std::string url() const;
    // Connection threads running now.
    int ActiveConnections() const;

    struct Shared;  // ui_server.cpp

private:
    std::shared_ptr<Shared> sh_;
    std::thread accept_;
    bool started_ = false;
};

}  // namespace pf
