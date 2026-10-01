// The client for Ghost's local control interface, as a plugin sees it
// (spec-plugin-api.md section 1).
//
// - Talks to exactly the handshake's apiBase ("http://127.0.0.1:<port>") over WinHTTP with
//   WINHTTP_ACCESS_TYPE_NO_PROXY: a system proxy must never see the token.
// - Every request carries `X-Ghost-Plugin-Token: <token>` and NO Origin header (a native
//   process has no page; any Origin other than apiBase itself is a 401).
// - Keep-alive, redirects, cookies and automatic authentication are switched off per
//   request. Keep-alive matters most: on a reused connection that the server closed, WinHTTP
//   may silently send the request a second time -- and a second upstream.tunnel request is
//   a second connection through the user's proxy (see tunnel_client.h). Loopback
//   connections are cheap; one connection per request costs nothing worth that risk.
// - Timeouts: resolve 1 s, connect 2 s, send 5 s, receive per call (default 30 s).
// - A local token bucket of 18/s, burst 90 keeps the plugin below Ghost's per-plugin budget
//   of 20/s, burst 100: callers WAIT for a token, they are never refused locally.
// - 429 (Ghost's budget is spent anyway): exponential backoff from 250 ms with jitter,
//   capped at 8 s, at most 5 retries. Safe for every route: a 429 is answered before any
//   work is done.
// - 401 (the token is no longer valid: the plugin was disabled, the host was lost): the
//   client becomes "unavailable" for good and every later call fails at once with
//   ghost_unavailable, without a request. Tokens never come back to life; a new token
//   means a new process.
// - A transport failure (no connection, no answer within the timeout, a cut connection) is
//   ghost_unreachable and is NEVER retried here: the request may have been carried out.
// - Answers are JSON objects. A 200 whose body is {"status":"error","error":"<code>"}
//   becomes that code. The body is judged by type before anything is taken from it.
#pragma once

#include "clock.h"
#include "json_util.h"
#include "token_bucket.h"

#include <windows.h>
#include <winhttp.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

namespace pf {

// Client-side reason codes (the server's own codes are passed through unchanged).
namespace api_err {
constexpr const char* kGhostUnavailable = "ghost_unavailable";  // a 401 was seen, or no valid apiBase/token
constexpr const char* kGhostUnreachable = "ghost_unreachable";  // transport failure; never retried
constexpr const char* kBadResponse = "bad_response";            // not a JSON object, an odd status, an odd code
constexpr const char* kRateLimited = "rate_limited";            // still 429 after the last retry
constexpr const char* kPermissionDenied = "permission_denied";  // 403
constexpr const char* kCancelled = "cancelled";                 // Shutdown() during a wait
}  // namespace api_err

// Our own bucket, a little below Ghost's 20/s burst 100 (spec-limits.md 7.1), so that
// timing jitter between the two clocks does not turn into 429s.
constexpr double kApiRatePerSec = 18.0;
constexpr double kApiBurst = 90.0;
constexpr int kMax429Retries = 5;

constexpr DWORD kResolveTimeoutMs = 1000;
constexpr DWORD kConnectTimeoutMs = 2000;
constexpr DWORD kSendTimeoutMs = 5000;
constexpr DWORD kDefaultReceiveTimeoutMs = 30000;
// The largest answer body read; anything longer is bad_response.
constexpr size_t kMaxResponseBytes = 1024 * 1024;

// ^[a-z][a-z0-9_]{0,63}$ -- the shape of every reason code Ghost sends. A server code of
// any other shape is reported as bad_response, so a code shown to the user or written to a
// log is always one of a known alphabet.
bool IsReasonCodeShaped(const std::string& s);

struct GhostApiOptions {
    std::string apiBase;  // "http://127.0.0.1:<port>", from the handshake
    std::string token;    // from the handshake
    Clock* clock = nullptr;  // null = DefaultClock()
    // Jitter source in [0, 1]; null = an internal random generator.
    std::function<double()> random01;
    double ratePerSec = kApiRatePerSec;
    double burst = kApiBurst;
    int max429Retries = kMax429Retries;
};

struct ApiResult {
    std::string code;  // "" on success
    int httpStatus = 0;  // 0 when no answer arrived
    json body;           // the parsed object on success (and on a 200 error answer)
    bool ok() const { return code.empty(); }
};

class GhostApi {
public:
    explicit GhostApi(GhostApiOptions opts);
    ~GhostApi();
    GhostApi(const GhostApi&) = delete;
    GhostApi& operator=(const GhostApi&) = delete;

    // `path` begins with '/'. `receiveTimeoutMs` 0 = kDefaultReceiveTimeoutMs.
    ApiResult Get(const std::string& path, DWORD receiveTimeoutMs = 0);
    ApiResult Post(const std::string& path, const json& body, DWORD receiveTimeoutMs = 0);

    // True after a 401 (or when constructed with an unusable apiBase/token).
    bool Unavailable() const { return unavailable_.load(); }

    // Wakes and fails every wait (token bucket, backoff) with `cancelled`, now and from
    // now on. A request already on the wire is NOT abandoned: its answer may carry a socket
    // that has been duplicated into this process, and only a received answer can be
    // adopted and closed.
    void Shutdown();
    // The event Shutdown() signals, for callers that want their own waits to end with it.
    HANDLE CancelEvent() const { return cancel_; }
    Clock* clock() const { return clock_; }

    // How many requests went on the wire (for logs and tests).
    uint64_t RequestsSent() const { return sent_.load(); }

private:
    ApiResult Call(const wchar_t* method, const std::string& path, const std::string* body, DWORD receiveTimeoutMs);
    bool WaitForBudget();
    double Random01();

    // One request on the wire. Returns false on a transport failure.
    bool SendOnce(const wchar_t* method, const std::string& path, const std::string* body, DWORD receiveTimeoutMs,
                  int* status, std::string* response, bool* tooLarge);

    Clock* clock_;
    std::function<double()> random01_;
    int max429Retries_;
    std::string token_;
    uint16_t port_ = 0;
    HINTERNET session_ = nullptr;
    HINTERNET connect_ = nullptr;
    HANDLE cancel_ = nullptr;
    std::atomic<bool> unavailable_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<uint64_t> sent_{0};

    std::mutex bucketMu_;
    TokenBucket bucket_;

    std::mutex rngMu_;
    uint64_t rngState_ = 0;
};

}  // namespace pf
