#include "ghost_api.h"

#include "host_handshake.h"
#include "random_hex.h"
#include "util_str.h"

#include <cstdlib>
#include <utility>
#include <vector>

namespace pf {

namespace {

constexpr const wchar_t* kTokenHeader = L"X-Ghost-Plugin-Token: ";

uint64_t SeedFromRng() {
    const std::string hex = RandomHex(8);
    if (hex.size() != 16) return 0x9e3779b97f4a7c15ull ^ GetTickCount64();
    return std::strtoull(hex.c_str(), nullptr, 16) | 1ull;
}

}  // namespace

bool IsReasonCodeShaped(const std::string& s) {
    if (s.empty() || s.size() > 64) return false;
    if (s[0] < 'a' || s[0] > 'z') return false;
    for (char c : s) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) return false;
    }
    return true;
}

GhostApi::GhostApi(GhostApiOptions opts)
    : clock_(opts.clock ? opts.clock : DefaultClock()),
      random01_(std::move(opts.random01)),
      max429Retries_(opts.max429Retries < 0 ? 0 : opts.max429Retries),
      token_(std::move(opts.token)),
      bucket_(opts.ratePerSec > 0 ? opts.ratePerSec : kApiRatePerSec, opts.burst >= 1 ? opts.burst : 1.0) {
    cancel_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    rngState_ = SeedFromRng();
    // A base or a token that does not have the handshake's shape never reaches the wire:
    // the token goes into a header verbatim, so its shape is what keeps CR/LF out.
    if (!ParseApiBase(opts.apiBase, &port_) || !IsTokenShaped(token_) || !cancel_) {
        unavailable_ = true;
        return;
    }
    session_ = WinHttpOpen(L"ghost-plugin-port-forwarder", WINHTTP_ACCESS_TYPE_NO_PROXY, WINHTTP_NO_PROXY_NAME,
                           WINHTTP_NO_PROXY_BYPASS, 0);
    if (session_) connect_ = WinHttpConnect(session_, L"127.0.0.1", port_, 0);
    if (!session_ || !connect_) unavailable_ = true;
}

GhostApi::~GhostApi() {
    if (connect_) WinHttpCloseHandle(connect_);
    if (session_) WinHttpCloseHandle(session_);
    if (cancel_) CloseHandle(cancel_);
}

void GhostApi::Shutdown() {
    std::vector<HINTERNET> doomed;
    {
        std::lock_guard<std::mutex> lock(liveMu_);
        shutdown_ = true;
        closed_ = true;  // from now on Register refuses, so nothing slips in after the sweep
        for (const auto& e : live_) doomed.push_back(e.first);
        live_.clear();
    }
    if (cancel_) SetEvent(cancel_);
    // Closed outside the lock: the owner thread is inside a WinHTTP call on the handle, and
    // closing it is what makes that call return.
    for (HINTERNET h : doomed) WinHttpCloseHandle(h);
}

void GhostApi::Abort(uintptr_t tag) {
    if (tag == 0) return;
    std::vector<HINTERNET> doomed;
    {
        std::lock_guard<std::mutex> lock(liveMu_);
        abortedTags_.push_back(tag);
        for (auto it = live_.begin(); it != live_.end();) {
            if (it->second == tag) {
                doomed.push_back(it->first);
                it = live_.erase(it);
            } else {
                ++it;
            }
        }
    }
    for (HINTERNET h : doomed) WinHttpCloseHandle(h);
}

bool GhostApi::Refused(uintptr_t tag) {
    std::lock_guard<std::mutex> lock(liveMu_);
    if (closed_) return true;
    if (tag == 0) return false;
    for (uintptr_t t : abortedTags_) {
        if (t == tag) return true;
    }
    return false;
}

bool GhostApi::Register(HINTERNET req, uintptr_t tag) {
    std::lock_guard<std::mutex> lock(liveMu_);
    if (closed_) return false;
    for (uintptr_t t : abortedTags_) {
        if (tag != 0 && t == tag) return false;
    }
    live_.emplace_back(req, tag);
    return true;
}

bool GhostApi::Owned(HINTERNET req) {
    std::lock_guard<std::mutex> lock(liveMu_);
    for (const auto& e : live_) {
        if (e.first == req) return true;
    }
    return false;
}

bool GhostApi::Release(HINTERNET req) {
    std::lock_guard<std::mutex> lock(liveMu_);
    for (auto it = live_.begin(); it != live_.end(); ++it) {
        if (it->first == req) {
            live_.erase(it);
            return true;
        }
    }
    return false;  // Shutdown()/Abort() took it and closes it
}

double GhostApi::Random01() {
    if (random01_) return random01_();
    std::lock_guard<std::mutex> lock(rngMu_);
    // xorshift64*: jitter only needs to differ between threads, not to be secret.
    rngState_ ^= rngState_ >> 12;
    rngState_ ^= rngState_ << 25;
    rngState_ ^= rngState_ >> 27;
    const uint64_t x = rngState_ * 0x2545F4914F6CDD1Dull;
    return static_cast<double>(x >> 11) / static_cast<double>(1ull << 53);
}

bool GhostApi::WaitForBudget() {
    uint64_t waitMs = 0;
    {
        std::lock_guard<std::mutex> lock(bucketMu_);
        waitMs = bucket_.Reserve(clock_->NowMs());
    }
    if (waitMs == 0) return !shutdown_.load();
    // A reservation is never handed back: a cancelled waiter's token simply stays spent,
    // which errs on the side of fewer requests.
    while (waitMs > 0) {
        const uint32_t slice = waitMs > 0x7fffffffull ? 0x7fffffffu : static_cast<uint32_t>(waitMs);
        if (!clock_->Wait(slice, cancel_)) return false;
        waitMs -= slice;
    }
    return !shutdown_.load();
}

ApiResult GhostApi::Get(const std::string& path, DWORD receiveTimeoutMs, uintptr_t tag) {
    return Call(L"GET", path, nullptr, receiveTimeoutMs, tag);
}

ApiResult GhostApi::Post(const std::string& path, const json& body, DWORD receiveTimeoutMs, uintptr_t tag) {
    const std::string text = DumpSafe(body);
    return Call(L"POST", path, &text, receiveTimeoutMs, tag);
}

ApiResult GhostApi::Call(const wchar_t* method, const std::string& path, const std::string* body,
                         DWORD receiveTimeoutMs, uintptr_t tag) {
    ApiResult r;
    if (receiveTimeoutMs == 0) receiveTimeoutMs = kDefaultReceiveTimeoutMs;
    if (path.empty() || path[0] != '/' || HasControlChar(path)) {
        r.code = api_err::kBadResponse;
        return r;
    }
    for (int attempt = 0;; ++attempt) {
        if (unavailable_.load()) {
            r.code = api_err::kGhostUnavailable;
            return r;
        }
        if (!WaitForBudget() || Refused(tag)) {
            r.code = api_err::kCancelled;
            return r;
        }
        // Checked again: another thread may have seen a 401 while we waited.
        if (unavailable_.load()) {
            r.code = api_err::kGhostUnavailable;
            return r;
        }
        int status = 0;
        std::string text;
        bool tooLarge = false;
        bool aborted = false;
        if (!SendOnce(method, path, body, receiveTimeoutMs, tag, &status, &text, &tooLarge, &aborted)) {
            r.code = aborted ? api_err::kCancelled : api_err::kGhostUnreachable;
            r.httpStatus = status;
            return r;
        }
        r.httpStatus = status;
        if (status == 401) {
            unavailable_ = true;
            r.code = api_err::kGhostUnavailable;
            return r;
        }
        if (status == 429) {
            if (attempt >= max429Retries_) {
                r.code = api_err::kRateLimited;
                return r;
            }
            if (!clock_->Wait(BackoffMs(attempt, Random01()), cancel_)) {
                r.code = api_err::kCancelled;
                return r;
            }
            continue;
        }
        if (status == 403) {
            r.code = api_err::kPermissionDenied;
            return r;
        }
        if (status != 200 || tooLarge) {
            r.code = api_err::kBadResponse;
            return r;
        }
        json j = ParseJsonNoThrow(text);
        if (!j.is_object()) {
            r.code = api_err::kBadResponse;
            return r;
        }
        std::string st;
        if (!JsonGetString(j, "status", &st)) {
            r.code = api_err::kBadResponse;
            return r;
        }
        if (st == "error") {
            std::string code;
            r.code = (JsonGetString(j, "error", &code) && IsReasonCodeShaped(code)) ? code : api_err::kBadResponse;
            r.body = std::move(j);
            return r;
        }
        r.body = std::move(j);
        return r;
    }
}

bool GhostApi::SendOnce(const wchar_t* method, const std::string& path, const std::string* body,
                        DWORD receiveTimeoutMs, uintptr_t tag, int* status, std::string* response, bool* tooLarge,
                        bool* aborted) {
    *status = 0;
    response->clear();
    *tooLarge = false;
    *aborted = false;
    if (!connect_) return false;

    const std::wstring wpath = Utf8ToWide(path);
    HINTERNET req = WinHttpOpenRequest(connect_, method, wpath.c_str(), nullptr, WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!req) return false;
    if (!Register(req, tag)) {
        WinHttpCloseHandle(req);
        *aborted = true;
        return false;
    }
    // Every exit goes through here: we close the handle only if nobody aborted it. A complete
    // answer read before an abort is still an answer -- it may carry a socket that only
    // adopting can close -- so `ok` is passed through.
    const auto finish = [&](bool ok) {
        if (Release(req)) {
            WinHttpCloseHandle(req);
        } else {
            *aborted = true;
        }
        return ok;
    };

    // Without our timeouts a lost answer would wait for WinHTTP's defaults; if they cannot
    // be set the request is not sent.
    if (!WinHttpSetTimeouts(req, static_cast<int>(kResolveTimeoutMs), static_cast<int>(kConnectTimeoutMs),
                            static_cast<int>(kSendTimeoutMs), static_cast<int>(receiveTimeoutMs))) {
        return finish(false);
    }
    DWORD rr = receiveTimeoutMs;
    if (!WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT, &rr, sizeof(rr))) return finish(false);
    // No keep-alive (see the top of ghost_api.h), no redirects, no cookies, no automatic
    // authentication. If this option cannot be set the request is not sent: without it a
    // dropped connection could be retried behind our back.
    DWORD features = WINHTTP_DISABLE_KEEP_ALIVE | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_COOKIES |
                     WINHTTP_DISABLE_AUTHENTICATION;
    if (!WinHttpSetOption(req, WINHTTP_OPTION_DISABLE_FEATURE, &features, sizeof(features))) return finish(false);

    std::wstring headers = kTokenHeader + Utf8ToWide(token_) + L"\r\n";
    if (body) headers += L"Content-Type: application/json\r\n";

    const DWORD bodyLen = body ? static_cast<DWORD>(body->size()) : 0;
    // From here on the handle may be aborted under us; each call is preceded by a check that
    // it is still ours (a call already blocked in WinHTTP is what the abort ends).
    if (!Owned(req)) return finish(false);
    ++sent_;
    if (!WinHttpSendRequest(req, headers.c_str(), static_cast<DWORD>(-1L),
                            body ? const_cast<char*>(body->data()) : WINHTTP_NO_REQUEST_DATA, bodyLen, bodyLen, 0)) {
        return finish(false);
    }
    if (!Owned(req) || !WinHttpReceiveResponse(req, nullptr)) return finish(false);

    DWORD code = 0;
    DWORD size = sizeof(code);
    if (!Owned(req) ||
        !WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX,
                             &code, &size, WINHTTP_NO_HEADER_INDEX)) {
        return finish(false);
    }
    *status = static_cast<int>(code);

    std::vector<char> buf(16 * 1024);
    for (;;) {
        DWORD got = 0;
        if (!Owned(req) || !WinHttpReadData(req, buf.data(), static_cast<DWORD>(buf.size()), &got)) {
            return finish(false);
        }
        if (got == 0) break;
        if (response->size() + got > kMaxResponseBytes) {
            *tooLarge = true;
            break;
        }
        response->append(buf.data(), got);
    }
    return finish(true);
}

}  // namespace pf
