#include "ui_server.h"

#include "json_util.h"
#include "random_hex.h"

#include <ws2tcpip.h>

#include <chrono>
#include <condition_variable>
#include <exception>
#include <mutex>
#include <utility>
#include <vector>

namespace pf {

struct UiServer::Shared {
    UiServerOptions opts;
    std::string csp;
    uint16_t port = 0;
    std::string prefix;
    std::string host;    // "127.0.0.1:<port>"
    std::string origin;  // "http://127.0.0.1:<port>"
    SOCKET listener = INVALID_SOCKET;
    std::atomic<bool> stop{false};

    std::mutex mu;
    std::condition_variable cv;
    int active = 0;
};

namespace {

using Shared = UiServer::Shared;

bool IsTchar(unsigned char c) {
    if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) return true;
    switch (c) {
        case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+':
        case '-': case '.': case '^': case '_': case '`': case '|': case '~':
            return true;
        default:
            return false;
    }
}

std::string Lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

const char* Reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 411: return "Length Required";
        case 413: return "Payload Too Large";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 503: return "Service Unavailable";
        default: return "Status";
    }
}

std::string ErrorBody(const char* code) {
    json j = json::object();
    j["error"] = code;
    return DumpSafe(j);
}

std::string FormatResponse(const std::string& csp, const UiResponse& r) {
    std::string out = "HTTP/1.1 " + std::to_string(r.status) + " " + Reason(r.status) + "\r\n";
    out += "Content-Type: " + (r.contentType.empty() ? std::string("application/json; charset=utf-8") : r.contentType) +
           "\r\n";
    out += "Content-Length: " + std::to_string(r.body.size()) + "\r\n";
    out += "Connection: close\r\n";
    out += "Content-Security-Policy: " + csp + "\r\n";
    out += "X-Content-Type-Options: nosniff\r\n";
    out += "Referrer-Policy: no-referrer\r\n";
    out += "Cache-Control: no-store\r\n";
    out += "\r\n";
    out += r.body;
    return out;
}

UiResponse Error(int status, const char* code) {
    UiResponse r;
    r.status = status;
    r.body = ErrorBody(code);
    return r;
}

// Waits until `s` is ready for `events` or `deadline` (GetTickCount64) passes or the server
// stops. 1 ready, 0 timed out / stopping, -1 error.
int WaitFor(SOCKET s, short events, uint64_t deadline, const std::atomic<bool>& stop) {
    for (;;) {
        if (stop.load()) return 0;
        const uint64_t now = GetTickCount64();
        if (now >= deadline) return 0;
        uint64_t left = deadline - now;
        if (left > kUiPollSliceMs) left = kUiPollSliceMs;
        WSAPOLLFD p = {};
        p.fd = s;
        p.events = events;
        const int r = WSAPoll(&p, 1, static_cast<INT>(left));
        if (r < 0) return -1;
        if (r > 0) return 1;  // ready, or an error/hangup the next call reports itself
    }
}

bool SendAll(SOCKET s, const std::string& data, uint64_t deadline, const std::atomic<bool>& stop) {
    size_t off = 0;
    while (off < data.size()) {
        const int chunk = static_cast<int>(data.size() - off > 65536 ? 65536 : data.size() - off);
        const int n = send(s, data.data() + off, chunk, 0);
        if (n > 0) {
            off += static_cast<size_t>(n);
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            if (WaitFor(s, POLLWRNORM, deadline, stop) != 1) return false;
            continue;
        }
        return false;
    }
    return true;
}

// Ends the connection without discarding the response: our FIN first, then whatever the
// client still sends (an unread body: a 413, a 404 before the body) is read and dropped
// until its FIN, a bounded time and amount -- closing a socket with unread data resets the
// connection, and a reset can make the client lose the response it was about to read.
//
// The wait ends early once `stop` is set: the process is exiting, and a lost answer then
// costs nothing. `budgetMs` and the byte cap bound it otherwise.
void LingeringClose(SOCKET s, DWORD budgetMs, const std::atomic<bool>& stop) {
    shutdown(s, SD_SEND);
    const uint64_t deadline = GetTickCount64() + budgetMs;
    size_t drained = 0;
    char buf[4096];
    while (drained < 256 * 1024) {
        if (WaitFor(s, POLLRDNORM, deadline, stop) != 1) break;
        const int n = recv(s, buf, sizeof(buf), 0);
        if (n > 0) {
            drained += static_cast<size_t>(n);
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) continue;
        break;
    }
    closesocket(s);
}

bool IsDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
    }
    return true;
}

struct Header {
    std::string name;  // lower case
    std::string value;
};

// Parses the request line and the header lines (`head` ends before the blank line).
bool ParseHead(const std::string& head, std::string* method, std::string* target, std::vector<Header>* headers) {
    size_t pos = 0;
    bool first = true;
    while (pos <= head.size()) {
        size_t eol = head.find("\r\n", pos);
        if (eol == std::string::npos) eol = head.size();
        const std::string line = head.substr(pos, eol - pos);
        pos = eol + 2;
        // A lone CR or LF, or any other control character but tab, is not HTTP.
        for (unsigned char c : line) {
            if ((c < 0x20 && c != '\t') || c == 0x7f) return false;
        }
        if (first) {
            first = false;
            const size_t sp1 = line.find(' ');
            if (sp1 == std::string::npos || sp1 == 0) return false;
            const size_t sp2 = line.find(' ', sp1 + 1);
            if (sp2 == std::string::npos || sp2 == sp1 + 1) return false;
            if (line.find(' ', sp2 + 1) != std::string::npos) return false;
            *method = line.substr(0, sp1);
            *target = line.substr(sp1 + 1, sp2 - sp1 - 1);
            const std::string version = line.substr(sp2 + 1);
            if (version != "HTTP/1.1" && version != "HTTP/1.0") return false;
            for (unsigned char c : *method) {
                if (c < 'A' || c > 'Z') return false;
            }
            if (target->empty() || (*target)[0] != '/') return false;
            for (unsigned char c : *target) {
                if (c <= 0x20 || c >= 0x7f) return false;
            }
            if (eol >= head.size()) break;
            continue;
        }
        if (line.empty()) return false;  // cannot happen before the blank line
        if (line[0] == ' ' || line[0] == '\t') return false;  // obsolete line folding
        const size_t colon = line.find(':');
        if (colon == std::string::npos || colon == 0) return false;
        Header h;
        for (size_t i = 0; i < colon; ++i) {
            if (!IsTchar(static_cast<unsigned char>(line[i]))) return false;
        }
        h.name = Lower(line.substr(0, colon));
        size_t b = colon + 1, e = line.size();
        while (b < e && (line[b] == ' ' || line[b] == '\t')) ++b;
        while (e > b && (line[e - 1] == ' ' || line[e - 1] == '\t')) --e;
        h.value = line.substr(b, e - b);
        headers->push_back(std::move(h));
        if (eol >= head.size()) break;
    }
    return !first;
}

// Every header named `name`.
std::vector<std::string> Values(const std::vector<Header>& headers, const char* name) {
    std::vector<std::string> v;
    for (const Header& h : headers) {
        if (h.name == name) v.push_back(h.value);
    }
    return v;
}

struct ReadOutcome {
    bool respond = false;  // false: just close (the client went away, or the server stops)
    UiResponse response;
};

ReadOutcome Answer(UiResponse r) {
    ReadOutcome o;
    o.respond = true;
    o.response = std::move(r);
    return o;
}

ReadOutcome ServeOne(Shared& sh, SOCKET c) {
    const uint64_t deadline = GetTickCount64() + sh.opts.requestTimeoutMs;

    // ---- Headers --------------------------------------------------------------------
    std::string buf;
    size_t headEnd = std::string::npos;
    char chunk[4096];
    for (;;) {
        const size_t searchFrom = buf.size() >= 3 ? buf.size() - 3 : 0;
        // Never read more than the limit allows, plus the 4 bytes that would end it.
        const size_t room = kUiMaxHeaderBytes + 1 - buf.size();
        const int want = static_cast<int>(room < sizeof(chunk) ? room : sizeof(chunk));
        const int n = recv(c, chunk, want, 0);
        if (n > 0) {
            buf.append(chunk, static_cast<size_t>(n));
            headEnd = buf.find("\r\n\r\n", searchFrom);
            if (headEnd != std::string::npos) {
                if (headEnd + 4 > kUiMaxHeaderBytes) return Answer(Error(431, ui_err::kHeadersTooLarge));
                break;
            }
            if (buf.size() > kUiMaxHeaderBytes) return Answer(Error(431, ui_err::kHeadersTooLarge));
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            const int w = WaitFor(c, POLLRDNORM, deadline, sh.stop);
            if (w == 1) continue;
            if (w == 0 && !sh.stop.load() && !buf.empty()) return Answer(Error(408, ui_err::kRequestTimeout));
            return ReadOutcome();
        }
        return ReadOutcome();  // EOF or an error before a whole head arrived
    }

    std::string method, target;
    std::vector<Header> headers;
    if (!ParseHead(buf.substr(0, headEnd), &method, &target, &headers)) return Answer(Error(400, ui_err::kBadRequest));

    // ---- Host: exactly ours (DNS rebinding) ------------------------------------------------
    const std::vector<std::string> hosts = Values(headers, "host");
    if (hosts.size() != 1 || hosts[0] != sh.host) return Answer(Error(400, ui_err::kBadHost));

    // ---- Body size, from the headers alone ----------------------------------------------------
    if (!Values(headers, "transfer-encoding").empty()) return Answer(Error(411, ui_err::kLengthRequired));
    const std::vector<std::string> lengths = Values(headers, "content-length");
    if (lengths.size() > 1) return Answer(Error(400, ui_err::kBadRequest));
    size_t bodyLen = 0;
    if (lengths.size() == 1) {
        const std::string& v = lengths[0];
        if (!IsDigits(v)) return Answer(Error(400, ui_err::kBadRequest));
        if (v.size() > 9) return Answer(Error(413, ui_err::kPayloadTooLarge));
        for (char ch : v) bodyLen = bodyLen * 10 + static_cast<size_t>(ch - '0');
        if (bodyLen > kUiMaxBodyBytes) return Answer(Error(413, ui_err::kPayloadTooLarge));
    }

    // ---- The prefix --------------------------------------------------------------------------
    std::string path = target, query;
    const size_t q = path.find('?');
    if (q != std::string::npos) {
        query = path.substr(q + 1);
        path.resize(q);
    }
    const std::string base = "/" + sh.prefix + "/";
    if (path.compare(0, base.size(), base) != 0) return Answer(Error(404, ui_err::kNotFound));

    // ---- Method, Origin, Content-Type ------------------------------------------------------------
    if (method != "GET" && method != "POST") return Answer(Error(405, ui_err::kMethodNotAllowed));
    const std::vector<std::string> origins = Values(headers, "origin");
    if (method == "POST") {
        if (origins.size() != 1 || origins[0] != sh.origin) return Answer(Error(403, ui_err::kForbiddenOrigin));
        const std::vector<std::string> types = Values(headers, "content-type");
        if (types.size() != 1 || !IsJsonContentType(types[0])) return Answer(Error(403, ui_err::kBadContentType));
    } else if (!origins.empty() && (origins.size() != 1 || origins[0] != sh.origin)) {
        return Answer(Error(403, ui_err::kForbiddenOrigin));
    }

    // ---- Body -------------------------------------------------------------------------------------
    std::string body = buf.substr(headEnd + 4);
    if (body.size() > bodyLen) return Answer(Error(400, ui_err::kBadRequest));  // pipelining is not supported
    while (body.size() < bodyLen) {
        const size_t want = bodyLen - body.size();
        const int n = recv(c, chunk, static_cast<int>(want < sizeof(chunk) ? want : sizeof(chunk)), 0);
        if (n > 0) {
            body.append(chunk, static_cast<size_t>(n));
            continue;
        }
        if (n == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK) {
            const int w = WaitFor(c, POLLRDNORM, deadline, sh.stop);
            if (w == 1) continue;
            if (w == 0 && !sh.stop.load()) return Answer(Error(408, ui_err::kRequestTimeout));
            return ReadOutcome();
        }
        return ReadOutcome();
    }

    UiRequest req;
    req.method = method;
    req.path = path.substr(base.size());
    req.query = query;
    req.body = std::move(body);
    try {
        return Answer(sh.opts.handler ? sh.opts.handler(req) : Error(404, ui_err::kNotFound));
    } catch (...) {
        return Answer(Error(500, ui_err::kInternalError));
    }
}

void ServeConnection(std::shared_ptr<Shared> sh, SOCKET c) {
    bool answered = false;
    try {
        const ReadOutcome o = ServeOne(*sh, c);
        if (o.respond) {
            answered =
                SendAll(c, FormatResponse(sh->csp, o.response), GetTickCount64() + sh->opts.sendTimeoutMs, sh->stop);
        }
    } catch (...) {
    }
    try {
        // Lingering only protects an answer that was sent; with none (the client went away,
        // the server is stopping) there is nothing to protect.
        if (answered && !sh->stop.load()) {
            LingeringClose(c, kUiLingerMs, sh->stop);
        } else {
            closesocket(c);
        }
    } catch (...) {
        closesocket(c);
    }
    {
        std::lock_guard<std::mutex> lock(sh->mu);
        --sh->active;
    }
    sh->cv.notify_all();
}

void AcceptLoop(std::shared_ptr<Shared> sh) {
    try {
        while (!sh->stop.load()) {
            WSAPOLLFD p = {};
            p.fd = sh->listener;
            p.events = POLLRDNORM;
            const int r = WSAPoll(&p, 1, static_cast<INT>(kUiPollSliceMs));
            if (r <= 0) continue;
            SOCKET c = accept(sh->listener, nullptr, nullptr);
            if (c == INVALID_SOCKET) {
                const int e = WSAGetLastError();
                if (e != WSAEWOULDBLOCK && e != WSAECONNRESET) Sleep(kUiPollSliceMs);  // out of resources: no spin
                continue;
            }
            SetHandleInformation(reinterpret_cast<HANDLE>(c), HANDLE_FLAG_INHERIT, 0);
            u_long nb = 1;
            ioctlsocket(c, FIONBIO, &nb);
            bool admit = false;
            {
                std::lock_guard<std::mutex> lock(sh->mu);
                if (sh->active < sh->opts.maxConnections) {
                    ++sh->active;
                    admit = true;
                }
            }
            if (!admit) {
                // One non-blocking send of a short answer; a client that does not read it
                // loses it, which is all a 17th connection is owed.
                const std::string busy = FormatResponse(sh->csp, Error(503, ui_err::kBusy));
                send(c, busy.data(), static_cast<int>(busy.size()), 0);
                // A short linger (kUiBusyLingerMs, on this thread: this is the overload path,
                // and accepting more slowly is what it should do): the request that is still
                // arriving is read and dropped, so that closing does not reset the connection
                // and lose the 503.
                LingeringClose(c, kUiBusyLingerMs, sh->stop);
                continue;
            }
            try {
                std::thread(ServeConnection, sh, c).detach();
            } catch (...) {
                closesocket(c);
                {
                    std::lock_guard<std::mutex> lock(sh->mu);
                    --sh->active;
                }
                sh->cv.notify_all();
            }
        }
    } catch (...) {
    }
}

// "http://127.0.0.1:<port>" with a port 1..65535 and no leading zero.
bool IsLoopbackOrigin(const std::string& s) {
    const std::string head = "http://127.0.0.1:";
    if (s.compare(0, head.size(), head) != 0) return false;
    const std::string port = s.substr(head.size());
    if (!IsDigits(port) || port.size() > 5 || port[0] == '0') return false;
    return std::stoul(port) <= 65535;
}

}  // namespace

std::string UiCsp(const std::string& frameAncestor) {
    const std::string ancestor = IsLoopbackOrigin(frameAncestor) ? frameAncestor : std::string("'none'");
    return "default-src 'self'; img-src 'self' data:; form-action 'none'; base-uri 'none'; frame-ancestors " +
           ancestor;
}

bool IsJsonContentType(const std::string& value) {
    const std::string v = Lower(value);
    const std::string mt = "application/json";
    if (v.compare(0, mt.size(), mt) != 0) return false;
    if (v.size() == mt.size()) return true;
    size_t i = mt.size();
    while (i < v.size() && (v[i] == ' ' || v[i] == '\t')) ++i;
    return i < v.size() && v[i] == ';';
}

bool IsUiUrlShaped(const std::string& url) {
    if (url.size() > kMaxUiUrlBytes) return false;
    for (unsigned char c : url) {
        if (c <= 0x20 || c >= 0x7f || c == '"' || c == '\'' || c == '<' || c == '>' || c == '`' || c == '\\')
            return false;
    }
    const std::string head = "http://127.0.0.1:";
    if (url.compare(0, head.size(), head) != 0) return false;
    size_t i = head.size(), digits = 0;
    while (i < url.size() && url[i] >= '0' && url[i] <= '9') {
        ++i;
        ++digits;
    }
    if (digits < 1 || digits > 5 || i >= url.size() || url[i] != '/') return false;
    const unsigned long port = std::stoul(url.substr(head.size(), digits));
    return port >= 1 && port <= 65535 && port != 80 && port != kGhostControlPort;
}

UiServer::UiServer(UiServerOptions opts) : sh_(std::make_shared<Shared>()) {
    sh_->opts = std::move(opts);
    if (sh_->opts.maxConnections < 1) sh_->opts.maxConnections = 1;
    sh_->csp = UiCsp(sh_->opts.frameAncestor);
}

UiServer::~UiServer() { Stop(); }

bool UiServer::Start(std::string* error) {
    auto fail = [&](const std::string& why) {
        if (error) *error = why;
        return false;
    };
    if (started_) return fail("already started");
    sh_->prefix = RandomHex(16);
    if (sh_->prefix.size() != 32) return fail("rng_failed");

    SOCKET s = INVALID_SOCKET;
    uint16_t port = 0;
    for (int attempt = 0; attempt < 8; ++attempt) {
        s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        if (s == INVALID_SOCKET) return fail("socket: WSA error " + std::to_string(WSAGetLastError()));
        BOOL excl = TRUE;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&excl), sizeof(excl));
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int len = sizeof(a);
        if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
            getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            const int e = WSAGetLastError();
            closesocket(s);
            return fail("bind: WSA error " + std::to_string(e));
        }
        port = ntohs(a.sin_port);
        if (port != 80 && port != kGhostControlPort) break;
        closesocket(s);  // keep it out of the way of a later bind, then draw again
        s = INVALID_SOCKET;
    }
    if (s == INVALID_SOCKET) return fail("bind: no usable port");
    u_long nb = 1;
    if (listen(s, SOMAXCONN) != 0 || ioctlsocket(s, FIONBIO, &nb) != 0) {
        const int e = WSAGetLastError();
        closesocket(s);
        return fail("listen: WSA error " + std::to_string(e));
    }
    sh_->listener = s;
    sh_->port = port;
    sh_->host = "127.0.0.1:" + std::to_string(port);
    sh_->origin = "http://" + sh_->host;
    try {
        accept_ = std::thread(AcceptLoop, sh_);
    } catch (...) {
        closesocket(s);
        sh_->listener = INVALID_SOCKET;
        return fail("thread");
    }
    started_ = true;
    return true;
}

void UiServer::Stop() {
    // Idempotent: the destructor calls Stop() again, and a second wait would come after the
    // owner's exit deadline was planned around the first.
    if (stopCalled_) return;
    stopCalled_ = true;
    sh_->stop.store(true);
    if (accept_.joinable()) accept_.join();
    if (sh_->listener != INVALID_SOCKET) {
        closesocket(sh_->listener);
        sh_->listener = INVALID_SOCKET;
    }
    std::unique_lock<std::mutex> lock(sh_->mu);
    sh_->cv.wait_for(lock, std::chrono::milliseconds(sh_->opts.stopWaitMs), [this] { return sh_->active == 0; });
}

uint16_t UiServer::port() const { return sh_->port; }
const std::string& UiServer::prefix() const { return sh_->prefix; }

std::string UiServer::url() const {
    if (!started_) return std::string();
    return "http://127.0.0.1:" + std::to_string(sh_->port) + "/" + sh_->prefix + "/";
}

int UiServer::ActiveConnections() const {
    std::lock_guard<std::mutex> lock(sh_->mu);
    return sh_->active;
}

}  // namespace pf
