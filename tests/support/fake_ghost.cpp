#include "fake_ghost.h"

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstring>

using pf::json;

namespace pf_test {

namespace {

constexpr size_t kMaxHeaderBytes = 64 * 1024;
constexpr size_t kMaxBodyBytes = 1024 * 1024;

std::string Lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string Trim(const std::string& s) {
    size_t b = 0;
    size_t e = s.size();
    while (b < e && (s[b] == ' ' || s[b] == '\t')) ++b;
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t')) --e;
    return s.substr(b, e - b);
}

bool SendAll(SOCKET s, const std::string& data) {
    size_t off = 0;
    while (off < data.size()) {
        const int n = send(s, data.data() + off, static_cast<int>(data.size() - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

const char* Reason(int status) {
    switch (status) {
        case 200:
            return "OK";
        case 302:
            return "Found";
        case 401:
            return "Unauthorized";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 429:
            return "Too Many Requests";
        default:
            return "Error";
    }
}

std::string ErrorBody(const std::string& code) {
    return pf::DumpSafe(json{{"status", "error"}, {"error", code}});
}

bool IsIPv4Literal(const std::string& s) {
    in_addr a;
    return InetPtonA(AF_INET, s.c_str(), &a) == 1;
}

// The connection being served by this thread (set by Serve before Handle).
thread_local SOCKET t_client = INVALID_SOCKET;

// The client closed its end (EOF or reset) -- not merely sent more bytes.
bool ClientClosed(SOCKET c) {
    if (c == INVALID_SOCKET) return false;
    WSAPOLLFD p = {};
    p.fd = c;
    p.events = POLLRDNORM;
    if (WSAPoll(&p, 1, 0) <= 0) return false;
    char b;
    const int n = recv(c, &b, 1, MSG_PEEK);
    return n == 0 || (n < 0 && WSAGetLastError() != WSAEWOULDBLOCK);
}

}  // namespace

std::string FakeBase64Encode(const std::string& bytes) {
    static const char kAlpha[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 3 <= bytes.size()) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) |
                           (static_cast<unsigned char>(bytes[i + 1]) << 8) | static_cast<unsigned char>(bytes[i + 2]);
        out.push_back(kAlpha[(v >> 18) & 63]);
        out.push_back(kAlpha[(v >> 12) & 63]);
        out.push_back(kAlpha[(v >> 6) & 63]);
        out.push_back(kAlpha[v & 63]);
        i += 3;
    }
    const size_t rest = bytes.size() - i;
    if (rest == 1) {
        const unsigned v = static_cast<unsigned char>(bytes[i]) << 16;
        out.push_back(kAlpha[(v >> 18) & 63]);
        out.push_back(kAlpha[(v >> 12) & 63]);
        out += "==";
    } else if (rest == 2) {
        const unsigned v = (static_cast<unsigned char>(bytes[i]) << 16) | (static_cast<unsigned char>(bytes[i + 1]) << 8);
        out.push_back(kAlpha[(v >> 18) & 63]);
        out.push_back(kAlpha[(v >> 12) & 63]);
        out.push_back(kAlpha[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

std::string FakeRequest::Header(const std::string& name) const {
    const std::string n = Lower(name);
    for (const auto& kv : headers) {
        if (Lower(kv.first) == n) return kv.second;
    }
    return std::string();
}

int FakeRequest::HeaderCount(const std::string& name) const {
    const std::string n = Lower(name);
    int c = 0;
    for (const auto& kv : headers) {
        if (Lower(kv.first) == n) ++c;
    }
    return c;
}

FakeGhost::FakeGhost() : targetPid_(GetCurrentProcessId()) {
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    nodes_ = {FakeNode{"n1", "Node One", "socks5", true, true, true},
              FakeNode{"n2", "Office", "http", false, true, false}};
}

FakeGhost::~FakeGhost() {
    Stop();
    if (stopEvent_) CloseHandle(stopEvent_);
}

bool FakeGhost::Start() {
    LoopbackListener l;
    if (!ListenLoopback(&l)) return false;
    listener_ = l.sock;
    port_ = l.port;
    l.sock = INVALID_SOCKET;  // ownership moves to listener_
    accept_ = std::thread([this, s = listener_] {
        try {
            AcceptLoop(s);
        } catch (...) {
        }
    });
    return true;
}

void FakeGhost::Stop() {
    if (stopping_.exchange(true)) return;
    if (stopEvent_) SetEvent(stopEvent_);
    if (accept_.joinable()) accept_.join();
    if (listener_ != INVALID_SOCKET) closesocket(listener_);
    listener_ = INVALID_SOCKET;
    // Connection and relay threads see stopping_ within 50 ms and close their own sockets.
    std::vector<std::thread> threads;
    {
        std::lock_guard<std::mutex> lock(mu_);
        threads.swap(threads_);
    }
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
}

void FakeGhost::SetNodes(std::vector<FakeNode> nodes) {
    std::lock_guard<std::mutex> lock(mu_);
    nodes_ = std::move(nodes);
}
void FakeGhost::SetListBody(std::string body) {
    std::lock_guard<std::mutex> lock(mu_);
    listBody_ = std::move(body);
}
void FakeGhost::MapHost(const std::string& host, unsigned short port) {
    std::lock_guard<std::mutex> lock(mu_);
    hostMap_.emplace_back(host, port);
}
void FakeGhost::SetTargetPid(DWORD pid) {
    std::lock_guard<std::mutex> lock(mu_);
    targetPid_ = pid;
}
void FakeGhost::SetUnauthorized(bool on) {
    std::lock_guard<std::mutex> lock(mu_);
    unauthorized_ = on;
}
void FakeGhost::Set429Count(int n) {
    std::lock_guard<std::mutex> lock(mu_);
    remaining429_ = n;
}
void FakeGhost::Set429Always(bool on) {
    std::lock_guard<std::mutex> lock(mu_);
    always429_ = on;
}
void FakeGhost::SetTunnelError(std::string code) {
    std::lock_guard<std::mutex> lock(mu_);
    tunnelError_ = std::move(code);
}
void FakeGhost::QueueTunnelErrors(std::vector<std::string> codes) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& c : codes) tunnelErrorQueue_.push_back(std::move(c));
}
void FakeGhost::SetTunnelGate(HANDLE gate) {
    std::lock_guard<std::mutex> lock(mu_);
    tunnelGate_ = gate;
}

std::string FakeGhost::Describe() const {
    std::lock_guard<std::mutex> lock(mu_);
    int list = 0;
    int tunnel = 0;
    int other = 0;
    for (const auto& r : requests_) {
        if (r.path == "/api/upstream/list") {
            ++list;
        } else if (r.path == "/api/upstream/tunnel") {
            ++tunnel;
        } else {
            ++other;
        }
    }
    return "fake ghost: list=" + std::to_string(list) + " tunnel=" + std::to_string(tunnel) +
           " other=" + std::to_string(other) + " inProgress=" + std::to_string(tunnelsInProgress_.load()) +
           " closedDuringDelay=" + std::to_string(closedDuringDelay_.load()) +
           " udpEchoed=" + std::to_string(udpEchoed_.load());
}

void FakeGhost::SetTunnelDelayMs(DWORD ms) {
    std::lock_guard<std::mutex> lock(mu_);
    tunnelDelayMs_ = ms;
}
void FakeGhost::SetTunnelDrop(bool on) {
    std::lock_guard<std::mutex> lock(mu_);
    tunnelDrop_ = on;
}
void FakeGhost::SetTunnelFixedBody(std::string body) {
    std::lock_guard<std::mutex> lock(mu_);
    tunnelFixedBody_ = std::move(body);
}
void FakeGhost::SetTunnelMutator(std::function<void(json&)> fn) {
    std::lock_guard<std::mutex> lock(mu_);
    tunnelMutator_ = std::move(fn);
}
void FakeGhost::SetUdpMaxPayload(long long n) {
    std::lock_guard<std::mutex> lock(mu_);
    udpMaxPayload_ = n;
}
void FakeGhost::SetFixedAnswer(int status, std::vector<std::pair<std::string, std::string>> headers,
                               std::string body) {
    std::lock_guard<std::mutex> lock(mu_);
    fixedStatus_ = status;
    fixedHeaders_ = std::move(headers);
    fixedBody_ = std::move(body);
}
void FakeGhost::SetListDelayMs(DWORD ms) {
    std::lock_guard<std::mutex> lock(mu_);
    listDelayMs_ = ms;
}

std::vector<FakeRequest> FakeGhost::Requests() const {
    std::lock_guard<std::mutex> lock(mu_);
    return requests_;
}

int FakeGhost::CountPath(const std::string& path) const {
    std::lock_guard<std::mutex> lock(mu_);
    int n = 0;
    for (const auto& r : requests_) {
        if (r.path == path) ++n;
    }
    return n;
}

void FakeGhost::CloseUdpRelays() {
    // Each relay thread sees its flag within 50 ms and closes its own socket.
    std::vector<std::shared_ptr<std::atomic<bool>>> flags;
    {
        std::lock_guard<std::mutex> lock(mu_);
        flags.swap(udpCloseFlags_);
    }
    for (auto& f : flags) f->store(true);
    for (auto& f : flags) {
        WaitUntil([&] { return f.use_count() == 1; }, 2000);
    }
}

void FakeGhost::AcceptLoop(SOCKET listener) {
    for (;;) {
        if (!WaitReadable(listener, stopping_)) return;
        SOCKET c = accept(listener, nullptr, nullptr);
        if (c == INVALID_SOCKET) return;
        std::lock_guard<std::mutex> lock(mu_);
        if (stopping_) {
            closesocket(c);
            return;
        }
        threads_.emplace_back([this, c] { Serve(c); });  // Serve catches everything itself
    }
}

void FakeGhost::Serve(SOCKET c) {
    try {
        std::string buf;
        char chunk[8192];
        for (;;) {
            // Headers.
            size_t end = std::string::npos;
            while ((end = buf.find("\r\n\r\n")) == std::string::npos) {
                if (buf.size() > kMaxHeaderBytes) goto done;
                if (!WaitReadable(c, stopping_)) goto done;
                const int n = recv(c, chunk, sizeof(chunk), 0);
                if (n <= 0) goto done;
                buf.append(chunk, static_cast<size_t>(n));
            }
            FakeRequest req;
            {
                const std::string head = buf.substr(0, end);
                buf.erase(0, end + 4);
                size_t lineEnd = head.find("\r\n");
                const std::string requestLine = head.substr(0, lineEnd);
                const size_t sp1 = requestLine.find(' ');
                const size_t sp2 = requestLine.find(' ', sp1 == std::string::npos ? 0 : sp1 + 1);
                if (sp1 == std::string::npos || sp2 == std::string::npos) goto done;
                req.method = requestLine.substr(0, sp1);
                req.path = requestLine.substr(sp1 + 1, sp2 - sp1 - 1);
                size_t pos = (lineEnd == std::string::npos) ? head.size() : lineEnd + 2;
                while (pos < head.size()) {
                    size_t e = head.find("\r\n", pos);
                    if (e == std::string::npos) e = head.size();
                    const std::string line = head.substr(pos, e - pos);
                    const size_t colon = line.find(':');
                    if (colon != std::string::npos) {
                        req.headers.emplace_back(line.substr(0, colon), Trim(line.substr(colon + 1)));
                    }
                    pos = e + 2;
                }
            }
            // Body.
            size_t length = 0;
            const std::string cl = req.Header("Content-Length");
            if (!cl.empty()) {
                length = static_cast<size_t>(std::strtoull(cl.c_str(), nullptr, 10));
                if (length > kMaxBodyBytes) goto done;
            }
            while (buf.size() < length) {
                if (!WaitReadable(c, stopping_)) goto done;
                const int n = recv(c, chunk, sizeof(chunk), 0);
                if (n <= 0) goto done;
                buf.append(chunk, static_cast<size_t>(n));
            }
            req.body = buf.substr(0, length);
            buf.erase(0, length);
            req.atMs = GetTickCount64();
            {
                std::lock_guard<std::mutex> lock(mu_);
                requests_.push_back(req);
            }

            t_client = c;
            const Answer a = Handle(req);
            if (a.drop) goto done;
            const bool close = Lower(req.Header("Connection")) == "close";
            std::string extra;
            for (const auto& h : a.headers) extra += h.first + ": " + h.second + "\r\n";
            std::string resp = "HTTP/1.1 " + std::to_string(a.status) + " " + Reason(a.status) +
                               "\r\nContent-Type: application/json\r\nContent-Length: " +
                               std::to_string(a.body.size()) + "\r\n" + extra +
                               (close ? "Connection: close\r\n" : "Connection: keep-alive\r\n") + "\r\n" + a.body;
            if (!SendAll(c, resp) || close) goto done;
        }
    done:;
    } catch (...) {
    }
    closesocket(c);
}

FakeGhost::Answer FakeGhost::Handle(const FakeRequest& req) {
    Answer a;
    DWORD listDelay = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (fixedStatus_ != 0) {
            a.status = fixedStatus_;
            a.headers = fixedHeaders_;
            a.body = fixedBody_;
            return a;
        }
        listDelay = listDelayMs_;
        if (unauthorized_) {
            a.status = 401;
            a.body = ErrorBody("unauthorized");
            return a;
        }
        if (always429_ || remaining429_ > 0) {
            if (remaining429_ > 0) --remaining429_;
            a.status = 429;
            a.body = ErrorBody("rate_limited");
            return a;
        }
    }
    if (req.method == "GET" && req.path == "/api/upstream/list") {
        if (listDelay > 0 && WaitForSingleObject(stopEvent_, listDelay) != WAIT_TIMEOUT) {
            a.drop = true;
            return a;
        }
        std::lock_guard<std::mutex> lock(mu_);
        if (!listBody_.empty()) {
            a.body = listBody_;
            return a;
        }
        json nodes = json::array();
        json active = nullptr;
        for (const auto& n : nodes_) {
            nodes.push_back(json{{"id", n.id},
                                 {"name", n.name},
                                 {"type", n.type},
                                 {"active", n.active},
                                 {"valid", n.valid},
                                 {"udp", n.udp}});
            if (n.active && active.is_null()) active = n.id;
        }
        a.body = pf::DumpSafe(json{{"status", "ok"}, {"active", active}, {"nodes", nodes}});
        return a;
    }
    if (req.method == "POST" && req.path == "/api/upstream/tunnel") return HandleTunnel(req);
    if (req.method == "POST" && req.path == "/api/log-ingest") {
        const json j = pf::ParseJsonNoThrow(req.body);
        auto it = j.is_object() ? j.find("entries") : j.end();
        if (!j.is_object() || it == j.end() || !it->is_array()) {
            a.body = ErrorBody("invalid_json");
            return a;
        }
        a.body = pf::DumpSafe(json{{"status", "ok"}, {"accepted", it->size()}, {"truncated", false}});
        return a;
    }
    a.status = 404;
    a.body = ErrorBody("not_found");
    return a;
}

FakeGhost::Answer FakeGhost::HandleTunnel(const FakeRequest& req) {
    struct InProgress {
        std::atomic<int>& n;
        explicit InProgress(std::atomic<int>& c) : n(c) { ++n; }
        ~InProgress() { --n; }
    } progress(tunnelsInProgress_);

    Answer a;
    DWORD delay = 0;
    HANDLE gate = nullptr;
    bool drop = false;
    std::string fixedBody;
    std::string error;
    std::function<void(json&)> mutator;
    std::vector<FakeNode> nodes;
    std::vector<std::pair<std::string, unsigned short>> hostMap;
    long long maxPayload = 0;
    {
        std::lock_guard<std::mutex> lock(mu_);
        delay = tunnelDelayMs_;
        gate = tunnelGate_;
        drop = tunnelDrop_;
        fixedBody = tunnelFixedBody_;
        if (!tunnelErrorQueue_.empty()) {
            error = tunnelErrorQueue_.front();
            tunnelErrorQueue_.pop_front();
        } else {
            error = tunnelError_;
        }
        mutator = tunnelMutator_;
        nodes = nodes_;
        hostMap = hostMap_;
        maxPayload = udpMaxPayload_;
    }
    if (delay > 0 || gate) {
        // Wait out the delay and the gate in 50 ms steps, watching the client: a client that
        // closes meanwhile has given up on the answer (an aborted request).
        const ULONGLONG until = GetTickCount64() + delay;
        for (;;) {
            const bool delayDone = GetTickCount64() >= until;
            const bool gateOpen = !gate || WaitForSingleObject(gate, 0) == WAIT_OBJECT_0;
            if (delayDone && gateOpen) break;
            if (WaitForSingleObject(stopEvent_, 50) != WAIT_TIMEOUT) {
                a.drop = true;
                return a;
            }
            if (ClientClosed(t_client)) {
                ++closedDuringDelay_;
                a.drop = true;
                return a;
            }
        }
    }
    if (drop) {
        a.drop = true;
        return a;
    }
    if (!error.empty()) {
        a.body = ErrorBody(error);
        return a;
    }
    if (!fixedBody.empty()) {
        a.body = fixedBody;
        return a;
    }

    const json j = pf::ParseJsonNoThrow(req.body);
    std::string via;
    std::string nodeId;
    std::string proto;
    std::string host;
    long long port = 0;
    if (!pf::JsonGetString(j, "via", &via) || !pf::JsonGetString(j, "proto", &proto) ||
        !pf::JsonGetString(j, "host", &host) || !pf::JsonGetInt64(j, "port", &port)) {
        a.body = ErrorBody("invalid_json");
        return a;
    }
    const FakeNode* node = nullptr;
    if (via == "active") {
        for (const auto& n : nodes) {
            if (n.active) {
                node = &n;
                break;
            }
        }
    } else if (via == "node" && pf::JsonGetString(j, "nodeId", &nodeId)) {
        for (const auto& n : nodes) {
            if (n.id == nodeId) {
                node = &n;
                break;
            }
        }
    } else {
        a.body = ErrorBody("bad_target");
        return a;
    }
    if (!node) {
        a.body = ErrorBody("upstream_not_found");
        return a;
    }
    if (port < 1 || port > 65535 || (proto != "tcp" && proto != "udp")) {
        a.body = ErrorBody("bad_target");
        return a;
    }

    std::string info;
    std::string code;
    if (proto == "tcp") {
        std::string target = host;
        int targetPort = static_cast<int>(port);
        bool mapped = false;
        for (const auto& kv : hostMap) {
            if (kv.first == host) {
                target = "127.0.0.1";
                targetPort = kv.second;
                mapped = true;
                break;
            }
        }
        if (!mapped && !IsIPv4Literal(host)) {
            a.body = ErrorBody("upstream_refused");
            return a;
        }
        if (!OpenTcp(target, targetPort, &info, &code)) {
            a.body = ErrorBody(code);
            return a;
        }
    } else {
        if (!OpenUdp(&info, &code)) {
            a.body = ErrorBody(code);
            return a;
        }
    }

    json resp = json{{"status", "ok"},
                     {"proto", proto},
                     {"protocolInfo", info},
                     {"protocolInfoBytes", sizeof(WSAPROTOCOL_INFOW)},
                     {"node", json{{"id", node->id}, {"name", node->name}, {"type", node->type}}}};
    if (proto == "udp") {
        resp["maxPayload"] = maxPayload;
        resp["idleTimeoutMs"] = 120000;
    }
    if (mutator) mutator(resp);
    a.body = pf::DumpSafe(resp);
    return a;
}

bool FakeGhost::Duplicate(SOCKET s, std::string* infoB64) {
    DWORD pid;
    {
        std::lock_guard<std::mutex> lock(mu_);
        pid = targetPid_;
    }
    WSAPROTOCOL_INFOW info = {};
    if (WSADuplicateSocketW(s, pid, &info) != 0) return false;
    *infoB64 = FakeBase64Encode(std::string(reinterpret_cast<const char*>(&info), sizeof(info)));
    return true;
}

bool FakeGhost::OpenTcp(const std::string& host, int port, std::string* infoB64, std::string* code) {
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) {
        *code = "tunnel_failed";
        return false;
    }
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<u_short>(port));
    if (InetPtonA(AF_INET, host.c_str(), &a.sin_addr) != 1 ||
        connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        closesocket(s);
        *code = "upstream_unreachable";
        return false;
    }
    const bool ok = Duplicate(s, infoB64);
    // Ghost closes its own copy (never shutdown: that would end the connection for the
    // plugin's copy too).
    closesocket(s);
    if (!ok) *code = "tunnel_failed";
    return ok;
}

bool FakeGhost::OpenUdp(std::string* infoB64, std::string* code) {
    *code = "tunnel_failed";
    SOCKET plugin = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    SOCKET relay = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    auto fail = [&] {
        if (plugin != INVALID_SOCKET) closesocket(plugin);
        if (relay != INVALID_SOCKET) closesocket(relay);
        return false;
    };
    if (plugin == INVALID_SOCKET || relay == INVALID_SOCKET) return fail();
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sockaddr_in pa = a;
    sockaddr_in ra = a;
    int len = sizeof(pa);
    if (bind(plugin, reinterpret_cast<sockaddr*>(&pa), sizeof(pa)) != 0 ||
        getsockname(plugin, reinterpret_cast<sockaddr*>(&pa), &len) != 0)
        return fail();
    len = sizeof(ra);
    if (bind(relay, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)) != 0 ||
        getsockname(relay, reinterpret_cast<sockaddr*>(&ra), &len) != 0)
        return fail();
    if (connect(plugin, reinterpret_cast<sockaddr*>(&ra), sizeof(ra)) != 0 ||
        connect(relay, reinterpret_cast<sockaddr*>(&pa), sizeof(pa)) != 0)
        return fail();
    if (!Duplicate(plugin, infoB64)) return fail();
    closesocket(plugin);
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stopping_) {
            closesocket(relay);
            return false;
        }
        auto flag = std::make_shared<std::atomic<bool>>(false);
        udpCloseFlags_.push_back(flag);
        threads_.emplace_back([this, relay, flag] {
            try {
                UdpEcho(relay, flag);
            } catch (...) {
            }
        });
    }
    code->clear();
    return true;
}

void FakeGhost::UdpEcho(SOCKET s, std::shared_ptr<std::atomic<bool>> close) {
    std::vector<char> buf(65536);
    for (;;) {
        // Stops on Stop() or on CloseUdpRelays() for this relay -- both checked every 50 ms
        // while waiting (WaitReadable alone watches only stopping_, so a relay asked to
        // close stayed open until the next datagram arrived, and swallowed that datagram).
        if (close->load() || stopping_.load()) break;
        WSAPOLLFD p = {};
        p.fd = s;
        p.events = POLLRDNORM;
        const int ready = WSAPoll(&p, 1, 50);
        if (ready == 0) continue;
        if (ready < 0 || close->load()) break;
        const int n = recv(s, buf.data(), static_cast<int>(buf.size()), 0);
        if (n < 0) {
            const int e = WSAGetLastError();
            // A connected UDP socket reports an ICMP "port unreachable" from an earlier
            // send as WSAECONNRESET on the next receive; that is not the end of the relay.
            if (e == WSAECONNRESET) continue;
            break;
        }
        ++udpEchoed_;
        send(s, buf.data(), n, 0);
    }
    closesocket(s);
    close.reset();
}

}  // namespace pf_test
