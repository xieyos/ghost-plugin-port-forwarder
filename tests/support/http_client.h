// A raw HTTP/1.1 client for the page server's tests: the request goes out byte for byte as
// the test wrote it (a wrong Host, no Origin, a lying Content-Length -- things a real HTTP
// library will not send), and the whole answer is read until the server closes.
#pragma once

#include "test_support.h"

#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace pf_test {

struct HttpReply {
    bool ok = false;  // a status line was read
    int status = 0;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::string raw;

    // The first header named `name` (case-insensitive), or "".
    std::string Header(const std::string& name) const {
        for (const auto& h : headers) {
            if (_stricmp(h.first.c_str(), name.c_str()) == 0) return h.second;
        }
        return std::string();
    }
};

inline HttpReply ParseReply(const std::string& raw) {
    HttpReply r;
    r.raw = raw;
    const size_t end = raw.find("\r\n\r\n");
    if (end == std::string::npos) return r;
    const std::string head = raw.substr(0, end);
    r.body = raw.substr(end + 4);
    size_t pos = 0;
    bool first = true;
    while (pos <= head.size()) {
        size_t eol = head.find("\r\n", pos);
        if (eol == std::string::npos) eol = head.size();
        const std::string line = head.substr(pos, eol - pos);
        pos = eol + 2;
        if (first) {
            first = false;
            if (line.compare(0, 9, "HTTP/1.1 ") != 0 || line.size() < 12) return r;
            r.status = std::atoi(line.substr(9, 3).c_str());
            r.ok = true;
        } else {
            const size_t colon = line.find(':');
            if (colon != std::string::npos) {
                size_t b = colon + 1;
                while (b < line.size() && line[b] == ' ') ++b;
                r.headers.emplace_back(line.substr(0, colon), line.substr(b));
            }
        }
        if (eol >= head.size()) break;
    }
    return r;
}

// Connects to 127.0.0.1:port, sends `request` as it is, reads until EOF or `timeoutMs`.
inline HttpReply RawHttp(unsigned short port, const std::string& request, DWORD timeoutMs = 10000) {
    HttpReply none;
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) return none;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(port);
    if (connect(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        closesocket(s);
        return none;
    }
    size_t off = 0;
    while (off < request.size()) {
        const int n = send(s, request.data() + off, static_cast<int>(request.size() - off), 0);
        if (n <= 0) break;  // the server may answer and stop reading early (413)
        off += static_cast<size_t>(n);
    }
    std::string raw;
    const ULONGLONG deadline = GetTickCount64() + timeoutMs;
    char buf[8192];
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) break;
        WSAPOLLFD p = {};
        p.fd = s;
        p.events = POLLRDNORM;
        const int r = WSAPoll(&p, 1, static_cast<INT>(deadline - now));
        if (r <= 0) break;
        const int n = recv(s, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, static_cast<size_t>(n));
    }
    closesocket(s);
    return ParseReply(raw);
}

// A well-formed request to the page server. `origin` and `contentType` are sent when not
// empty; extra header lines are appended as they are.
inline std::string BuildRequest(const std::string& method, const std::string& target, unsigned short port,
                                const std::string& body = std::string(), const std::string& origin = std::string(),
                                const std::string& contentType = std::string(),
                                const std::string& extraHeaders = std::string()) {
    std::string r = method + " " + target + " HTTP/1.1\r\nHost: 127.0.0.1:" + std::to_string(port) + "\r\n";
    if (!origin.empty()) r += "Origin: " + origin + "\r\n";
    if (!contentType.empty()) r += "Content-Type: " + contentType + "\r\n";
    if (method == "POST" || !body.empty()) r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += extraHeaders;
    r += "Connection: close\r\n\r\n";
    r += body;
    return r;
}

// Splits a uiUrl "http://127.0.0.1:<port>/<prefix>/" into its port and prefix.
inline bool SplitUiUrl(const std::string& url, unsigned short* port, std::string* prefix) {
    const std::string head = "http://127.0.0.1:";
    if (url.compare(0, head.size(), head) != 0) return false;
    const size_t slash = url.find('/', head.size());
    if (slash == std::string::npos || url.empty() || url.back() != '/') return false;
    *port = static_cast<unsigned short>(std::atoi(url.substr(head.size(), slash - head.size()).c_str()));
    *prefix = url.substr(slash + 1, url.size() - slash - 2);
    return *port != 0;
}

}  // namespace pf_test
