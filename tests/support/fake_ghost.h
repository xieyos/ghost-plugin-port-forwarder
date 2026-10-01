// A stand-in for Ghost's local control interface, written from the public plugin API
// specification (spec-plugin-api.md sections 1, 5 and 10) for this plugin's tests.
//
// It contains no proxy protocol. Where Ghost would connect to an upstream node and
// handshake through it, this fake connects DIRECTLY to the destination the test named (a
// host name such as "echo.test" maps to a local port with MapHost; an IPv4 literal is
// used as it is) and hands that socket over the way Ghost does: WSADuplicateSocketW into
// the target process (this test process by default, or a launched exe), close its own
// copy, answer the WSAPROTOCOL_INFOW bytes in base64. For UDP it creates a pair of
// loopback UDP sockets connected to each other, hands one end over, and echoes every
// datagram that arrives on the other.
//
// A minimal HTTP/1.1 server on 127.0.0.1:0 with keep-alive (so a client that reuses
// connections is exercised as one would be against Ghost). Every request is recorded:
// method, path, headers, body. Faults can be injected: 401 for every request, a number of
// 429s, a fixed error code or a queue of codes for the tunnel route, a delay before the
// tunnel answer, closing the connection instead of answering, a fixed answer body, or a
// mutation of the real answer.
#pragma once

#include "test_support.h"

#include "json_util.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace pf_test {

struct FakeRequest {
    std::string method;
    std::string path;
    std::vector<std::pair<std::string, std::string>> headers;  // as received
    std::string body;
    uint64_t atMs = 0;  // GetTickCount64 when the request was complete

    // The value of the first header named `name` (case-insensitive), or "".
    std::string Header(const std::string& name) const;
    // How many headers are named `name` (case-insensitive).
    int HeaderCount(const std::string& name) const;
};

struct FakeNode {
    std::string id;
    std::string name;
    std::string type;  // "socks5" | "http"
    bool active = false;
    bool valid = true;
    bool udp = true;
};

class FakeGhost {
public:
    FakeGhost();
    ~FakeGhost();
    FakeGhost(const FakeGhost&) = delete;
    FakeGhost& operator=(const FakeGhost&) = delete;

    bool Start();
    void Stop();

    unsigned short port() const { return port_; }
    std::string apiBase() const { return "http://127.0.0.1:" + std::to_string(port_); }

    // ---- Configuration (any time, from any thread) ----
    void SetNodes(std::vector<FakeNode> nodes);
    // Replaces the generated upstream.list answer with this exact body.
    void SetListBody(std::string body);
    // Tunnel requests for host `host` (any port) connect to 127.0.0.1:<port>.
    void MapHost(const std::string& host, unsigned short port);
    // The process the socket is duplicated into (default: this process).
    void SetTargetPid(DWORD pid);
    void SetUnauthorized(bool on);         // every request answers 401
    void Set429Count(int n);               // the next n requests (any route) answer 429
    void Set429Always(bool on);            // every request answers 429
    void SetTunnelError(std::string code); // "" = succeed; else every tunnel answers this code
    void QueueTunnelErrors(std::vector<std::string> codes);  // answered first, one per request
    void SetTunnelDelayMs(DWORD ms);       // wait before answering a tunnel request
    void SetTunnelDrop(bool on);           // read the tunnel request, close without answering
    void SetTunnelFixedBody(std::string body);  // answer this, open nothing ("" = off)
    // Applied to the real success answer (after the socket was duplicated).
    void SetTunnelMutator(std::function<void(pf::json&)> fn);
    void SetUdpMaxPayload(long long n);

    // ---- Observation ----
    std::vector<FakeRequest> Requests() const;
    int CountPath(const std::string& path) const;
    // Tunnel requests currently being handled (between reading and answering).
    int TunnelsInProgress() const { return tunnelsInProgress_.load(); }
    // Datagrams echoed by the UDP relay ends.
    int UdpEchoed() const { return udpEchoed_.load(); }
    // Closes every UDP relay end this fake holds (the plugin's next recv then fails).
    void CloseUdpRelays();

private:
    struct Answer {
        int status = 200;
        std::string body;
        bool drop = false;  // close the connection instead
    };

    void AcceptLoop(SOCKET listener);
    void Serve(SOCKET c);
    Answer Handle(const FakeRequest& req);
    Answer HandleTunnel(const FakeRequest& req);
    bool OpenTcp(const std::string& host, int port, std::string* infoB64, std::string* code);
    bool OpenUdp(std::string* infoB64, std::string* code);
    bool Duplicate(SOCKET s, std::string* infoB64);
    void UdpEcho(SOCKET s, std::shared_ptr<std::atomic<bool>> close);

    unsigned short port_ = 0;
    SOCKET listener_ = INVALID_SOCKET;
    HANDLE stopEvent_ = nullptr;
    std::atomic<bool> stopping_{false};
    std::thread accept_;

    mutable std::mutex mu_;
    std::vector<std::thread> threads_;
    std::vector<std::shared_ptr<std::atomic<bool>>> udpCloseFlags_;
    std::vector<FakeRequest> requests_;

    std::vector<FakeNode> nodes_;
    std::string listBody_;
    std::vector<std::pair<std::string, unsigned short>> hostMap_;
    DWORD targetPid_;
    bool unauthorized_ = false;
    int remaining429_ = 0;
    bool always429_ = false;
    std::string tunnelError_;
    std::deque<std::string> tunnelErrorQueue_;
    DWORD tunnelDelayMs_ = 0;
    bool tunnelDrop_ = false;
    std::string tunnelFixedBody_;
    std::function<void(pf::json&)> tunnelMutator_;
    long long udpMaxPayload_ = 65497;

    std::atomic<int> tunnelsInProgress_{0};
    std::atomic<int> udpEchoed_{0};
};

// Standard base64 with padding (the fake's own encoder, independent of the plugin's
// decoder).
std::string FakeBase64Encode(const std::string& bytes);

}  // namespace pf_test
