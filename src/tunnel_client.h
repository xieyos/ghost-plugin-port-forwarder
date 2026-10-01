// upstream.connect from the plugin's side (spec-plugin-api.md section 10): list Ghost's
// upstream nodes, and have Ghost build a tunnel through one of them and hand us the
// connected socket.
//
// There is no proxy protocol in this plugin. Ghost connects to the node, speaks its
// protocol, duplicates the finished socket into this process with WSADuplicateSocketW and
// answers the raw WSAPROTOCOL_INFOW bytes; OpenTunnel adopts them with WSASocketW.
//
// The rules that keep a tunnel from leaking or doubling:
//   * One tunnel, one request. An answer that never arrived (transport failure, timeout)
//     is a failure and is never retried: Ghost may already have duplicated a socket into
//     this process, and a second request would open a second connection through the
//     user's proxy. The request waits at least kTunnelClientWaitMs (30 s) for the answer;
//     Ghost promises one within 10 s.
//   * The one retried code is plugin_not_running: the host's "running" report (with our
//     pid) travels asynchronously, triggered by the very receipt we just wrote, so the
//     first call after the handshake may overtake it. Every 200 ms, for at most 5 s.
//     A 429 is retried inside GhostApi (it is answered before any work).
//   * Fail closed: a failure here is a failure. Callers close the client connection and
//     record the code; they never fall back to a direct connection.
//   * At most 8 tunnel requests of this plugin in flight (Ghost's per-plugin limit is 8,
//     spec-limits.md 7.2). A caller that cannot get a slot within 15 s fails with
//     tunnel_limit, without a request.
//   * protocolInfo is decoded only if it is strict base64 whose length equals both
//     protocolInfoBytes and sizeof(WSAPROTOCOL_INFOW); otherwise WSASocketW is never called
//     (it would read past the bytes we have).
//   * The adopted socket is created with WSA_FLAG_NO_HANDLE_INHERIT and, because that flag
//     does not reach a handle that WSADuplicateSocketW created, its HANDLE_FLAG_INHERIT is
//     then cleared explicitly (no child process inherits a connection through the user's
//     proxy; failing to clear it fails the call). It must be of the requested type
//     (SOCK_STREAM for tcp, SOCK_DGRAM for udp), else it is closed and the call fails.
//     TCP sockets get TCP_NODELAY and keepalive (60 s idle, 10 s interval). The socket
//     stays in blocking mode with no timeouts, as Ghost hands it over.
#pragma once

#include "clock.h"
#include "ghost_api.h"
#include "rules.h"
#include "unique_socket.h"

#include <windows.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace pf {

// Client-side codes, alongside api_err and the server's spec-errors.md section 9 codes
// (which are passed through as they are).
namespace tunnel_err {
constexpr const char* kNeedsGhost = "needs_ghost";              // standalone: no Ghost API at all
constexpr const char* kPermissionMissing = "permission_missing"; // upstream.connect was not granted
constexpr const char* kTunnelLimit = "tunnel_limit";            // no local slot within the wait
constexpr const char* kAdoptFailed = "adopt_failed";            // WSASocketW failed or the socket type is wrong
constexpr const char* kBadEgress = "bad_egress";                // direct egress, or a malformed node id
}  // namespace tunnel_err

constexpr const char* kPermUpstreamConnect = "upstream.connect";

constexpr DWORD kTunnelClientWaitMs = 30000;  // spec-limits.md 7.2: wait at least 30 s
constexpr DWORD kListReceiveTimeoutMs = 5000;
constexpr uint32_t kNodeListCacheMs = 10000;
constexpr uint32_t kNotRunningRetryMs = 200;
constexpr uint32_t kNotRunningRetryForMs = 5000;
constexpr int kMaxTunnelsInFlight = 8;
constexpr DWORD kTunnelSlotWaitMs = 15000;
constexpr size_t kProtocolInfoBytes = sizeof(WSAPROTOCOL_INFOW);

struct NodeInfo {
    std::string id;
    std::string name;
    std::string type;  // "socks5" | "http"
    bool active = false;
    bool valid = false;
    bool udp = false;
};

struct NodeList {
    std::string code;  // "" on success
    bool hasActive = false;
    std::string active;  // the id via:"active" would use, when hasActive
    std::vector<NodeInfo> nodes;
    bool ok() const { return code.empty(); }
};

// Answer of upstream.list -> NodeList. Exposed for the tests. Entries that are not
// objects, or lack any of the six keys with the right type, or whose id is not a node id,
// are skipped (the list stays useful when one entry is odd); a body that is not an object
// with status "ok", a top-level "active" that is neither a string nor null, or "nodes"
// that is not an array is bad_response.
NodeList ParseNodeList(const json& body);

struct TunnelNode {
    std::string id;
    std::string name;
    std::string type;
};

struct TunnelResult {
    std::string code;  // "" on success
    UniqueSocket sock;
    TunnelNode node;
    uint32_t maxPayload = 0;      // udp only
    uint32_t idleTimeoutMs = 0;   // udp only
    int requests = 0;             // how many tunnel requests this call sent (0..)
    bool ok() const { return code.empty(); }
};

struct TunnelClientOptions {
    // Null in standalone mode: every call answers needs_ghost.
    GhostApi* api = nullptr;
    // Whether the handshake granted upstream.connect.
    bool permitted = false;
    Clock* clock = nullptr;  // null = api->clock() or DefaultClock()
    uint32_t listCacheMs = kNodeListCacheMs;
    uint32_t notRunningRetryMs = kNotRunningRetryMs;
    uint32_t notRunningRetryForMs = kNotRunningRetryForMs;
    int maxInFlight = kMaxTunnelsInFlight;
    DWORD slotWaitMs = kTunnelSlotWaitMs;  // real time
};

class TunnelClient {
public:
    explicit TunnelClient(TunnelClientOptions opts);
    ~TunnelClient();
    TunnelClient(const TunnelClient&) = delete;
    TunnelClient& operator=(const TunnelClient&) = delete;

    // GET /api/upstream/list, cached for listCacheMs (successful answers only).
    NodeList ListNodes(bool forceRefresh = false);

    // POST /api/upstream/tunnel. egress Active -> via "active"; Node -> via "node" with
    // nodeId; Direct -> bad_egress without a request. host/port are sent as given (Ghost
    // judges their syntax: bad_target).
    TunnelResult OpenTunnel(EgressKind egress, const std::string& nodeId, Proto proto, const std::string& host,
                            int port);

    // Ends this client's slot waits and retry waits with `cancelled`, now and from now on.
    // The GhostApi's own waits (token bucket, 429 backoff) end with GhostApi::Shutdown,
    // which the owner of the shared GhostApi calls.
    void Shutdown();

    // Tunnel requests in flight right now (holding a slot).
    int InFlight() const { return inFlight_.load(); }

private:
    TunnelResult OpenOnce(const json& request, Proto proto);

    GhostApi* api_;
    bool permitted_;
    Clock* clock_;
    uint32_t listCacheMs_;
    uint32_t notRunningRetryMs_;
    uint32_t notRunningRetryForMs_;
    DWORD slotWaitMs_;
    HANDLE slots_ = nullptr;
    HANDLE cancel_ = nullptr;
    std::atomic<int> inFlight_{0};
    bool wsaOk_ = false;

    std::mutex listMu_;
    bool haveList_ = false;
    uint64_t listAt_ = 0;
    NodeList list_;
};

// Adopts raw WSAPROTOCOL_INFOW bytes (exactly kProtocolInfoBytes of them, else nothing is
// called) and checks the socket type. Exposed for the tests. Returns "" or adopt_failed /
// bad_response.
std::string AdoptProtocolInfo(const std::string& infoBytes, Proto proto, UniqueSocket* out);

}  // namespace pf
