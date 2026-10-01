#include "tunnel_client.h"

#include "base64.h"

#include <winsock2.h>
#include <mstcpip.h>
#include <ws2tcpip.h>

#include <cstring>
#include <utility>

namespace pf {

namespace {

constexpr const char* kPluginNotRunning = "plugin_not_running";

// Owns one count of the in-flight semaphore.
class SlotGuard {
public:
    SlotGuard(HANDLE sem, std::atomic<int>* counter) : sem_(sem), counter_(counter) { ++*counter_; }
    ~SlotGuard() {
        --*counter_;
        ReleaseSemaphore(sem_, 1, nullptr);
    }
    SlotGuard(const SlotGuard&) = delete;
    SlotGuard& operator=(const SlotGuard&) = delete;

private:
    HANDLE sem_;
    std::atomic<int>* counter_;
};

bool ParseNode(const json& j, NodeInfo* out) {
    NodeInfo n;
    if (!JsonGetString(j, "id", &n.id) || !IsNodeIdShaped(n.id)) return false;
    if (!JsonGetString(j, "name", &n.name)) return false;
    if (!JsonGetString(j, "type", &n.type)) return false;
    if (!JsonGetBool(j, "active", &n.active)) return false;
    if (!JsonGetBool(j, "valid", &n.valid)) return false;
    if (!JsonGetBool(j, "udp", &n.udp)) return false;
    *out = std::move(n);
    return true;
}

bool ReadUint32(const json& j, const char* key, uint32_t* out) {
    long long v = 0;
    if (!JsonGetInt64(j, key, &v) || v < 0 || v > 0xffffffffll) return false;
    *out = static_cast<uint32_t>(v);
    return true;
}

}  // namespace

NodeList ParseNodeList(const json& body) {
    NodeList r;
    std::string st;
    if (!JsonGetString(body, "status", &st) || st != "ok") {
        r.code = api_err::kBadResponse;
        return r;
    }
    auto act = body.find("active");
    if (act == body.end() || !(act->is_null() || act->is_string())) {
        r.code = api_err::kBadResponse;
        return r;
    }
    if (act->is_string()) {
        r.active = act->get<std::string>();
        r.hasActive = IsNodeIdShaped(r.active);
        if (!r.hasActive) r.active.clear();
    }
    auto nodes = body.find("nodes");
    if (nodes == body.end() || !nodes->is_array()) {
        r.code = api_err::kBadResponse;
        return r;
    }
    for (const auto& e : *nodes) {
        NodeInfo n;
        if (ParseNode(e, &n)) r.nodes.push_back(std::move(n));
    }
    return r;
}

std::string AdoptProtocolInfo(const std::string& infoBytes, Proto proto, UniqueSocket* out) {
    out->Reset();
    // The size is checked before anything reads the bytes as a structure.
    if (infoBytes.size() != kProtocolInfoBytes) return api_err::kBadResponse;
    WSAPROTOCOL_INFOW info;
    std::memcpy(&info, infoBytes.data(), sizeof(info));
    UniqueSocket s(WSASocketW(FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, FROM_PROTOCOL_INFO, &info, 0,
                              WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT));
    if (!s) return tunnel_err::kAdoptFailed;
    // WSA_FLAG_NO_HANDLE_INHERIT is not enough here. Adopting FROM_PROTOCOL_INFO attaches
    // the handle WSADuplicateSocketW already created in this process, and that handle
    // arrives inheritable (observed: HANDLE_FLAG_INHERIT set right after WSASocketW, with
    // the flag passed). Cleared explicitly; if it cannot be cleared the socket is not used
    // -- every child process started later would hold a connection through the user's
    // proxy.
    if (!SetHandleInformation(reinterpret_cast<HANDLE>(s.get()), HANDLE_FLAG_INHERIT, 0)) {
        return tunnel_err::kAdoptFailed;
    }

    int type = 0;
    int len = sizeof(type);
    if (getsockopt(s.get(), SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&type), &len) != 0) {
        return tunnel_err::kAdoptFailed;
    }
    const int want = (proto == Proto::Tcp) ? SOCK_STREAM : SOCK_DGRAM;
    if (type != want) return tunnel_err::kAdoptFailed;

    if (proto == Proto::Tcp) {
        // Best effort: a forwarder works without them, only worse.
        BOOL one = TRUE;
        setsockopt(s.get(), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof(one));
        tcp_keepalive ka = {};
        ka.onoff = 1;
        ka.keepalivetime = 60000;
        ka.keepaliveinterval = 10000;
        DWORD returned = 0;
        WSAIoctl(s.get(), SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &returned, nullptr, nullptr);
    }
    *out = std::move(s);
    return std::string();
}

TunnelClient::TunnelClient(TunnelClientOptions opts)
    : api_(opts.api),
      permitted_(opts.permitted),
      clock_(opts.clock ? opts.clock : (opts.api ? opts.api->clock() : DefaultClock())),
      listCacheMs_(opts.listCacheMs),
      notRunningRetryMs_(opts.notRunningRetryMs),
      notRunningRetryForMs_(opts.notRunningRetryForMs),
      slotWaitMs_(opts.slotWaitMs) {
    const LONG n = opts.maxInFlight >= 1 ? opts.maxInFlight : 1;
    slots_ = CreateSemaphoreW(nullptr, n, n, nullptr);
    cancel_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    WSADATA d;
    wsaOk_ = WSAStartup(MAKEWORD(2, 2), &d) == 0;
}

TunnelClient::~TunnelClient() {
    if (slots_) CloseHandle(slots_);
    if (cancel_) CloseHandle(cancel_);
    if (wsaOk_) WSACleanup();
}

void TunnelClient::Shutdown() {
    if (cancel_) SetEvent(cancel_);
}

NodeList TunnelClient::ListNodes(bool forceRefresh) {
    NodeList r;
    if (!api_) {
        r.code = tunnel_err::kNeedsGhost;
        return r;
    }
    if (!permitted_) {
        r.code = tunnel_err::kPermissionMissing;
        return r;
    }
    std::lock_guard<std::mutex> lock(listMu_);
    const uint64_t now = clock_->NowMs();
    if (!forceRefresh && haveList_ && now - listAt_ < listCacheMs_) return list_;
    ApiResult a = api_->Get("/api/upstream/list", kListReceiveTimeoutMs);
    if (!a.ok()) {
        r.code = a.code;
        return r;
    }
    r = ParseNodeList(a.body);
    if (r.ok()) {
        list_ = r;
        haveList_ = true;
        listAt_ = clock_->NowMs();
    }
    return r;
}

TunnelResult TunnelClient::OpenTunnel(EgressKind egress, const std::string& nodeId, Proto proto,
                                      const std::string& host, int port) {
    TunnelResult r;
    if (!api_) {
        r.code = tunnel_err::kNeedsGhost;
        return r;
    }
    if (!permitted_) {
        r.code = tunnel_err::kPermissionMissing;
        return r;
    }
    if (egress == EgressKind::Direct || (egress == EgressKind::Node && !IsNodeIdShaped(nodeId))) {
        r.code = tunnel_err::kBadEgress;
        return r;
    }
    if (api_->Unavailable()) {
        r.code = api_err::kGhostUnavailable;
        return r;
    }
    if (!wsaOk_ || !slots_ || !cancel_) {
        r.code = tunnel_err::kAdoptFailed;
        return r;
    }

    json request = json::object();
    request["via"] = (egress == EgressKind::Active) ? "active" : "node";
    if (egress == EgressKind::Node) request["nodeId"] = nodeId;
    request["proto"] = ProtoName(proto);
    request["host"] = host;
    request["port"] = port;

    HANDLE waits[2] = {cancel_, slots_};
    const DWORD w = WaitForMultipleObjects(2, waits, FALSE, slotWaitMs_);
    if (w == WAIT_OBJECT_0) {
        r.code = api_err::kCancelled;
        return r;
    }
    if (w != WAIT_OBJECT_0 + 1) {
        r.code = tunnel_err::kTunnelLimit;
        return r;
    }
    SlotGuard slot(slots_, &inFlight_);

    const uint64_t start = clock_->NowMs();
    int requests = 0;
    for (;;) {
        TunnelResult one = OpenOnce(request, proto);
        ++requests;
        // The only retry: Ghost has not heard from the host that we run yet. Any other
        // code -- above all a lost answer -- ends the call.
        if (one.code == kPluginNotRunning && clock_->NowMs() - start < notRunningRetryForMs_) {
            if (!clock_->Wait(notRunningRetryMs_, cancel_)) {
                r.code = api_err::kCancelled;
                r.requests = requests;
                return r;
            }
            continue;
        }
        one.requests = requests;
        return one;
    }
}

TunnelResult TunnelClient::OpenOnce(const json& request, Proto proto) {
    TunnelResult r;
    // A request is put on the wire at most once here; GhostApi retries only 429s, which
    // are answered before Ghost does anything.
    ApiResult a = api_->Post("/api/upstream/tunnel", request, kTunnelClientWaitMs);
    if (!a.ok()) {
        r.code = a.code;
        return r;
    }
    std::string st;
    std::string b64;
    long long declared = -1;
    if (!JsonGetString(a.body, "status", &st) || st != "ok" || !JsonGetString(a.body, "protocolInfo", &b64) ||
        !JsonGetInt64(a.body, "protocolInfoBytes", &declared)) {
        r.code = api_err::kBadResponse;
        return r;
    }
    std::string bytes;
    if (!DecodeBase64Strict(b64, &bytes) || declared < 0 || static_cast<unsigned long long>(declared) != bytes.size() ||
        bytes.size() != kProtocolInfoBytes) {
        // Never adopted: the bytes are not one WSAPROTOCOL_INFOW. If Ghost did duplicate a
        // handle into us it stays unreachable until the process exits -- reading a
        // structure out of bytes of the wrong size would be worse.
        r.code = api_err::kBadResponse;
        return r;
    }
    // Adopted before the remaining fields are judged, so that an answer that is odd in
    // some other way still has its socket closed instead of leaked.
    r.code = AdoptProtocolInfo(bytes, proto, &r.sock);
    if (!r.ok()) return r;

    std::string gotProto;
    const json* node = nullptr;
    auto it = a.body.find("node");
    if (it != a.body.end() && it->is_object()) node = &*it;
    if (!JsonGetString(a.body, "proto", &gotProto) || gotProto != ProtoName(proto) || !node ||
        !JsonGetString(*node, "id", &r.node.id) || !JsonGetString(*node, "name", &r.node.name) ||
        !JsonGetString(*node, "type", &r.node.type)) {
        r.sock.Reset();
        r.code = api_err::kBadResponse;
        return r;
    }
    if (proto == Proto::Udp &&
        (!ReadUint32(a.body, "maxPayload", &r.maxPayload) || !ReadUint32(a.body, "idleTimeoutMs", &r.idleTimeoutMs))) {
        r.sock.Reset();
        r.code = api_err::kBadResponse;
        return r;
    }
    return r;
}

}  // namespace pf
