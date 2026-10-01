// What the forwarders need from Ghost: "is a tunnel possible at all" and "open one".
//
// An interface rather than a TunnelClient& for one reason: lifetime. A connection thread
// can be inside OpenTunnel when the engine is told to stop. Shutdown() aborts that request,
// but the thread still has to return through the client, and a thread waiting out a 429
// backoff is not woken at all (see GhostApi::Abort); such a thread can outlive
// Engine::Stop. It holds a shared_ptr to its TunnelSource, and ClientTunnelSource holds
// shared_ptrs to the TunnelClient and to the GhostApi it points into -- so neither is
// destroyed under a thread still using it.
#pragma once

#include "ghost_api.h"
#include "rules.h"
#include "tunnel_client.h"

#include <memory>
#include <string>
#include <utility>

namespace pf {

class TunnelSource {
public:
    virtual ~TunnelSource() = default;

    // "" when tunnels can be requested; otherwise the rule status for a via-node rule:
    // permission_missing (upstream.connect not granted) or ghost_unavailable (Ghost has
    // answered 401; tokens never come back). Standalone mode has no TunnelSource at all,
    // which the forwarders report as needs_ghost.
    virtual std::string Availability() = 0;

    virtual TunnelResult Open(EgressKind egress, const std::string& nodeId, Proto proto, const std::string& host,
                              int port) = 0;

    // Ends every wait for a slot or a retry and aborts every tunnel request on the wire,
    // now and from now on (TunnelClient::Shutdown). Does NOT shut the GhostApi down: the
    // plugin's log shares it and still has a final batch to send. Its owner calls
    // GhostApi::Shutdown after that.
    virtual void Shutdown() = 0;
};

class ClientTunnelSource final : public TunnelSource {
public:
    ClientTunnelSource(std::shared_ptr<GhostApi> api, std::shared_ptr<TunnelClient> client, bool permitted)
        : api_(std::move(api)), client_(std::move(client)), permitted_(permitted) {}

    std::string Availability() override {
        if (!client_ || !api_) return tunnel_err::kNeedsGhost;
        if (!permitted_) return tunnel_err::kPermissionMissing;
        if (api_->Unavailable()) return api_err::kGhostUnavailable;
        return std::string();
    }

    TunnelResult Open(EgressKind egress, const std::string& nodeId, Proto proto, const std::string& host,
                      int port) override {
        if (!client_) {
            TunnelResult r;
            r.code = tunnel_err::kNeedsGhost;
            return r;
        }
        return client_->OpenTunnel(egress, nodeId, proto, host, port);
    }

    void Shutdown() override {
        if (client_) client_->Shutdown();
    }

private:
    std::shared_ptr<GhostApi> api_;
    std::shared_ptr<TunnelClient> client_;
    bool permitted_;
};

}  // namespace pf
