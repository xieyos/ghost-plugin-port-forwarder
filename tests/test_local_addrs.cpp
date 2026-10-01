// Functional: this machine's IPv4 addresses (local_addrs.h). The list is whatever the
// machine has -- possibly empty on a CI runner -- so the checks are properties of every
// entry, and the strongest one is real: each listed address can be bound.

#include "local_addrs.h"
#include "rules.h"
#include "test_support.h"

#include <string>
#include <vector>

int main() {
    pf_test::WinsockScope ws;
    CHECK(ws.ok());

    std::string error;
    const std::vector<std::string> addrs = pf::EnumerateLocalIPv4(&error);
    std::printf("%zu local IPv4 address(es)%s%s\n", addrs.size(), error.empty() ? "" : ", error: ", error.c_str());
    CHECK_MSG(error.empty(), error.c_str());

    for (size_t i = 0; i < addrs.size(); ++i) {
        const std::string& a = addrs[i];
        const std::string label = "address " + a;
        CHECK_MSG(pf::IsStrictIPv4(a), (label + " is strict dotted IPv4").c_str());
        CHECK_MSG(a.compare(0, 4, "127.") != 0, (label + " is not loopback").c_str());
        CHECK_MSG(a != pf::kAnyAddr, (label + " is not 0.0.0.0").c_str());
        for (size_t k = 0; k < i; ++k) CHECK_MSG(addrs[k] != a, (label + " is listed once").c_str());

        SOCKET s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        CHECK(s != INVALID_SOCKET);
        sockaddr_in sa = {};
        sa.sin_family = AF_INET;
        CHECK(InetPtonA(AF_INET, a.c_str(), &sa.sin_addr) == 1);
        const bool bound = bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) == 0;
        CHECK_MSG(bound, (label + " can be bound").c_str());
        closesocket(s);

        // And ValidateRule accepts it as a listen address (with lanAck).
        pf::Rule r;
        r.id = "r_0123456789abcdef";
        r.name = "lan";
        r.listenAddr = a;
        r.listenPort = 8080;
        r.remoteHost = "example.com";
        r.remotePort = 80;
        r.lanAck = true;
        CHECK_MSG(pf::ValidateRule(r, addrs).empty(), (label + " is a valid listen address").c_str());
    }
    return pf_test::TestExitCode();
}
