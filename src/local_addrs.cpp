#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "local_addrs.h"

#include <algorithm>
#include <vector>

namespace pf {

std::vector<std::string> EnumerateLocalIPv4(std::string* error) {
    std::vector<std::string> out;
    const ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER |
                        GAA_FLAG_SKIP_FRIENDLY_NAME;
    ULONG size = 16 * 1024;
    std::vector<unsigned char> buf;
    ULONG rc = ERROR_BUFFER_OVERFLOW;
    // The table can grow between the sizing call and the real one; retry a few times.
    for (int attempt = 0; attempt < 4 && rc == ERROR_BUFFER_OVERFLOW; ++attempt) {
        buf.assign(size, 0);
        rc = GetAdaptersAddresses(AF_INET, flags, nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()),
                                  &size);
    }
    if (rc == ERROR_NO_DATA) return out;  // no IPv4 adapter at all
    if (rc != NO_ERROR) {
        if (error) *error = "GetAdaptersAddresses failed: " + std::to_string(rc);
        return out;
    }
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        if (a->OperStatus != IfOperStatusUp) continue;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
            if (u->DadState != IpDadStatePreferred) continue;
            const auto* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            const unsigned long host = ntohl(sin->sin_addr.s_addr);
            if ((host >> 24) == 127) continue;
            char text[INET_ADDRSTRLEN] = {};
            if (!inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text))) continue;
            const std::string s(text);
            if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
        }
    }
    return out;
}

}  // namespace pf
