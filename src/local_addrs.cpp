#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include "local_addrs.h"

#include <algorithm>
#include <vector>

namespace pf {

std::vector<std::string> FilterLocalIPv4(const std::vector<AdapterIPv4>& entries) {
    std::vector<std::string> out;
    for (const AdapterIPv4& e : entries) {
        if (!e.adapterUp || !e.preferred) continue;
        if ((e.addrHostOrder >> 24) == 127 || e.addrHostOrder == 0) continue;
        const uint32_t a = e.addrHostOrder;
        const std::string s = std::to_string(a >> 24) + "." + std::to_string((a >> 16) & 0xFF) + "." +
                              std::to_string((a >> 8) & 0xFF) + "." + std::to_string(a & 0xFF);
        if (std::find(out.begin(), out.end(), s) == out.end()) out.push_back(s);
    }
    return out;
}

std::vector<std::string> EnumerateLocalIPv4(std::string* error) {
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
    if (rc == ERROR_NO_DATA) return {};  // no IPv4 adapter at all
    if (rc != NO_ERROR) {
        if (error) *error = "GetAdaptersAddresses failed: " + std::to_string(rc);
        return {};
    }
    std::vector<AdapterIPv4> entries;
    for (auto* a = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()); a; a = a->Next) {
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
            const auto* sin = reinterpret_cast<const sockaddr_in*>(u->Address.lpSockaddr);
            AdapterIPv4 e;
            e.adapterUp = a->OperStatus == IfOperStatusUp;
            e.preferred = u->DadState == IpDadStatePreferred;
            e.addrHostOrder = ntohl(sin->sin_addr.s_addr);
            entries.push_back(e);
        }
    }
    return FilterLocalIPv4(entries);
}

}  // namespace pf
