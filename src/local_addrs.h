// This machine's IPv4 addresses, for validating listen.addr. Kept apart from rules.h so
// that ValidateRule stays pure: it takes the list as a parameter.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pf {

// One unicast IPv4 address as GetAdaptersAddresses reports it, reduced to what the
// filter looks at.
struct AdapterIPv4 {
    bool adapterUp = false;      // IfOperStatusUp
    bool preferred = false;      // DadState == IpDadStatePreferred
    uint32_t addrHostOrder = 0;  // e.g. 0xC0A8010A for 192.168.1.10
};

// The pure half: keeps addresses of adapters that are up and that are preferred (not
// tentative, duplicate or deprecated -- binding those fails or is about to), drops
// 127.0.0.0/8 (the loopback address is always allowed by name) and 0.0.0.0, formats the
// rest as dotted IPv4 and removes duplicates, keeping the first occurrence's order.
std::vector<std::string> FilterLocalIPv4(const std::vector<AdapterIPv4>& entries);

// Unicast IPv4 addresses from GetAdaptersAddresses, through FilterLocalIPv4. On failure
// returns an empty list and, if `error` is given, a short reason.
std::vector<std::string> EnumerateLocalIPv4(std::string* error = nullptr);

}  // namespace pf
