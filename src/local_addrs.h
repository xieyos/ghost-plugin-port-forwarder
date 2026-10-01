// This machine's IPv4 addresses, for validating listen.addr. Kept apart from rules.h so
// that ValidateRule stays pure: it takes the list as a parameter.
#pragma once

#include <string>
#include <vector>

namespace pf {

// Unicast IPv4 addresses of adapters that are up, in dotted form, without duplicates,
// excluding 127.0.0.0/8 (the loopback address is always allowed by name) and addresses
// still in duplicate-address detection or deprecated -- binding those fails or is about
// to. On failure returns an empty list and, if `error` is given, a short reason.
std::vector<std::string> EnumerateLocalIPv4(std::string* error = nullptr);

}  // namespace pf
