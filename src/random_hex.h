// Random lower-case hex from the system RNG (BCryptGenRandom). Rule ids, temporary file
// names and, later, the UI's path prefix all come from here.
#pragma once

#include <windows.h>
#include <bcrypt.h>

#include <string>
#include <vector>

namespace pf {

// 2 * nBytes hex digits, or "" if the RNG failed (callers treat "" as a failure; they
// never fall back to a predictable value).
inline std::string RandomHex(size_t nBytes) {
    if (nBytes == 0 || nBytes > 1024) return std::string();
    std::vector<unsigned char> buf(nBytes);
    if (!BCRYPT_SUCCESS(BCryptGenRandom(nullptr, buf.data(), static_cast<ULONG>(buf.size()),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return std::string();
    }
    static const char kHex[] = "0123456789abcdef";
    std::string s;
    s.reserve(nBytes * 2);
    for (unsigned char b : buf) {
        s.push_back(kHex[b >> 4]);
        s.push_back(kHex[b & 0x0f]);
    }
    return s;
}

}  // namespace pf
