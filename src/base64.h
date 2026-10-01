// Standard base64 (RFC 4648 section 4, with '=' padding), decoding only -- the one
// base64 the plugin reads is Ghost's protocolInfo.
#pragma once

#include <string>
#include <utility>

namespace pf {

// Strict: the length is a multiple of 4; only A-Z a-z 0-9 + / in the body; '=' only as
// the last one or two characters; no whitespace, no line breaks, no URL-safe alphabet.
// Unused bits in the last group are not required to be zero (they are ignored).
// Returns false and leaves `out` empty on anything else.
inline bool DecodeBase64Strict(const std::string& in, std::string* out) {
    out->clear();
    if (in.size() % 4 != 0) return false;
    auto val = [](unsigned char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };
    std::string r;
    r.reserve(in.size() / 4 * 3);
    for (size_t i = 0; i < in.size(); i += 4) {
        const bool last = (i + 4 == in.size());
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; ++k) {
            const unsigned char c = static_cast<unsigned char>(in[i + static_cast<size_t>(k)]);
            if (c == '=') {
                // Padding: only in the last group, only in positions 2 and 3, and once it
                // starts nothing but padding may follow.
                if (!last || k < 2) return false;
                v[k] = 0;
                ++pad;
                continue;
            }
            if (pad > 0) return false;
            v[k] = val(c);
            if (v[k] < 0) return false;
        }
        const unsigned triple = (static_cast<unsigned>(v[0]) << 18) | (static_cast<unsigned>(v[1]) << 12) |
                                (static_cast<unsigned>(v[2]) << 6) | static_cast<unsigned>(v[3]);
        r.push_back(static_cast<char>((triple >> 16) & 0xff));
        if (pad < 2) r.push_back(static_cast<char>((triple >> 8) & 0xff));
        if (pad < 1) r.push_back(static_cast<char>(triple & 0xff));
    }
    *out = std::move(r);
    return true;
}

}  // namespace pf
