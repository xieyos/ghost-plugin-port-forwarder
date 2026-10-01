#include "rules.h"

#include <array>
#include <climits>
#include <cstdint>

namespace pf {

namespace {

bool IsDigit(char c) { return c >= '0' && c <= '9'; }
bool IsAlpha(char c) { return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'); }
bool IsHexDigit(char c) { return IsDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

std::string AsciiLower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::vector<std::string> Split(const std::string& s, char sep) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (;;) {
        const size_t at = s.find(sep, start);
        if (at == std::string::npos) {
            parts.push_back(s.substr(start));
            return parts;
        }
        parts.push_back(s.substr(start, at - start));
        start = at + 1;
    }
}

int HexValue(char c) {
    if (IsDigit(c)) return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return c - 'A' + 10;
}

// Strict dotted IPv4 -> host-order value.
bool ParseStrictIPv4(const std::string& s, uint32_t* value) {
    if (s.empty() || s.size() > 15) return false;
    const std::vector<std::string> parts = Split(s, '.');
    if (parts.size() != 4) return false;
    uint32_t v = 0;
    for (const std::string& p : parts) {
        if (p.empty() || p.size() > 3) return false;
        if (p.size() > 1 && p[0] == '0') return false;
        uint32_t octet = 0;
        for (char c : p) {
            if (!IsDigit(c)) return false;
            octet = octet * 10 + static_cast<uint32_t>(c - '0');
        }
        if (octet > 255) return false;
        v = (v << 8) | octet;
    }
    if (value) *value = v;
    return true;
}

// One side of an IPv6 text around "::" (or the whole text without one), as 16-bit groups;
// a trailing dotted IPv4 becomes two groups and is allowed only when `mayEndInIPv4`.
bool ParseIPv6Side(const std::string& side, bool mayEndInIPv4, std::vector<uint16_t>* groups) {
    groups->clear();
    if (side.empty()) return true;
    const std::vector<std::string> pieces = Split(side, ':');
    for (size_t i = 0; i < pieces.size(); ++i) {
        const std::string& p = pieces[i];
        if (p.empty()) return false;
        const bool last = i + 1 == pieces.size();
        if (p.find('.') != std::string::npos) {
            uint32_t v4 = 0;
            if (!last || !mayEndInIPv4 || !ParseStrictIPv4(p, &v4)) return false;
            groups->push_back(static_cast<uint16_t>(v4 >> 16));
            groups->push_back(static_cast<uint16_t>(v4 & 0xFFFF));
            continue;
        }
        if (p.size() > 4) return false;
        unsigned g = 0;
        for (char c : p) {
            if (!IsHexDigit(c)) return false;
            g = (g << 4) | static_cast<unsigned>(HexValue(c));
        }
        groups->push_back(static_cast<uint16_t>(g));
    }
    return true;
}

// IPv6 text (no brackets, no zone) -> eight groups.
bool ParseIPv6(const std::string& s, std::array<uint16_t, 8>* out) {
    if (s.size() < 2 || s.size() > 45) return false;
    std::vector<uint16_t> left, right;
    const size_t dbl = s.find("::");
    if (dbl == std::string::npos) {
        if (!ParseIPv6Side(s, true, &left) || left.size() != 8) return false;
    } else {
        // A second "::" (":::" included) is ambiguous.
        if (s.find("::", dbl + 1) != std::string::npos) return false;
        if (!ParseIPv6Side(s.substr(0, dbl), false, &left)) return false;
        if (!ParseIPv6Side(s.substr(dbl + 2), true, &right)) return false;
        if (left.size() + right.size() > 7) return false;
    }
    if (out) {
        out->fill(0);
        for (size_t i = 0; i < left.size(); ++i) (*out)[i] = left[i];
        for (size_t i = 0; i < right.size(); ++i) (*out)[8 - right.size() + i] = right[i];
    }
    return true;
}

// ::ffff:0:0/96, in any spelling (::ffff:1.2.3.4, ::ffff:7f00:1, 0:0:0:0:0:ffff:...).
bool IsV4MappedIPv6(const std::string& s) {
    std::array<uint16_t, 8> g{};
    if (!ParseIPv6(s, &g)) return false;
    return g[0] == 0 && g[1] == 0 && g[2] == 0 && g[3] == 0 && g[4] == 0 && g[5] == 0xFFFF;
}

// Destinations no connection can be made to: the unspecified address, the limited
// broadcast and IPv4 multicast (224.0.0.0/4).
bool IsUnusableIPv4Destination(uint32_t v) {
    return v == 0 || v == 0xFFFFFFFFu || (v >> 28) == 0xE;
}

bool PortInRange(int p) { return p >= 1 && p <= 65535; }

// Reads an integer field into an int. False when absent, not an integer (floats and
// booleans included) or outside int -- a 2^40 port must not wrap into a valid one.
bool ReadIntField(const json& obj, const char* key, int* out) {
    long long v = 0;
    if (!JsonGetInt64(obj, key, &v)) return false;
    if (v < INT_MIN || v > INT_MAX) return false;
    *out = static_cast<int>(v);
    return true;
}

bool Contains(const std::vector<std::string>& v, const std::string& s) {
    for (const auto& e : v) {
        if (e == s) return true;
    }
    return false;
}

// A rule whose remote end is its own listener: every accepted connection would open
// another one to ourselves until the connection limit is hit. This holds for every egress
// kind: a Ghost node is often a local proxy client (e.g. Clash on 127.0.0.1), and the
// plugin cannot see node addresses, so "127.0.0.1" through a node may well come back
// here -- burning the tunnel budget on the way.
//
// v4-mapped IPv6 remotes never reach this point (bad_host), so the IPv4 text is the
// only spelling of an IPv4 destination to compare.
bool IsSelfLoop(const Rule& r, const std::vector<std::string>& localAddrs) {
    if (r.remotePort != r.listenPort) return false;
    const std::string host = AsciiLower(r.remoteHost);
    if (host == r.listenAddr) return true;
    uint32_t v4 = 0;
    const bool hostIsLoopback = host == "localhost" || (ParseStrictIPv4(host, &v4) && (v4 >> 24) == 127);
    if (r.listenAddr == kLoopbackAddr) return host == "localhost";
    if (r.listenAddr == kAnyAddr) {
        // 0.0.0.0 receives what is sent to any local address, loopback included.
        return hostIsLoopback || Contains(localAddrs, host);
    }
    return false;
}

// `localAddrs == nullptr`: the stored-rule variant (any strict IPv4 may be listened on).
std::string ValidateRuleImpl(const Rule& r, const std::vector<std::string>* localAddrs) {
    if (!IsRuleIdShaped(r.id)) return rule_err::kBadId;
    if (!IsValidRuleName(r.name)) return rule_err::kBadName;
    if (r.proto != Proto::Tcp && r.proto != Proto::Udp) return rule_err::kBadProto;

    if (!IsStrictIPv4(r.listenAddr)) return rule_err::kBadListenAddr;
    if (localAddrs && r.listenAddr != kLoopbackAddr && r.listenAddr != kAnyAddr &&
        !Contains(*localAddrs, r.listenAddr)) {
        return rule_err::kListenAddrNotLocal;
    }
    if (!PortInRange(r.listenPort)) return rule_err::kBadListenPort;
    // Anything but loopback is reachable from the network: every machine on the LAN can
    // use this port, and through a node, the user's upstream. The user says so explicitly.
    if (r.listenAddr != kLoopbackAddr && !r.lanAck) return rule_err::kLanAckRequired;

    if (!IsValidRemoteHost(r.remoteHost)) return rule_err::kBadHost;
    if (!PortInRange(r.remotePort)) return rule_err::kBadRemotePort;

    switch (r.egress) {
        case EgressKind::Direct:
        case EgressKind::Active:
            if (!r.nodeId.empty()) return rule_err::kBadNodeId;
            break;
        case EgressKind::Node:
            if (!IsNodeIdShaped(r.nodeId)) return rule_err::kBadNodeId;
            break;
        default:
            return rule_err::kBadEgress;
    }

    if (r.maxConnections < kMinMaxConnections || r.maxConnections > kMaxMaxConnections) return rule_err::kBadLimits;
    if (r.udpIdleSec < kMinUdpIdleSec || r.udpIdleSec > kMaxUdpIdleSec) return rule_err::kBadLimits;

    static const std::vector<std::string> kNone;
    if (IsSelfLoop(r, localAddrs ? *localAddrs : kNone)) return rule_err::kLoop;
    return std::string();
}

bool ListenOverlaps(const Rule& a, const Rule& b) {
    if (a.proto != b.proto || a.listenPort != b.listenPort) return false;
    if (a.listenAddr == b.listenAddr) return true;
    return a.listenAddr == kAnyAddr || b.listenAddr == kAnyAddr;
}

}  // namespace

const char* ProtoName(Proto p) { return p == Proto::Udp ? "udp" : "tcp"; }

const char* EgressKindName(EgressKind k) {
    switch (k) {
        case EgressKind::Active: return "active";
        case EgressKind::Node: return "node";
        default: return "direct";
    }
}

bool operator==(const Rule& a, const Rule& b) {
    return a.id == b.id && a.name == b.name && a.enabled == b.enabled && a.proto == b.proto &&
           a.listenAddr == b.listenAddr && a.listenPort == b.listenPort && a.remoteHost == b.remoteHost &&
           a.remotePort == b.remotePort && a.egress == b.egress && a.nodeId == b.nodeId &&
           a.maxConnections == b.maxConnections && a.udpIdleSec == b.udpIdleSec && a.lanAck == b.lanAck;
}

// ---- Grammar ------------------------------------------------------------------------------

bool IsStrictIPv4(const std::string& s) {
    return ParseStrictIPv4(s, nullptr);
}

bool IsIPv6Literal(const std::string& s) {
    return ParseIPv6(s, nullptr);
}

bool IsHostName(const std::string& s) {
    if (s.empty() || s.size() > kMaxHostBytes) return false;
    const std::vector<std::string> labels = Split(s, '.');
    for (const std::string& l : labels) {
        if (l.empty() || l.size() > 63) return false;
        if (l.front() == '-' || l.back() == '-') return false;
        for (char c : l) {
            if (!IsAlpha(c) && !IsDigit(c) && c != '-' && c != '_') return false;
        }
    }
    const std::string& last = labels.back();
    bool hasLetter = false;
    for (char c : last) {
        if (IsAlpha(c)) hasLetter = true;
    }
    if (!hasLetter) return false;
    if (last.size() >= 2 && last[0] == '0' && (last[1] == 'x' || last[1] == 'X')) return false;
    return true;
}

bool IsValidRemoteHost(const std::string& s) {
    uint32_t v4 = 0;
    if (ParseStrictIPv4(s, &v4)) return !IsUnusableIPv4Destination(v4);
    if (IsIPv6Literal(s)) return !IsV4MappedIPv6(s);
    return IsHostName(s);
}

bool IsNodeIdShaped(const std::string& s) {
    if (s.empty() || s.size() > kMaxNodeIdBytes) return false;
    for (char c : s) {
        if (!IsAlpha(c) && !IsDigit(c) && c != '_' && c != '.' && c != '-') return false;
    }
    return true;
}

bool IsRuleIdShaped(const std::string& s) {
    if (s.size() != 18 || s[0] != 'r' || s[1] != '_') return false;
    for (size_t i = 2; i < s.size(); ++i) {
        const char c = s[i];
        if (!IsDigit(c) && !(c >= 'a' && c <= 'f')) return false;
    }
    return true;
}

bool IsValidRuleName(const std::string& s) {
    size_t i = 0, codePoints = 0;
    const size_t n = s.size();
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        unsigned cp = 0;
        size_t need = 0;
        unsigned minCp = 0;
        if (c < 0x80) {
            cp = c;
        } else if ((c & 0xE0) == 0xC0) {
            cp = c & 0x1F, need = 1, minCp = 0x80;
        } else if ((c & 0xF0) == 0xE0) {
            cp = c & 0x0F, need = 2, minCp = 0x800;
        } else if ((c & 0xF8) == 0xF0) {
            cp = c & 0x07, need = 3, minCp = 0x10000;
        } else {
            return false;  // a continuation byte where a lead byte belongs, or 0xF8..0xFF
        }
        if (need > 0 && i + need >= n) return false;  // truncated sequence
        for (size_t k = 1; k <= need; ++k) {
            const unsigned char cc = static_cast<unsigned char>(s[i + k]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if (need > 0 && cp < minCp) return false;           // overlong
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;     // surrogate
        if (cp > 0x10FFFF) return false;
        if (cp < 0x20 || (cp >= 0x7F && cp <= 0x9F)) return false;  // C0, DEL, C1
        i += need + 1;
        if (++codePoints > kMaxNameCodePoints) return false;
    }
    return codePoints >= 1;
}

// ---- One rule ---------------------------------------------------------------------------

std::string ParseRule(const json& j, Rule* out) {
    if (!j.is_object()) return rule_err::kBadRule;
    Rule r;

    if (JsonHas(j, "id") && !JsonGetString(j, "id", &r.id)) return rule_err::kBadId;
    if (!JsonGetString(j, "name", &r.name)) return rule_err::kBadName;
    if (JsonHas(j, "enabled") && !JsonGetBool(j, "enabled", &r.enabled)) return rule_err::kBadEnabled;

    std::string proto;
    if (!JsonGetString(j, "proto", &proto)) return rule_err::kBadProto;
    if (proto == "tcp") {
        r.proto = Proto::Tcp;
    } else if (proto == "udp") {
        r.proto = Proto::Udp;
    } else {
        return rule_err::kBadProto;
    }

    const auto listen = j.find("listen");
    if (listen == j.end() || !listen->is_object()) return rule_err::kBadListenAddr;
    if (!JsonGetString(*listen, "addr", &r.listenAddr)) return rule_err::kBadListenAddr;
    if (!ReadIntField(*listen, "port", &r.listenPort)) return rule_err::kBadListenPort;

    const auto remote = j.find("remote");
    if (remote == j.end() || !remote->is_object()) return rule_err::kBadHost;
    if (!JsonGetString(*remote, "host", &r.remoteHost)) return rule_err::kBadHost;
    if (!ReadIntField(*remote, "port", &r.remotePort)) return rule_err::kBadRemotePort;

    const auto egress = j.find("egress");
    if (egress != j.end()) {
        if (!egress->is_object()) return rule_err::kBadEgress;
        std::string kind;
        if (!JsonGetString(*egress, "kind", &kind)) return rule_err::kBadEgress;
        if (kind == "direct") {
            r.egress = EgressKind::Direct;
        } else if (kind == "active") {
            r.egress = EgressKind::Active;
        } else if (kind == "node") {
            r.egress = EgressKind::Node;
        } else {
            return rule_err::kBadEgress;
        }
        std::string nodeId;
        if (JsonHas(*egress, "nodeId") && !JsonGetString(*egress, "nodeId", &nodeId)) return rule_err::kBadNodeId;
        if (r.egress == EgressKind::Node) {
            if (!JsonHas(*egress, "nodeId")) return rule_err::kBadNodeId;
            r.nodeId = nodeId;
        }
    }

    const auto limits = j.find("limits");
    if (limits != j.end()) {
        if (!limits->is_object()) return rule_err::kBadLimits;
        if (JsonHas(*limits, "maxConnections") && !ReadIntField(*limits, "maxConnections", &r.maxConnections)) {
            return rule_err::kBadLimits;
        }
        if (JsonHas(*limits, "udpIdleSec") && !ReadIntField(*limits, "udpIdleSec", &r.udpIdleSec)) {
            return rule_err::kBadLimits;
        }
    }

    if (JsonHas(j, "lanAck") && !JsonGetBool(j, "lanAck", &r.lanAck)) return rule_err::kBadLanAck;

    if (out) *out = std::move(r);
    return std::string();
}

json RuleToJson(const Rule& r) {
    json egress = json::object();
    egress["kind"] = EgressKindName(r.egress);
    if (r.egress == EgressKind::Node) egress["nodeId"] = r.nodeId;
    json j = json::object();
    j["id"] = r.id;
    j["name"] = r.name;
    j["enabled"] = r.enabled;
    j["proto"] = ProtoName(r.proto);
    j["listen"] = json{{"addr", r.listenAddr}, {"port", r.listenPort}};
    j["remote"] = json{{"host", r.remoteHost}, {"port", r.remotePort}};
    j["egress"] = std::move(egress);
    j["limits"] = json{{"maxConnections", r.maxConnections}, {"udpIdleSec", r.udpIdleSec}};
    j["lanAck"] = r.lanAck;
    return j;
}

std::string ValidateRule(const Rule& r, const std::vector<std::string>& localAddrs) {
    return ValidateRuleImpl(r, &localAddrs);
}

std::string ValidateStoredRule(const Rule& r) {
    return ValidateRuleImpl(r, nullptr);
}

std::string ValidateRuleChange(const Rule* before, const Rule& after, const std::vector<std::string>& localAddrs) {
    if (before && before->listenAddr == after.listenAddr) return ValidateStoredRule(after);
    return ValidateRule(after, localAddrs);
}

// ---- The set ------------------------------------------------------------------------------

std::string ValidateSet(const std::vector<Rule>& rules, std::string* offendingId) {
    if (rules.size() > kMaxRules) {
        if (offendingId) *offendingId = rules[kMaxRules].id;
        return rule_err::kTooManyRules;
    }
    for (size_t i = 0; i < rules.size(); ++i) {
        for (size_t k = 0; k < i; ++k) {
            if (rules[k].id == rules[i].id) {
                if (offendingId) *offendingId = rules[i].id;
                return rule_err::kDuplicateId;
            }
        }
    }
    for (size_t i = 0; i < rules.size(); ++i) {
        if (!rules[i].enabled) continue;
        for (size_t k = 0; k < i; ++k) {
            if (!rules[k].enabled) continue;
            if (ListenOverlaps(rules[k], rules[i])) {
                if (offendingId) *offendingId = rules[i].id;
                return rule_err::kListenConflict;
            }
        }
    }
    return std::string();
}

std::string ParseRuleDocument(const json& doc, std::vector<Rule>* out) {
    if (!doc.is_object()) return rule_err::kBadDocument;
    long long v = 0;
    if (!JsonGetInt64(doc, "v", &v) || v != 1) return rule_err::kBadVersion;
    const auto rules = doc.find("rules");
    if (rules == doc.end() || !rules->is_array()) return rule_err::kBadDocument;
    if (rules->size() > kMaxRules) return rule_err::kTooManyRules;

    std::vector<Rule> parsed;
    parsed.reserve(rules->size());
    for (const json& j : *rules) {
        Rule r;
        std::string code = ParseRule(j, &r);
        if (code.empty()) code = ValidateStoredRule(r);
        if (!code.empty()) return code;
        parsed.push_back(std::move(r));
    }
    const std::string code = ValidateSet(parsed);
    if (!code.empty()) return code;
    if (out) *out = std::move(parsed);
    return std::string();
}

json RuleDocumentToJson(const std::vector<Rule>& rules) {
    json arr = json::array();
    for (const Rule& r : rules) arr.push_back(RuleToJson(r));
    json doc = json::object();
    doc["v"] = 1;
    doc["rules"] = std::move(arr);
    return doc;
}

}  // namespace pf
