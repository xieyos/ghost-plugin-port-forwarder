// The forwarding rule model and its validation. Pure logic: no I/O, no system state.
//
// The document (rules.json, and the body of the UI's rule routes):
//
//   {"v":1,"rules":[{"id":"r_<16hex>","name":"...","enabled":true,"proto":"tcp"|"udp",
//     "listen":{"addr":"127.0.0.1","port":8080},"remote":{"host":"example.com","port":80},
//     "egress":{"kind":"direct"|"active"|"node","nodeId":"..."},
//     "limits":{"maxConnections":128,"udpIdleSec":60},"lanAck":false}]}
//
// Reading follows one rule: unknown fields are ignored, a known field of the wrong type
// rejects the rule -- never "use the default instead". A default is used only when the
// field is absent (see ParseRule for which fields may be).
//
// Every rejection is a short snake_case code. The UI server answers it to the page as
// {"error":"<code>"}, so the page can name the field; the full list is below.
#pragma once

#include "json_util.h"

#include <string>
#include <vector>

namespace pf {

// ---- Reason codes ------------------------------------------------------------------
namespace rule_err {
// One rule
constexpr const char* kBadRule = "bad_rule";                // the rule is not a JSON object
constexpr const char* kBadId = "bad_id";                    // id is not r_<16 lower-case hex>
constexpr const char* kBadName = "bad_name";                // name: 1..64 code points, valid UTF-8, no controls
constexpr const char* kBadEnabled = "bad_enabled";          // enabled present but not a boolean
constexpr const char* kBadProto = "bad_proto";              // proto missing or not "tcp"/"udp"
constexpr const char* kBadListenAddr = "bad_listen_addr";   // listen.addr not allowed here
constexpr const char* kBadListenPort = "bad_listen_port";   // listen.port not an integer 1..65535
constexpr const char* kBadHost = "bad_host";                // remote.host fails the host grammar
constexpr const char* kBadRemotePort = "bad_remote_port";   // remote.port not an integer 1..65535
constexpr const char* kBadEgress = "bad_egress";            // egress not an object / kind unknown
constexpr const char* kBadNodeId = "bad_node_id";           // kind "node" without a well-formed nodeId
constexpr const char* kBadLimits = "bad_limits";            // maxConnections 1..1024, udpIdleSec 5..3600
constexpr const char* kBadLanAck = "bad_lan_ack";           // lanAck present but not a boolean
constexpr const char* kLanAckRequired = "lan_ack_required"; // non-loopback listen without lanAck:true
constexpr const char* kLoop = "loop";                       // a direct rule that forwards to itself
// The set
constexpr const char* kTooManyRules = "too_many_rules";     // more than kMaxRules
constexpr const char* kDuplicateId = "duplicate_id";
constexpr const char* kListenConflict = "listen_conflict";  // two enabled rules on one (proto, addr, port)
// The document
constexpr const char* kBadDocument = "bad_document";        // not an object, or rules not an array
constexpr const char* kBadVersion = "bad_version";          // v is not the integer 1
}  // namespace rule_err

// ---- Limits and defaults -------------------------------------------------------------
constexpr size_t kMaxRules = 64;
constexpr size_t kMaxNameCodePoints = 64;
constexpr long long kMinMaxConnections = 1, kMaxMaxConnections = 1024, kDefaultMaxConnections = 128;
constexpr long long kMinUdpIdleSec = 5, kMaxUdpIdleSec = 3600, kDefaultUdpIdleSec = 60;
constexpr size_t kMaxHostBytes = 253;
constexpr size_t kMaxNodeIdBytes = 64;

// The two listen addresses that need no adapter: loopback and "every interface".
constexpr const char* kLoopbackAddr = "127.0.0.1";
constexpr const char* kAnyAddr = "0.0.0.0";

enum class Proto { Tcp, Udp };
enum class EgressKind { Direct, Active, Node };

const char* ProtoName(Proto p);           // "tcp" / "udp"
const char* EgressKindName(EgressKind k); // "direct" / "active" / "node"

struct Rule {
    std::string id;     // "r_" + 16 lower-case hex digits
    std::string name;
    bool enabled = true;
    Proto proto = Proto::Tcp;
    std::string listenAddr;  // dotted IPv4
    int listenPort = 0;
    std::string remoteHost;  // IPv4, IPv6 without brackets, or a host name
    int remotePort = 0;
    EgressKind egress = EgressKind::Direct;
    std::string nodeId;      // non-empty only when egress == Node
    int maxConnections = static_cast<int>(kDefaultMaxConnections);
    int udpIdleSec = static_cast<int>(kDefaultUdpIdleSec);
    bool lanAck = false;
};

// Field-by-field equality. The engine restarts a rule exactly when this says it changed.
bool operator==(const Rule& a, const Rule& b);
inline bool operator!=(const Rule& a, const Rule& b) { return !(a == b); }

// ---- Grammar pieces (exposed for the tests and the UI server) -------------------------

// Strict dotted IPv4: four parts of 1..3 digits, each <= 255, no leading zeros.
// Rejects 127.1, 0x7f000001, 1.2.3.04, " 1.2.3.4".
bool IsStrictIPv4(const std::string& s);
// IPv6 text without brackets and without a zone: hex groups of 1..4 digits, at most
// one "::", optionally ending in a strict dotted IPv4 (which counts as two groups).
bool IsIPv6Literal(const std::string& s);
// Host name: <= 253 bytes; labels of 1..63 [A-Za-z0-9_-] not starting or ending with
// '-'; no empty label (so no trailing dot); the last label contains a letter and does
// not start with "0x"/"0X" -- otherwise a resolver may read it as a number (127.1,
// 0x7f000001) and connect somewhere the text does not say.
bool IsHostName(const std::string& s);
// remote.host: exactly one of the three above.
bool IsValidRemoteHost(const std::string& s);
// ^[A-Za-z0-9_.-]{1,64}$
bool IsNodeIdShaped(const std::string& s);
// ^r_[0-9a-f]{16}$
bool IsRuleIdShaped(const std::string& s);
// Valid UTF-8, 1..64 code points, no C0 control and no DEL.
bool IsValidRuleName(const std::string& s);

// ---- One rule ---------------------------------------------------------------------------

// JSON -> Rule. Checks types and enumerations only (ranges and grammar are
// ValidateRule's): returns "" or one of bad_rule, bad_id (wrong type), bad_name,
// bad_enabled, bad_proto, bad_listen_addr, bad_listen_port, bad_host, bad_remote_port,
// bad_egress, bad_node_id, bad_limits, bad_lan_ack.
//   Required: name, proto, listen{addr, port}, remote{host, port}.
//   Optional: id (absent -> "", the UI server assigns one before validating),
//             enabled (true), egress (direct), limits and each of its keys (128 / 60),
//             lanAck (false).
//   egress.nodeId is read only when kind is "node"; for other kinds it is dropped.
std::string ParseRule(const json& j, Rule* out);

// The inverse of ParseRule; always writes every field. nodeId only for kind "node".
json RuleToJson(const Rule& r);

// Range and grammar checks, in field order. `localAddrs` is this machine's IPv4
// addresses (see local_addrs.h); listen.addr must be 127.0.0.1, 0.0.0.0 or one of them.
// Kept as a parameter so this stays pure. Returns "" or a code from rule_err.
//
// The self-loop check applies to direct rules only: through a node, "127.0.0.1" is the
// node's own loopback and the connection never comes back here.
std::string ValidateRule(const Rule& r, const std::vector<std::string>& localAddrs);

// The same checks for a rule read back from rules.json, except that listen.addr only
// has to be a strict IPv4: an adapter address that has gone away (a new DHCP lease, a
// VPN that is down) must not make the whole file "corrupt" and get it renamed aside.
// Such a rule simply fails to bind when the engine starts it.
std::string ValidateStoredRule(const Rule& r);

// ---- The set ------------------------------------------------------------------------------

// Set-level checks, assuming each rule is already valid on its own:
//   too_many_rules  more than 64 rules
//   duplicate_id    two rules with one id
//   listen_conflict two ENABLED rules of one proto on one port where the addresses are
//                   equal or either is 0.0.0.0 (it binds every interface)
// Returns "" or the code; `offendingId` (optional) receives the id of the second rule
// involved, for the page to point at.
std::string ValidateSet(const std::vector<Rule>& rules, std::string* offendingId = nullptr);

// The whole document: v == 1, rules an array, every rule ParseRule + ValidateStoredRule,
// then ValidateSet. On failure `out` is left untouched.
std::string ParseRuleDocument(const json& doc, std::vector<Rule>* out);
json RuleDocumentToJson(const std::vector<Rule>& rules);

}  // namespace pf
