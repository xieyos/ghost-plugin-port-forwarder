// Unit: the rule model (rules.h).
//
// Every rejected row starts from one good rule and breaks exactly one thing, and asserts the
// exact code -- so a row passes only because the check it is about exists, not because some
// other check happened to trip first.

#include "rules.h"
#include "test_support.h"

#include <functional>
#include <string>
#include <vector>

using pf::json;
using pf::Rule;
namespace E = pf::rule_err;

namespace {

const std::vector<std::string> kLocal = {"192.168.1.10", "10.0.0.5"};

json GoodRule() {
    return json::parse(R"({
        "id": "r_0123456789abcdef", "name": "web", "enabled": true, "proto": "tcp",
        "listen": {"addr": "127.0.0.1", "port": 8080},
        "remote": {"host": "example.com", "port": 80},
        "egress": {"kind": "direct"},
        "limits": {"maxConnections": 128, "udpIdleSec": 60},
        "lanAck": false})");
}

std::string Check(const json& j, const std::vector<std::string>& addrs, Rule* parsed = nullptr) {
    Rule r;
    std::string code = pf::ParseRule(j, &r);
    if (!code.empty()) return code;
    if (parsed) *parsed = r;
    return pf::ValidateRule(r, addrs);
}

std::string Repeat(const std::string& s, size_t n) {
    std::string out;
    for (size_t i = 0; i < n; ++i) out += s;
    return out;
}

struct Row {
    const char* label;
    std::function<void(json&)> mutate;
    std::string expected;  // "" = accepted
};

void RuleRows() {
    const std::string cjk = "\xE7\xAB\xAF";        // 端, 3 bytes, one code point
    const std::string emoji = "\xF0\x9F\x98\x80";  // U+1F600, 4 bytes, one code point
    const std::vector<Row> rows = {
        {"baseline", [](json&) {}, ""},
        {"rule not an object", [](json& j) { j = json::array({1}); }, E::kBadRule},
        {"unknown fields are ignored", [](json& j) { j["color"] = "red"; j["listen"]["extra"] = json::array(); }, ""},
        // id
        {"id missing", [](json& j) { j.erase("id"); }, E::kBadId},
        {"id a number", [](json& j) { j["id"] = 7; }, E::kBadId},
        {"id upper-case hex", [](json& j) { j["id"] = "r_0123456789ABCDEF"; }, E::kBadId},
        {"id 15 hex", [](json& j) { j["id"] = "r_0123456789abcde"; }, E::kBadId},
        {"id 17 hex", [](json& j) { j["id"] = "r_0123456789abcdef0"; }, E::kBadId},
        {"id wrong prefix", [](json& j) { j["id"] = "x_0123456789abcdef"; }, E::kBadId},
        // name
        {"name missing", [](json& j) { j.erase("name"); }, E::kBadName},
        {"name a number", [](json& j) { j["name"] = 7; }, E::kBadName},
        {"name empty", [](json& j) { j["name"] = ""; }, E::kBadName},
        {"name 64 ascii", [](json& j) { j["name"] = std::string(64, 'a'); }, ""},
        {"name 65 ascii", [](json& j) { j["name"] = std::string(65, 'a'); }, E::kBadName},
        {"name 64 CJK (192 bytes)", [cjk](json& j) { j["name"] = Repeat(cjk, 64); }, ""},
        {"name 65 CJK", [cjk](json& j) { j["name"] = Repeat(cjk, 65); }, E::kBadName},
        {"name 64 emoji (256 bytes)", [emoji](json& j) { j["name"] = Repeat(emoji, 64); }, ""},
        {"name 65 emoji", [emoji](json& j) { j["name"] = Repeat(emoji, 65); }, E::kBadName},
        {"name with a tab", [](json& j) { j["name"] = "a\tb"; }, E::kBadName},
        {"name with DEL", [](json& j) { j["name"] = "a\x7f"; }, E::kBadName},
        {"name with C1 NEL", [](json& j) { j["name"] = "a\xC2\x85"; }, E::kBadName},
        {"name with a space is fine", [](json& j) { j["name"] = "my web"; }, ""},
        // enabled
        {"enabled missing -> true", [](json& j) { j.erase("enabled"); }, ""},
        {"enabled false", [](json& j) { j["enabled"] = false; }, ""},
        {"enabled \"true\"", [](json& j) { j["enabled"] = "true"; }, E::kBadEnabled},
        {"enabled 1", [](json& j) { j["enabled"] = 1; }, E::kBadEnabled},
        // proto
        {"proto missing", [](json& j) { j.erase("proto"); }, E::kBadProto},
        {"proto TCP", [](json& j) { j["proto"] = "TCP"; }, E::kBadProto},
        {"proto sctp", [](json& j) { j["proto"] = "sctp"; }, E::kBadProto},
        {"proto 6", [](json& j) { j["proto"] = 6; }, E::kBadProto},
        {"proto udp", [](json& j) { j["proto"] = "udp"; }, ""},
        // listen.addr
        {"listen missing", [](json& j) { j.erase("listen"); }, E::kBadListenAddr},
        {"listen a string", [](json& j) { j["listen"] = "127.0.0.1:8080"; }, E::kBadListenAddr},
        {"listen.addr missing", [](json& j) { j["listen"].erase("addr"); }, E::kBadListenAddr},
        {"listen.addr a number", [](json& j) { j["listen"]["addr"] = 2130706433; }, E::kBadListenAddr},
        {"listen.addr localhost", [](json& j) { j["listen"]["addr"] = "localhost"; }, E::kBadListenAddr},
        {"listen.addr 127.0.0.2", [](json& j) { j["listen"]["addr"] = "127.0.0.2"; }, E::kBadListenAddr},
        {"listen.addr 127.000.0.1", [](json& j) { j["listen"]["addr"] = "127.000.0.1"; }, E::kBadListenAddr},
        {"listen.addr ::1", [](json& j) { j["listen"]["addr"] = "::1"; }, E::kBadListenAddr},
        {"listen.addr not on this machine",
         [](json& j) { j["listen"]["addr"] = "192.168.1.99"; j["lanAck"] = true; }, E::kBadListenAddr},
        {"listen.addr local + lanAck", [](json& j) { j["listen"]["addr"] = "192.168.1.10"; j["lanAck"] = true; }, ""},
        {"listen.addr 0.0.0.0 + lanAck", [](json& j) { j["listen"]["addr"] = "0.0.0.0"; j["lanAck"] = true; }, ""},
        // lanAck
        {"local addr without lanAck", [](json& j) { j["listen"]["addr"] = "10.0.0.5"; }, E::kLanAckRequired},
        {"0.0.0.0 without lanAck", [](json& j) { j["listen"]["addr"] = "0.0.0.0"; }, E::kLanAckRequired},
        {"0.0.0.0 lanAck false", [](json& j) { j["listen"]["addr"] = "0.0.0.0"; j["lanAck"] = false; },
         E::kLanAckRequired},
        {"lanAck \"yes\"", [](json& j) { j["lanAck"] = "yes"; }, E::kBadLanAck},
        {"lanAck 1", [](json& j) { j["lanAck"] = 1; }, E::kBadLanAck},
        {"lanAck missing -> false", [](json& j) { j.erase("lanAck"); }, ""},
        {"loopback with lanAck true is fine", [](json& j) { j["lanAck"] = true; }, ""},
        // listen.port
        {"listen.port missing", [](json& j) { j["listen"].erase("port"); }, E::kBadListenPort},
        {"listen.port 0", [](json& j) { j["listen"]["port"] = 0; }, E::kBadListenPort},
        {"listen.port 65536", [](json& j) { j["listen"]["port"] = 65536; }, E::kBadListenPort},
        {"listen.port -1", [](json& j) { j["listen"]["port"] = -1; }, E::kBadListenPort},
        {"listen.port 8080.0", [](json& j) { j["listen"]["port"] = 8080.0; }, E::kBadListenPort},
        {"listen.port \"8080\"", [](json& j) { j["listen"]["port"] = "8080"; }, E::kBadListenPort},
        {"listen.port true", [](json& j) { j["listen"]["port"] = true; }, E::kBadListenPort},
        {"listen.port 2^32 + 8080", [](json& j) { j["listen"]["port"] = 4294975376LL; }, E::kBadListenPort},
        {"listen.port 1", [](json& j) { j["listen"]["port"] = 1; }, ""},
        {"listen.port 65535", [](json& j) { j["listen"]["port"] = 65535; }, ""},
        // remote
        {"remote missing", [](json& j) { j.erase("remote"); }, E::kBadHost},
        {"remote a string", [](json& j) { j["remote"] = "example.com:80"; }, E::kBadHost},
        {"remote.host missing", [](json& j) { j["remote"].erase("host"); }, E::kBadHost},
        {"remote.host a number", [](json& j) { j["remote"]["host"] = 7; }, E::kBadHost},
        {"remote.host empty", [](json& j) { j["remote"]["host"] = ""; }, E::kBadHost},
        {"remote.host 127.1", [](json& j) { j["remote"]["host"] = "127.1"; }, E::kBadHost},
        {"remote.host IPv6", [](json& j) { j["remote"]["host"] = "2001:db8::1"; }, ""},
        {"remote.port missing", [](json& j) { j["remote"].erase("port"); }, E::kBadRemotePort},
        {"remote.port 0", [](json& j) { j["remote"]["port"] = 0; }, E::kBadRemotePort},
        {"remote.port 65536", [](json& j) { j["remote"]["port"] = 65536; }, E::kBadRemotePort},
        {"remote.port \"80\"", [](json& j) { j["remote"]["port"] = "80"; }, E::kBadRemotePort},
        {"remote.port 80.5", [](json& j) { j["remote"]["port"] = 80.5; }, E::kBadRemotePort},
        // egress
        {"egress missing -> direct", [](json& j) { j.erase("egress"); }, ""},
        {"egress a string", [](json& j) { j["egress"] = "direct"; }, E::kBadEgress},
        {"egress {}", [](json& j) { j["egress"] = json::object(); }, E::kBadEgress},
        {"egress kind DIRECT", [](json& j) { j["egress"]["kind"] = "DIRECT"; }, E::kBadEgress},
        {"egress kind proxy", [](json& j) { j["egress"]["kind"] = "proxy"; }, E::kBadEgress},
        {"egress kind 1", [](json& j) { j["egress"]["kind"] = 1; }, E::kBadEgress},
        {"egress active", [](json& j) { j["egress"]["kind"] = "active"; }, ""},
        {"egress node n1", [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", "n1"}}; }, ""},
        {"egress node, nodeId missing", [](json& j) { j["egress"] = {{"kind", "node"}}; }, E::kBadNodeId},
        {"egress node, nodeId empty", [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", ""}}; },
         E::kBadNodeId},
        {"egress node, nodeId 7", [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", 7}}; }, E::kBadNodeId},
        {"egress node, nodeId 64 chars",
         [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", std::string(64, 'n')}}; }, ""},
        {"egress node, nodeId 65 chars",
         [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", std::string(65, 'n')}}; }, E::kBadNodeId},
        {"egress node, nodeId with a space", [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", "a b"}}; },
         E::kBadNodeId},
        {"egress node, nodeId with a slash", [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", "a/b"}}; },
         E::kBadNodeId},
        {"egress node, nodeId every allowed class",
         [](json& j) { j["egress"] = {{"kind", "node"}, {"nodeId", "n.1_x-Y"}}; }, ""},
        {"egress direct, nodeId 7 (wrong type still rejects)",
         [](json& j) { j["egress"] = {{"kind", "direct"}, {"nodeId", 7}}; }, E::kBadNodeId},
        {"egress direct, nodeId string is dropped",
         [](json& j) { j["egress"] = {{"kind", "direct"}, {"nodeId", "n1"}}; }, ""},
        // limits
        {"limits missing -> defaults", [](json& j) { j.erase("limits"); }, ""},
        {"limits {} -> defaults", [](json& j) { j["limits"] = json::object(); }, ""},
        {"limits a number", [](json& j) { j["limits"] = 5; }, E::kBadLimits},
        {"maxConnections 0", [](json& j) { j["limits"]["maxConnections"] = 0; }, E::kBadLimits},
        {"maxConnections 1", [](json& j) { j["limits"]["maxConnections"] = 1; }, ""},
        {"maxConnections 1024", [](json& j) { j["limits"]["maxConnections"] = 1024; }, ""},
        {"maxConnections 1025", [](json& j) { j["limits"]["maxConnections"] = 1025; }, E::kBadLimits},
        {"maxConnections \"128\"", [](json& j) { j["limits"]["maxConnections"] = "128"; }, E::kBadLimits},
        {"maxConnections 1.5", [](json& j) { j["limits"]["maxConnections"] = 1.5; }, E::kBadLimits},
        {"udpIdleSec 4", [](json& j) { j["limits"]["udpIdleSec"] = 4; }, E::kBadLimits},
        {"udpIdleSec 5", [](json& j) { j["limits"]["udpIdleSec"] = 5; }, ""},
        {"udpIdleSec 3600", [](json& j) { j["limits"]["udpIdleSec"] = 3600; }, ""},
        {"udpIdleSec 3601", [](json& j) { j["limits"]["udpIdleSec"] = 3601; }, E::kBadLimits},
        {"udpIdleSec null", [](json& j) { j["limits"]["udpIdleSec"] = nullptr; }, E::kBadLimits},
        // loop: a direct rule whose remote end is its own listener
        {"loop 127.0.0.1:8080 -> 127.0.0.1:8080",
         [](json& j) { j["remote"] = {{"host", "127.0.0.1"}, {"port", 8080}}; }, E::kLoop},
        {"loop 127.0.0.1:8080 -> LOCALHOST:8080",
         [](json& j) { j["remote"] = {{"host", "LOCALHOST"}, {"port", 8080}}; }, E::kLoop},
        {"no loop: another port", [](json& j) { j["remote"] = {{"host", "127.0.0.1"}, {"port", 8081}}; }, ""},
        {"no loop: 127.0.0.2 is not our listener",
         [](json& j) { j["remote"] = {{"host", "127.0.0.2"}, {"port", 8080}}; }, ""},
        {"no loop: through a node it is the node's own loopback",
         [](json& j) {
             j["remote"] = {{"host", "127.0.0.1"}, {"port", 8080}};
             j["egress"] = {{"kind", "node"}, {"nodeId", "n1"}};
         },
         ""},
        {"no loop: through the active node",
         [](json& j) { j["remote"] = {{"host", "127.0.0.1"}, {"port", 8080}}; j["egress"]["kind"] = "active"; }, ""},
        {"loop 0.0.0.0:8080 -> 127.0.0.5:8080",
         [](json& j) {
             j["listen"]["addr"] = "0.0.0.0";
             j["lanAck"] = true;
             j["remote"] = {{"host", "127.0.0.5"}, {"port", 8080}};
         },
         E::kLoop},
        {"loop 0.0.0.0:8080 -> a local address:8080",
         [](json& j) {
             j["listen"]["addr"] = "0.0.0.0";
             j["lanAck"] = true;
             j["remote"] = {{"host", "10.0.0.5"}, {"port", 8080}};
         },
         E::kLoop},
        {"loop 0.0.0.0:8080 -> localhost:8080",
         [](json& j) {
             j["listen"]["addr"] = "0.0.0.0";
             j["lanAck"] = true;
             j["remote"] = {{"host", "localhost"}, {"port", 8080}};
         },
         E::kLoop},
        {"loop 192.168.1.10:8080 -> 192.168.1.10:8080",
         [](json& j) {
             j["listen"]["addr"] = "192.168.1.10";
             j["lanAck"] = true;
             j["remote"] = {{"host", "192.168.1.10"}, {"port", 8080}};
         },
         E::kLoop},
        {"no loop: 192.168.1.10:8080 -> 127.0.0.1:8080 (not listening on loopback)",
         [](json& j) {
             j["listen"]["addr"] = "192.168.1.10";
             j["lanAck"] = true;
             j["remote"] = {{"host", "127.0.0.1"}, {"port", 8080}};
         },
         ""},
        {"udp loop too",
         [](json& j) { j["proto"] = "udp"; j["remote"] = {{"host", "127.0.0.1"}, {"port", 8080}}; }, E::kLoop},
    };
    for (const Row& row : rows) {
        json j = GoodRule();
        row.mutate(j);
        const std::string got = Check(j, kLocal);
        const std::string label = std::string(row.label) + ": expected '" + row.expected + "', got '" + got + "'";
        CHECK_MSG(got == row.expected, label.c_str());
    }
}

// Names that cannot come out of the JSON parser (it rejects invalid UTF-8) but can be
// built in code, e.g. by the UI server from a raw body.
void NameBytes() {
    const struct {
        const char* label;
        std::string name;
        bool ok;
    } rows[] = {
        {"lone 0xFF", "a\xFF", false},
        {"lone continuation byte", "\x80", false},
        {"overlong '/'", "\xC0\xAF", false},
        {"overlong 3-byte NUL", "\xE0\x80\x80", false},
        {"surrogate D800", "\xED\xA0\x80", false},
        {"above U+10FFFF", "\xF4\x90\x80\x80", false},
        {"truncated 3-byte", "\xE4\xB8", false},
        {"truncated 2-byte at the end", "ab\xC3", false},
        {"embedded NUL", std::string("a\0b", 3), false},
        {"U+10FFFF is fine", "\xF4\x8F\xBF\xBF", true},
        {"2-byte e-acute", "caf\xC3\xA9", true},
    };
    for (const auto& r : rows) {
        CHECK_MSG(pf::IsValidRuleName(r.name) == r.ok, r.label);
    }
}

void HostGrammar() {
    const struct {
        const char* host;
        bool ok;
        bool oracle;  // InetPtonW(AF_INET6) must agree (rows with a ':' only)
    } rows[] = {
        // host names
        {"example.com", true, false},
        {"localhost", true, false},
        {"a", true, false},
        {"x-y.example", true, false},
        {"_srv._tcp.example.com", true, false},
        {"1example.com", true, false},
        {"example.co1", true, false},
        {"0x7f.com", true, false},  // 0x is judged on the last label only
        {"1e5", true, false},       // has a letter, and no resolver reads it as a number
        {"", false, false},
        {"127.1", false, false},
        {"1.2.3", false, false},
        {"123", false, false},
        {"0x7f000001", false, false},
        {"0X7F000001", false, false},
        {"a.0x7f", false, false},
        {"0x", false, false},
        {"example.com.", false, false},
        {".example.com", false, false},
        {"a..b", false, false},
        {"-a.com", false, false},
        {"a-.com", false, false},
        {"a.b-", false, false},
        {"a b.com", false, false},
        {"a@b.com", false, false},
        {"a%2e.com", false, false},
        {"\xE4\xBE\x8B.com", false, false},
        {" example.com", false, false},
        {"example.com\n", false, false},
        {"http://example.com", false, false},
        {"example.com:80", false, false},
        // IPv4
        {"1.2.3.4", true, false},
        {"0.0.0.0", true, false},
        {"255.255.255.255", true, false},
        {"10.0.0.0", true, false},
        {"1.2.3.04", false, false},
        {"01.2.3.4", false, false},
        {"256.1.1.1", false, false},
        {"1.2.3.4.5", false, false},
        {"1.2.3.-4", false, false},
        {"1.2.3.4 ", false, false},
        // IPv6
        {"::", true, true},
        {"::1", true, true},
        {"2001:db8::1", true, true},
        {"fe80::1:2:3:4", true, true},
        {"1:2:3:4:5:6:7:8", true, true},
        {"1:2:3:4:5:6:7::", true, true},
        {"::2:3:4:5:6:7:8", true, true},
        {"ABCD:ef01::", true, true},
        {"::ffff:1.2.3.4", true, true},
        {"1:2:3:4:5:6:1.2.3.4", true, true},
        {"0000:0000:0000:0000:0000:0000:0000:0001", true, true},
        {":::", false, true},
        {"1::2::3", false, true},
        {"1:2:3:4:5:6:7:8:9", false, true},
        {"1:2:3:4:5:6:7", false, true},
        {"1:2:3:4:5:6:7:8::", false, true},
        {"12345::", false, true},
        {"g::1", false, true},
        {":1::", false, true},
        {"1:", false, true},
        {"1.2.3.4::", false, true},
        {"::256.1.1.1", false, true},
        {"1:2:3:4:5:6:7:1.2.3.4", false, true},
        {"::1.2.3.04", false, false},
        {"[::1]", false, false},
        {"::1%3", false, false},
        {"fe80::1%eth0", false, false},
    };
    for (const auto& r : rows) {
        const std::string label = std::string("host '") + r.host + "'";
        CHECK_MSG(pf::IsValidRemoteHost(r.host) == r.ok, label.c_str());
        if (r.oracle) {
            IN6_ADDR a = {};
            const std::wstring w(r.host, r.host + std::char_traits<char>::length(r.host));
            const bool inet = InetPtonW(AF_INET6, w.c_str(), &a) == 1;
            const std::string olabel = label + " agrees with InetPtonW";
            CHECK_MSG(inet == r.ok, olabel.c_str());
        }
    }
    // Lengths: labels of 63 and names of 253 bytes are the limits.
    const std::string l63(63, 'a');
    CHECK_MSG(pf::IsValidRemoteHost(l63 + ".com"), "63-byte label");
    CHECK_MSG(!pf::IsValidRemoteHost(std::string(64, 'a') + ".com"), "64-byte label");
    std::string name253 = l63 + "." + l63 + "." + l63 + "." + std::string(61, 'b');
    CHECK_MSG(name253.size() == 253 && pf::IsValidRemoteHost(name253), "253-byte name");
    CHECK_MSG(!pf::IsValidRemoteHost(name253 + "b"), "254-byte name");
}

Rule MakeRule(const std::string& id, pf::Proto proto, const std::string& addr, int port, bool enabled = true) {
    Rule r;
    r.id = id;
    r.name = id;
    r.enabled = enabled;
    r.proto = proto;
    r.listenAddr = addr;
    r.listenPort = port;
    r.remoteHost = "example.com";
    r.remotePort = 80;
    r.lanAck = addr != "127.0.0.1";
    return r;
}

std::string Id(int n) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "r_%016x", n);
    return buf;
}

void SetRows() {
    using pf::Proto;
    const std::string a = Id(1), b = Id(2);
    const struct {
        const char* label;
        std::vector<Rule> rules;
        std::string expected;
    } rows[] = {
        {"empty", {}, ""},
        {"loopback twice, same port",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80), MakeRule(b, Proto::Tcp, "127.0.0.1", 80)}, E::kListenConflict},
        {"tcp and udp on one port",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80), MakeRule(b, Proto::Udp, "127.0.0.1", 80)}, ""},
        {"udp twice",
         {MakeRule(a, Proto::Udp, "127.0.0.1", 53), MakeRule(b, Proto::Udp, "127.0.0.1", 53)}, E::kListenConflict},
        {"same addr, other port",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80), MakeRule(b, Proto::Tcp, "127.0.0.1", 81)}, ""},
        {"second disabled",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80), MakeRule(b, Proto::Tcp, "127.0.0.1", 80, false)}, ""},
        {"first disabled",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80, false), MakeRule(b, Proto::Tcp, "127.0.0.1", 80)}, ""},
        {"0.0.0.0 then 127.0.0.1",
         {MakeRule(a, Proto::Tcp, "0.0.0.0", 80), MakeRule(b, Proto::Tcp, "127.0.0.1", 80)}, E::kListenConflict},
        {"127.0.0.1 then 0.0.0.0",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80), MakeRule(b, Proto::Tcp, "0.0.0.0", 80)}, E::kListenConflict},
        {"0.0.0.0 and a LAN address",
         {MakeRule(a, Proto::Tcp, "0.0.0.0", 80), MakeRule(b, Proto::Tcp, "192.168.1.10", 80)}, E::kListenConflict},
        {"0.0.0.0 twice",
         {MakeRule(a, Proto::Udp, "0.0.0.0", 80), MakeRule(b, Proto::Udp, "0.0.0.0", 80)}, E::kListenConflict},
        {"0.0.0.0 and loopback, other port",
         {MakeRule(a, Proto::Tcp, "0.0.0.0", 80), MakeRule(b, Proto::Tcp, "127.0.0.1", 81)}, ""},
        {"0.0.0.0 udp and loopback tcp",
         {MakeRule(a, Proto::Udp, "0.0.0.0", 80), MakeRule(b, Proto::Tcp, "127.0.0.1", 80)}, ""},
        {"two LAN addresses, one port",
         {MakeRule(a, Proto::Tcp, "192.168.1.10", 80), MakeRule(b, Proto::Tcp, "10.0.0.5", 80)}, ""},
        {"duplicate id, both disabled",
         {MakeRule(a, Proto::Tcp, "127.0.0.1", 80, false), MakeRule(a, Proto::Tcp, "127.0.0.1", 81, false)},
         E::kDuplicateId},
    };
    for (const auto& r : rows) {
        std::string offending = "unset";
        const std::string got = pf::ValidateSet(r.rules, &offending);
        const std::string label = std::string(r.label) + ": expected '" + r.expected + "', got '" + got + "'";
        CHECK_MSG(got == r.expected, label.c_str());
        if (!r.expected.empty()) CHECK_MSG(offending == r.rules.back().id, r.label);
    }

    std::vector<Rule> many;
    for (int i = 0; i < 64; ++i) many.push_back(MakeRule(Id(i), Proto::Tcp, "127.0.0.1", 1000 + i));
    CHECK_MSG(pf::ValidateSet(many).empty(), "64 rules are allowed");
    many.push_back(MakeRule(Id(64), Proto::Tcp, "127.0.0.1", 2000));
    CHECK_MSG(pf::ValidateSet(many) == E::kTooManyRules, "65 rules are too many");
}

void ParsedDefaults() {
    json j = GoodRule();
    j.erase("enabled");
    j.erase("egress");
    j.erase("limits");
    j.erase("lanAck");
    Rule r;
    CHECK(Check(j, kLocal, &r).empty());
    CHECK(r.enabled);
    CHECK(r.egress == pf::EgressKind::Direct);
    CHECK(r.maxConnections == 128 && r.udpIdleSec == 60);
    CHECK(!r.lanAck);

    j = GoodRule();
    j["limits"] = {{"udpIdleSec", 9}};
    CHECK(Check(j, kLocal, &r).empty());
    CHECK_MSG(r.maxConnections == 128 && r.udpIdleSec == 9, "a missing limits key takes its default alone");

    j = GoodRule();
    j["egress"] = {{"kind", "active"}, {"nodeId", "n1"}};
    CHECK(Check(j, kLocal, &r).empty());
    CHECK_MSG(r.nodeId.empty(), "nodeId is dropped unless kind is node");
    r.nodeId = "n1";
    CHECK_MSG(pf::ValidateRule(r, kLocal) == E::kBadNodeId, "a Rule built in code: nodeId only with kind node");
}

void StoredVariant() {
    json j = GoodRule();
    j["listen"]["addr"] = "10.255.255.1";  // not in kLocal: the adapter went away
    j["lanAck"] = true;
    Rule r;
    CHECK(pf::ParseRule(j, &r).empty());
    CHECK_MSG(pf::ValidateRule(r, kLocal) == E::kBadListenAddr, "live check: must be on this machine");
    CHECK_MSG(pf::ValidateStoredRule(r).empty(), "stored check: any strict IPv4");
    r.listenAddr = "10.255.255.01";
    CHECK_MSG(pf::ValidateStoredRule(r) == E::kBadListenAddr, "stored check: still a strict IPv4");
    r.listenAddr = "10.255.255.1";
    r.lanAck = false;
    CHECK_MSG(pf::ValidateStoredRule(r) == E::kLanAckRequired, "stored check: still needs lanAck");
}

void RoundTripAndEquality() {
    Rule r;
    json j = GoodRule();
    j["name"] = "\xE7\xAB\xAF\xE5\x8F\xA3 web";
    j["egress"] = {{"kind", "node"}, {"nodeId", "hk-1"}};
    j["proto"] = "udp";
    j["limits"] = {{"maxConnections", 7}, {"udpIdleSec", 30}};
    CHECK(Check(j, kLocal, &r).empty());
    Rule back;
    CHECK(pf::ParseRule(json::parse(pf::RuleToJson(r).dump()), &back).empty());
    CHECK_MSG(back == r, "RuleToJson -> ParseRule round trip");

    Rule direct = r;
    direct.egress = pf::EgressKind::Direct;
    direct.nodeId.clear();
    CHECK_MSG(!pf::RuleToJson(direct)["egress"].contains("nodeId"), "no nodeId written for direct");
    CHECK_MSG(pf::RuleToJson(r)["egress"]["nodeId"] == "hk-1", "nodeId written for node");

    const std::vector<std::pair<const char*, std::function<void(Rule&)>>> edits = {
        {"id", [](Rule& x) { x.id = "r_ffffffffffffffff"; }},
        {"name", [](Rule& x) { x.name += "x"; }},
        {"enabled", [](Rule& x) { x.enabled = !x.enabled; }},
        {"proto", [](Rule& x) { x.proto = pf::Proto::Tcp; }},
        {"listenAddr", [](Rule& x) { x.listenAddr = "0.0.0.0"; }},
        {"listenPort", [](Rule& x) { x.listenPort += 1; }},
        {"remoteHost", [](Rule& x) { x.remoteHost = "example.org"; }},
        {"remotePort", [](Rule& x) { x.remotePort += 1; }},
        {"egress", [](Rule& x) { x.egress = pf::EgressKind::Active; }},
        {"nodeId", [](Rule& x) { x.nodeId = "hk-2"; }},
        {"maxConnections", [](Rule& x) { x.maxConnections += 1; }},
        {"udpIdleSec", [](Rule& x) { x.udpIdleSec += 1; }},
        {"lanAck", [](Rule& x) { x.lanAck = !x.lanAck; }},
    };
    for (const auto& e : edits) {
        Rule changed = r;
        e.second(changed);
        const std::string label = std::string("changing ") + e.first + " makes the rule differ";
        CHECK_MSG(changed != r, label.c_str());
    }
}

void Documents() {
    std::vector<Rule> rules = {MakeRule(Id(1), pf::Proto::Tcp, "127.0.0.1", 80),
                               MakeRule(Id(2), pf::Proto::Udp, "0.0.0.0", 53, false)};
    std::vector<Rule> back;
    CHECK(pf::ParseRuleDocument(json::parse(pf::RuleDocumentToJson(rules).dump()), &back).empty());
    CHECK_MSG(back.size() == 2 && back[0] == rules[0] && back[1] == rules[1], "document round trip");

    const Rule sentinel = MakeRule(Id(99), pf::Proto::Tcp, "127.0.0.1", 9);
    const struct {
        const char* label;
        std::function<void(json&)> mutate;
        std::string expected;
    } rows[] = {
        {"baseline", [](json&) {}, ""},
        {"unknown top-level field", [](json& d) { d["note"] = "x"; }, ""},
        {"empty rules", [](json& d) { d["rules"] = json::array(); }, ""},
        {"not an object", [](json& d) { d = json::array(); }, E::kBadDocument},
        {"v missing", [](json& d) { d.erase("v"); }, E::kBadVersion},
        {"v 2", [](json& d) { d["v"] = 2; }, E::kBadVersion},
        {"v true", [](json& d) { d["v"] = true; }, E::kBadVersion},
        {"v 1.0", [](json& d) { d["v"] = 1.0; }, E::kBadVersion},
        {"v \"1\"", [](json& d) { d["v"] = "1"; }, E::kBadVersion},
        {"rules missing", [](json& d) { d.erase("rules"); }, E::kBadDocument},
        {"rules an object", [](json& d) { d["rules"] = json::object(); }, E::kBadDocument},
        {"a rule with a bad host", [](json& d) { d["rules"][0]["remote"]["host"] = "127.1"; }, E::kBadHost},
        {"a rule that is a string", [](json& d) { d["rules"][1] = "r"; }, E::kBadRule},
        {"a listen address from another machine is kept",
         [](json& d) { d["rules"][0]["listen"]["addr"] = "10.255.255.1"; d["rules"][0]["lanAck"] = true; }, ""},
        {"conflict", [](json& d) { d["rules"][1]["enabled"] = true; d["rules"][1]["proto"] = "tcp";
                                   d["rules"][1]["listen"]["port"] = 80; }, E::kListenConflict},
        {"duplicate id", [](json& d) { d["rules"][1]["id"] = d["rules"][0]["id"]; }, E::kDuplicateId},
        {"65 rules", [](json& d) {
             json arr = json::array();
             for (int i = 0; i < 65; ++i) arr.push_back(pf::RuleToJson(MakeRule(Id(i), pf::Proto::Tcp, "127.0.0.1", 1000 + i)));
             d["rules"] = arr;
         }, E::kTooManyRules},
    };
    for (const auto& r : rows) {
        json d = pf::RuleDocumentToJson(rules);
        r.mutate(d);
        std::vector<Rule> out = {sentinel};
        const std::string got = pf::ParseRuleDocument(d, &out);
        const std::string label = std::string(r.label) + ": expected '" + r.expected + "', got '" + got + "'";
        CHECK_MSG(got == r.expected, label.c_str());
        if (!r.expected.empty()) {
            CHECK_MSG(out.size() == 1 && out[0] == sentinel, "a rejected document leaves the output alone");
        }
    }
}

}  // namespace

int main() {
    RuleRows();
    NameBytes();
    HostGrammar();
    SetRows();
    ParsedDefaults();
    StoredVariant();
    RoundTripAndEquality();
    Documents();
    return pf_test::TestExitCode();
}
