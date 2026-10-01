// Unit: the adapter filter behind EnumerateLocalIPv4 (local_addrs.h), on hand-built entries.

#include "local_addrs.h"
#include "test_support.h"

#include <string>
#include <vector>

using pf::AdapterIPv4;

namespace {

AdapterIPv4 E(bool up, bool preferred, uint32_t addr) {
    AdapterIPv4 e;
    e.adapterUp = up;
    e.preferred = preferred;
    e.addrHostOrder = addr;
    return e;
}

std::string Join(const std::vector<std::string>& v) {
    std::string s;
    for (const auto& x : v) s += (s.empty() ? "" : ",") + x;
    return s;
}

void Expect(const char* label, const std::vector<AdapterIPv4>& in, const std::string& expected) {
    const std::string got = Join(pf::FilterLocalIPv4(in));
    const std::string l = std::string(label) + ": expected [" + expected + "], got [" + got + "]";
    CHECK_MSG(got == expected, l.c_str());
}

}  // namespace

int main() {
    const uint32_t lan = 0xC0A8010A;  // 192.168.1.10
    const uint32_t vpn = 0x0A000005;  // 10.0.0.5
    Expect("empty", {}, "");
    Expect("one up, preferred", {E(true, true, lan)}, "192.168.1.10");
    Expect("formatting of every octet", {E(true, true, 0x01FF0A00)}, "1.255.10.0");
    Expect("adapter down", {E(false, true, lan)}, "");
    Expect("not preferred (tentative, duplicate or deprecated)", {E(true, false, lan)}, "");
    Expect("loopback 127.0.0.1", {E(true, true, 0x7F000001)}, "");
    Expect("loopback 127.255.255.254", {E(true, true, 0x7FFFFFFE)}, "");
    Expect("128.0.0.1 is not loopback", {E(true, true, 0x80000001)}, "128.0.0.1");
    Expect("126.255.255.255 is not loopback", {E(true, true, 0x7EFFFFFF)}, "126.255.255.255");
    Expect("0.0.0.0", {E(true, true, 0)}, "");
    Expect("duplicates once, first order kept",
           {E(true, true, vpn), E(true, true, lan), E(true, true, vpn)}, "10.0.0.5,192.168.1.10");
    Expect("a down duplicate does not hide an up one", {E(false, true, lan), E(true, true, lan)}, "192.168.1.10");
    Expect("mixed", {E(true, true, lan), E(false, true, vpn), E(true, true, 0x7F000001), E(true, false, 0x0A000006)},
           "192.168.1.10");
    return pf_test::TestExitCode();
}
