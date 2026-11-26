// Functional: DialTcp and ConnectDirect (dialer.h) on real loopback sockets, with a
// recording TunnelSource standing in for Ghost.
//
// Every refusal row aims at a listener that would accept the connection, and asserts that
// it saw none: "via a node" must never become "direct" -- not when there is no Ghost, not
// when Ghost refuses, not when Ghost answers success without a socket.

#include "dialer.h"
#include "forward_common.h"
#include "test_support.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <string>
#include <utility>

using namespace pf;

namespace {

// Accepts whatever reaches `l` within `waitMs`; returns how many connections that was.
int DrainAccepts(SOCKET l, DWORD waitMs) {
    int n = 0;
    const ULONGLONG deadline = GetTickCount64() + waitMs;
    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) return n;
        fd_set r;
        FD_ZERO(&r);
        FD_SET(l, &r);
        timeval tv = {0, static_cast<long>(deadline - now) * 1000};
        if (select(0, &r, nullptr, nullptr, &tv) <= 0) return n;
        SOCKET a = accept(l, nullptr, nullptr);
        if (a != INVALID_SOCKET) {
            ++n;
            closesocket(a);
        }
    }
}

// Windows cannot be asked whether a socket is non-blocking, so this asks recv: on an idle
// connection a non-blocking socket answers WSAEWOULDBLOCK at once. A blocking one would
// wait -- the receive timeout makes that a 200 ms WSAETIMEDOUT (a "no") instead of a hang.
// Changes the socket's receive timeout; use it on a socket the test then throws away.
bool IsNonBlocking(SOCKET s) {
    const DWORD timeoutMs = 200;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeoutMs), sizeof(timeoutMs));
    char b;
    const int r = recv(s, &b, 1, MSG_PEEK);
    return r == SOCKET_ERROR && WSAGetLastError() == WSAEWOULDBLOCK;
}

UniqueSocket ConnectTo(int port) {
    UniqueSocket s(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(static_cast<u_short>(port));
    if (connect(s.get(), reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) s.Reset();
    return s;
}

// Answers what it is told and records what it was asked.
class RecordingSource final : public TunnelSource {
public:
    std::string answerCode;
    int answerSocketPort = 0;  // > 0: answer a socket connected to 127.0.0.1:<port>

    int calls = 0;
    EgressKind egress = EgressKind::Direct;
    std::string nodeId;
    Proto proto = Proto::Udp;
    std::string host;
    int port = 0;
    SOCKET handed = INVALID_SOCKET;

    std::string Availability() override { return std::string(); }
    TunnelResult Open(EgressKind e, const std::string& n, Proto p, const std::string& h, int pt) override {
        ++calls;
        egress = e;
        nodeId = n;
        proto = p;
        host = h;
        port = pt;
        TunnelResult r;
        r.code = answerCode;
        if (answerSocketPort > 0) {
            r.sock = ConnectTo(answerSocketPort);
            handed = r.sock.get();
        }
        return r;
    }
    void Shutdown() override {}
};

void TestDirectConnects() {
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    std::atomic<bool> stop{false};
    UniqueSocket out;
    const std::string code = DialTcp(EgressKind::Direct, "", "127.0.0.1", l.port, nullptr, {&stop, nullptr}, &out);
    CHECK_EQ(code, std::string());
    CHECK(out.valid());
    CHECK_MSG(IsNonBlocking(out.get()), "a direct connection comes back non-blocking");
    CHECK_EQ(DrainAccepts(l.sock, 1000), 1);
}

void TestDirectHonoursStop() {
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    std::atomic<bool> stop{true};
    UniqueSocket out;
    // An IPv4 literal resolves without a lookup, so the stop is met in the connect loop.
    const std::string code = ConnectDirect("127.0.0.1", l.port, {&stop, nullptr}, &out);
    CHECK_EQ(code, std::string(fwd_err::kConnectFailed));
    CHECK(!out.valid());
    CHECK_MSG(DrainAccepts(l.sock, 300) == 0, "a stopped dial starts no connection");
}

void TestDirectNothingListening() {
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    const int port = l.port;
    l.Close();  // the port is now closed
    UniqueSocket out;
    const ULONGLONG t0 = GetTickCount64();
    const std::string code = ConnectDirect("127.0.0.1", port, {}, &out);
    const ULONGLONG took = GetTickCount64() - t0;
    CHECK_EQ(code, std::string(fwd_err::kConnectFailed));
    CHECK(!out.valid());
    // Windows retries a refused loopback connect for about 2 s; the budget caps it.
    CHECK_MSG(took < kDirectConnectTimeoutMs + 1000, "bounded by kDirectConnectTimeoutMs");
}

void TestViaNodeWithoutGhost() {
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    for (EgressKind e : {EgressKind::Active, EgressKind::Node}) {
        UniqueSocket out;
        const std::string code = DialTcp(e, "n1", "127.0.0.1", l.port, nullptr, {}, &out);
        CHECK_EQ(code, std::string(tunnel_err::kNeedsGhost));
        CHECK(!out.valid());
    }
    CHECK_MSG(DrainAccepts(l.sock, 300) == 0, "no Ghost: never a direct connection instead");
}

void TestViaNodeRefused() {
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    RecordingSource src;
    src.answerCode = "upstream_unreachable";
    UniqueSocket out;
    const std::string code = DialTcp(EgressKind::Node, "n1", "127.0.0.1", l.port, &src, {}, &out);
    CHECK_EQ(code, std::string("upstream_unreachable"));
    CHECK(!out.valid());
    CHECK_EQ(src.calls, 1);
    CHECK_MSG(DrainAccepts(l.sock, 300) == 0, "Ghost refused: never a direct connection instead");
}

void TestViaNodeSuccessWithoutSocket() {
    pf_test::LoopbackListener l;
    CHECK(pf_test::ListenLoopback(&l));
    RecordingSource src;  // code "" and no socket
    UniqueSocket out;
    const std::string code = DialTcp(EgressKind::Node, "n1", "127.0.0.1", l.port, &src, {}, &out);
    CHECK_EQ(code, std::string(fwd_err::kInternal));
    CHECK(!out.valid());
    CHECK_MSG(DrainAccepts(l.sock, 300) == 0, "an empty success is not a reason to go direct");
}

void TestViaNodeHandsOverAndPassesArguments() {
    pf_test::LoopbackListener ghostSide;  // where the "tunnel" socket is connected
    CHECK(pf_test::ListenLoopback(&ghostSide));
    pf_test::LoopbackListener target;     // the host:port asked for; must see nothing
    CHECK(pf_test::ListenLoopback(&target));

    struct Row {
        EgressKind egress;
        std::string nodeId;
    };
    for (const Row& row : {Row{EgressKind::Node, "node-7"}, Row{EgressKind::Active, ""}}) {
        RecordingSource src;
        src.answerSocketPort = ghostSide.port;
        UniqueSocket out;
        const std::string code =
            DialTcp(row.egress, row.nodeId, "example.test", target.port, &src, {}, &out);
        CHECK_EQ(code, std::string());
        CHECK_MSG(out.valid() && out.get() == src.handed, "the socket Ghost handed over, not another");
        CHECK_EQ(src.calls, 1);
        CHECK(src.egress == row.egress);
        CHECK_EQ(src.nodeId, row.nodeId);
        CHECK_MSG(src.proto == Proto::Tcp, "a TCP dial asks for a TCP tunnel");
        CHECK_EQ(src.host, std::string("example.test"));
        CHECK_EQ(src.port, target.port);
        CHECK_EQ(DrainAccepts(ghostSide.sock, 1000), 1);
    }
    CHECK_MSG(DrainAccepts(target.sock, 300) == 0, "the target is reached only through the tunnel");
}

}  // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    pf_test::WinsockScope ws;
    CHECK(ws.ok());
    TestDirectConnects();
    TestDirectHonoursStop();
    TestDirectNothingListening();
    TestViaNodeWithoutGhost();
    TestViaNodeRefused();
    TestViaNodeSuccessWithoutSocket();
    TestViaNodeHandsOverAndPassesArguments();
    return pf_test::TestExitCode();
}
