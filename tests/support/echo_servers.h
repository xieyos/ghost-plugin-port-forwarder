// Echo destinations for the tests: what a forwarded connection or a tunnel ends at.
//
// TcpEchoServer echoes every byte back on each accepted connection and honours half-close:
// when the client shuts down its sending side, everything received has already been
// echoed, and the server then shuts down its own sending side. It counts accepted
// connections, so a test can assert that a refused tunnel reached the destination zero
// times.
//
// UdpEchoServer sends every datagram back to where it came from. It counts the datagrams it
// received and remembers each distinct source port, so a test can tell one forwarded
// session from two, and assert that a refused relay reached the destination zero times.
#pragma once

#include "test_support.h"

#include <mswsock.h>

#include <atomic>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

namespace pf_test {

class TcpEchoServer {
public:
    TcpEchoServer() = default;
    ~TcpEchoServer() { Stop(); }
    TcpEchoServer(const TcpEchoServer&) = delete;
    TcpEchoServer& operator=(const TcpEchoServer&) = delete;

    bool Start() {
        if (!ListenLoopback(&listener_)) return false;
        port_ = listener_.port;
        accept_ = std::thread([this, l = listener_.sock] {
            try {
                AcceptLoop(l);
            } catch (...) {
            }
        });
        return true;
    }

    void Stop() {
        stopping_ = true;
        if (accept_.joinable()) accept_.join();
        listener_.Close();
        std::vector<std::thread> threads;
        {
            std::lock_guard<std::mutex> lock(mu_);
            // Each echo thread sees stopping_ within 50 ms and closes its own socket, so no
            // handle is closed while another thread uses it.
            threads.swap(threads_);
        }
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }
    }

    unsigned short port() const { return port_; }
    int Connections() const { return accepted_.load(); }

private:
    void AcceptLoop(SOCKET l) {
        for (;;) {
            if (!WaitReadable(l, stopping_)) return;
            SOCKET c = accept(l, nullptr, nullptr);
            if (c == INVALID_SOCKET) return;
            ++accepted_;
            std::lock_guard<std::mutex> lock(mu_);
            if (stopping_) {
                closesocket(c);
                return;
            }
            threads_.emplace_back([this, c] {
                try {
                    Echo(c);
                } catch (...) {
                }
            });
        }
    }

    void Echo(SOCKET c) {
        char buf[16 * 1024];
        bool ok = true;
        for (;;) {
            if (!WaitReadable(c, stopping_)) {
                ok = false;
                break;
            }
            const int n = recv(c, buf, sizeof(buf), 0);
            if (n <= 0) break;
            int off = 0;
            while (off < n) {
                const int w = send(c, buf + off, n - off, 0);
                if (w <= 0) {
                    ok = false;
                    break;
                }
                off += w;
            }
            if (!ok) break;
        }
        if (ok) shutdown(c, SD_SEND);
        closesocket(c);
    }

    LoopbackListener listener_;
    unsigned short port_ = 0;
    std::atomic<bool> stopping_{false};
    std::atomic<int> accepted_{0};
    std::thread accept_;
    std::mutex mu_;
    std::vector<std::thread> threads_;
};

class UdpEchoServer {
public:
    UdpEchoServer() = default;
    ~UdpEchoServer() { Stop(); }
    UdpEchoServer(const UdpEchoServer&) = delete;
    UdpEchoServer& operator=(const UdpEchoServer&) = delete;

    bool Start() {
        sock_ = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
        if (sock_ == INVALID_SOCKET) return false;
        sockaddr_in a = {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int len = sizeof(a);
        // A reply to a forwarder socket that has closed must not end the echo loop.
        BOOL off = FALSE;
        DWORD bytes = 0;
        WSAIoctl(sock_, SIO_UDP_CONNRESET, &off, sizeof(off), nullptr, 0, &bytes, nullptr, nullptr);
        if (bind(sock_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 ||
            getsockname(sock_, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
            closesocket(sock_);
            sock_ = INVALID_SOCKET;
            return false;
        }
        port_ = ntohs(a.sin_port);
        thread_ = std::thread([this] {
            try {
                Loop();
            } catch (...) {
            }
        });
        return true;
    }

    void Stop() {
        stopping_ = true;
        if (thread_.joinable()) thread_.join();
        if (sock_ != INVALID_SOCKET) closesocket(sock_);
        sock_ = INVALID_SOCKET;
    }

    unsigned short port() const { return port_; }
    int Datagrams() const { return received_.load(); }
    size_t DistinctSources() const {
        std::lock_guard<std::mutex> lock(mu_);
        return sources_.size();
    }

private:
    void Loop() {
        std::vector<char> buf(65536);
        for (;;) {
            if (!WaitReadable(sock_, stopping_)) return;
            sockaddr_in from = {};
            int len = sizeof(from);
            const int n = recvfrom(sock_, buf.data(), static_cast<int>(buf.size()), 0,
                                   reinterpret_cast<sockaddr*>(&from), &len);
            if (n < 0) continue;
            ++received_;
            {
                std::lock_guard<std::mutex> lock(mu_);
                sources_.insert(ntohs(from.sin_port));
            }
            sendto(sock_, buf.data(), n, 0, reinterpret_cast<sockaddr*>(&from), len);
        }
    }

    SOCKET sock_ = INVALID_SOCKET;
    unsigned short port_ = 0;
    std::atomic<bool> stopping_{false};
    std::atomic<int> received_{0};
    mutable std::mutex mu_;
    std::set<unsigned short> sources_;
    std::thread thread_;
};

}  // namespace pf_test
