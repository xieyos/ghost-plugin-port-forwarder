// Echo destinations for the tests: what a forwarded connection or a tunnel ends at.
//
// TcpEchoServer echoes every byte back on each accepted connection and honours half-close:
// when the client shuts down its sending side, everything received has already been
// echoed, and the server then shuts down its own sending side. It counts accepted
// connections, so a test can assert that a refused tunnel reached the destination zero
// times.
#pragma once

#include "test_support.h"

#include <atomic>
#include <mutex>
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

}  // namespace pf_test
