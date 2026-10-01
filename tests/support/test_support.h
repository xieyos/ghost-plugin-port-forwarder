// Test scaffolding shared by every test executable. No framework: a test is a main()
// that runs checks and returns TestExitCode().
//
// CHECK and CHECK_MSG are two names on purpose, not one macro overloaded on its argument
// count: under MSVC's traditional preprocessor __VA_ARGS__ is forwarded as one token, the
// two-argument call lands in the one-argument branch and expands to `if (!(cond, "label"))`
// -- a comma expression whose value is the always-true string literal. Every labelled check
// would pass unconditionally.
#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <filesystem>
#include <functional>
#include <string>

namespace pf_test {

inline std::atomic<int>& Failures() {
    static std::atomic<int> n{0};
    return n;
}
inline std::atomic<int>& Passes() {
    static std::atomic<int> n{0};
    return n;
}

inline void Report(bool ok, const char* expr, const char* label, const char* file, int line) {
    if (ok) {
        ++Passes();
        return;
    }
    ++Failures();
    std::fprintf(stderr, "FAIL %s:%d: %s%s%s\n", file, line, expr, label ? "  -- " : "", label ? label : "");
    std::fflush(stderr);
}

// Prints the summary and returns the process exit code.
inline int TestExitCode() {
    const int f = Failures().load();
    if (f == 0) {
        std::printf("all %d checks passed\n", Passes().load());
    } else {
        std::printf("%d of %d checks FAILED\n", f, f + Passes().load());
    }
    std::fflush(stdout);
    return f == 0 ? 0 : 1;
}

// Polls `pred` every 10 ms until it is true or `ms` elapsed. Returns the last result.
// Use this instead of a fixed Sleep: a fixed value is too short on a loaded CI runner
// and too long everywhere else.
inline bool WaitUntil(const std::function<bool()>& pred, DWORD ms) {
    const ULONGLONG deadline = GetTickCount64() + ms;
    for (;;) {
        if (pred()) return true;
        if (GetTickCount64() >= deadline) return pred();
        Sleep(10);
    }
}

// A fresh directory under %TEMP% whose name carries a CJK component, so that any narrow
// (ANSI) path handling breaks visibly in tests instead of on a user's machine.
class ScopedTempDir {
public:
    ScopedTempDir() {
        static std::atomic<unsigned> counter{0};
        wchar_t tmp[MAX_PATH + 1] = {};
        const DWORD n = GetTempPathW(MAX_PATH + 1, tmp);
        std::wstring base = (n > 0 && n <= MAX_PATH) ? std::wstring(tmp, n) : std::wstring(L".\\");
        for (int attempt = 0; attempt < 100; ++attempt) {
            std::wstring p = base + L"pf_test_端口_" + std::to_wstring(GetCurrentProcessId()) + L"_" +
                             std::to_wstring(counter++) + L"_" + std::to_wstring(GetTickCount64());
            if (CreateDirectoryW(p.c_str(), nullptr)) {
                path_ = p;
                return;
            }
        }
    }
    ~ScopedTempDir() {
        if (path_.empty()) return;
        std::error_code ec;
        std::filesystem::remove_all(std::filesystem::path(path_), ec);
    }
    ScopedTempDir(const ScopedTempDir&) = delete;
    ScopedTempDir& operator=(const ScopedTempDir&) = delete;

    bool ok() const { return !path_.empty(); }
    const std::wstring& path() const { return path_; }

private:
    std::wstring path_;
};

// WSAStartup for the lifetime of the object.
class WinsockScope {
public:
    WinsockScope() {
        WSADATA d;
        ok_ = WSAStartup(MAKEWORD(2, 2), &d) == 0;
    }
    ~WinsockScope() {
        if (ok_) WSACleanup();
    }
    bool ok() const { return ok_; }

private:
    bool ok_ = false;
};

// A TCP listener on 127.0.0.1 with a system-chosen port. Closes on destruction.
class LoopbackListener {
public:
    LoopbackListener() = default;
    ~LoopbackListener() { Close(); }
    LoopbackListener(const LoopbackListener&) = delete;
    LoopbackListener& operator=(const LoopbackListener&) = delete;

    SOCKET sock = INVALID_SOCKET;
    unsigned short port = 0;

    void Close() {
        if (sock != INVALID_SOCKET) closesocket(sock);
        sock = INVALID_SOCKET;
        port = 0;
    }
};

// Binds 127.0.0.1:0 and listens. Returns false (and leaves `out` closed) on failure.
inline bool ListenLoopback(LoopbackListener* out, int backlog = SOMAXCONN) {
    out->Close();
    SOCKET s = WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in a = {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    int len = sizeof(a);
    if (bind(s, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0 || listen(s, backlog) != 0 ||
        getsockname(s, reinterpret_cast<sockaddr*>(&a), &len) != 0) {
        closesocket(s);
        return false;
    }
    out->sock = s;
    out->port = ntohs(a.sin_port);
    return true;
}

}  // namespace pf_test

#define CHECK(cond) ::pf_test::Report(static_cast<bool>(cond), #cond, nullptr, __FILE__, __LINE__)
#define CHECK_MSG(cond, label) ::pf_test::Report(static_cast<bool>(cond), #cond, (label), __FILE__, __LINE__)
