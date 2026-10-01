#include "resolve.h"

#include "forward_common.h"
#include "util_str.h"

#include <cstring>
#include <memory>

namespace pf {

namespace {

// How long a cancelled lookup gets to report its end before we stop waiting for it.
constexpr DWORD kCancelWaitMs = 5000;

// One asynchronous lookup. Heap-allocated: GetAddrInfoExW writes `result` and signals
// `ov.hEvent` when it completes, which may be after we stopped waiting.
struct Lookup {
    OVERLAPPED ov = {};
    ADDRINFOEXW* result = nullptr;
    HANDLE cancel = nullptr;
    ~Lookup() {
        if (result) FreeAddrInfoExW(result);
        if (ov.hEvent) CloseHandle(ov.hEvent);
    }
};

template <typename AI>
void Collect(const AI* list, std::vector<ResolvedAddr>* out) {
    for (const AI* ai = list; ai; ai = ai->ai_next) {
        if (!ai->ai_addr || ai->ai_addrlen == 0 || ai->ai_addrlen > sizeof(sockaddr_storage)) continue;
        if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) continue;
        ResolvedAddr a;
        a.family = ai->ai_family;
        std::memcpy(&a.addr, ai->ai_addr, ai->ai_addrlen);
        a.len = static_cast<int>(ai->ai_addrlen);
        out->push_back(a);
    }
}

}  // namespace

std::string ResolveHost(const std::string& host, int port, int socktype, HANDLE stopEvent,
                        std::vector<ResolvedAddr>* out) {
    out->clear();
    const std::wstring h = Utf8ToWide(host);
    const std::wstring p = std::to_wstring(port);
    const int protocol = socktype == SOCK_DGRAM ? IPPROTO_UDP : IPPROTO_TCP;

    auto lk = std::make_unique<Lookup>();
    lk->ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (lk->ov.hEvent) {
        ADDRINFOEXW hints = {};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = socktype;
        hints.ai_protocol = protocol;
        int rc = GetAddrInfoExW(h.c_str(), p.c_str(), NS_ALL, nullptr, &hints, &lk->result, nullptr, &lk->ov,
                                nullptr, &lk->cancel);
        if (rc == WSA_IO_PENDING) {
            HANDLE waits[2] = {lk->ov.hEvent, stopEvent};
            const DWORD w = WaitForMultipleObjects(stopEvent ? 2 : 1, waits, FALSE, kNameLookupTimeoutMs);
            if (w != WAIT_OBJECT_0) {
                GetAddrInfoExCancel(&lk->cancel);
                if (WaitForSingleObject(lk->ov.hEvent, kCancelWaitMs) != WAIT_OBJECT_0) {
                    // The lookup has not let go of `lk` yet: leave it to it rather than free
                    // memory it may still write.
                    lk.release();
                }
                return w == WAIT_TIMEOUT ? std::string(fwd_err::kResolveFailed) : std::string(resolve_err::kCancelled);
            }
            rc = GetAddrInfoExOverlappedResult(&lk->ov);
        }
        if (rc == NO_ERROR) {
            Collect(lk->result, out);
            return out->empty() ? std::string(fwd_err::kResolveFailed) : std::string();
        }
        if (rc != WSAEINVAL && rc != WSAEOPNOTSUPP) return fwd_err::kResolveFailed;
        // The asynchronous form is not available here: fall through to the blocking one.
    }

    ADDRINFOW hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    ADDRINFOW* list = nullptr;
    if (GetAddrInfoW(h.c_str(), p.c_str(), &hints, &list) != 0 || !list) return fwd_err::kResolveFailed;
    Collect(list, out);
    FreeAddrInfoW(list);
    return out->empty() ? std::string(fwd_err::kResolveFailed) : std::string();
}

void InterleaveFamilies(std::vector<ResolvedAddr>* addrs) {
    if (addrs->size() < 3) {
        // Two addresses of different families are already interleaved; two of one family
        // have nothing to interleave with.
        return;
    }
    const int first = (*addrs)[0].family;
    std::vector<ResolvedAddr> same;
    std::vector<ResolvedAddr> other;
    for (const ResolvedAddr& a : *addrs) (a.family == first ? same : other).push_back(a);
    std::vector<ResolvedAddr> out;
    out.reserve(addrs->size());
    size_t i = 0;
    size_t j = 0;
    while (i < same.size() || j < other.size()) {
        if (i < same.size()) out.push_back(same[i++]);
        if (j < other.size()) out.push_back(other[j++]);
    }
    addrs->swap(out);
}

}  // namespace pf
