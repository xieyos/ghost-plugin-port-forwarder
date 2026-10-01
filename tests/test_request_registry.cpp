// Unit: the live-request registry of GhostApi (request_registry.h), with made-up handle
// values -- it never calls WinHTTP.
//
// The case that matters: Abort closes a handle, WinHTTP hands the same handle value to the
// next request, and the first owner -- still holding the old value -- must not see that
// request as its own, nor release (and so close) it.

#include "request_registry.h"
#include "test_support.h"

#include <cstdint>

using pf::RequestRegistry;

namespace {

void* H(uintptr_t v) { return reinterpret_cast<void*>(v); }

void TestOwnerReleases() {
    RequestRegistry r;
    const uint64_t g = r.Register(H(0x10), 7);
    CHECK(g != 0);
    CHECK(r.Owned(H(0x10), g));
    CHECK_MSG(r.Release(H(0x10), g), "the owner removes its own entry and closes the handle");
    CHECK(!r.Owned(H(0x10), g));
    CHECK_MSG(!r.Release(H(0x10), g), "only once");
}

void TestReusedHandleValue() {
    RequestRegistry r;
    const uint64_t first = r.Register(H(0x20), 1);
    CHECK(first != 0);
    // Abort(1) takes it and closes it...
    const auto taken = r.TakeTag(1);
    CHECK(taken.size() == 1 && taken[0] == H(0x20));
    CHECK(!r.Owned(H(0x20), first));
    // ...and the next request (another tag) gets the same handle value.
    const uint64_t second = r.Register(H(0x20), 2);
    CHECK(second != 0);
    CHECK(second != first);
    CHECK_MSG(!r.Owned(H(0x20), first), "the first owner does not see the new request as its own");
    CHECK_MSG(!r.Release(H(0x20), first), "nor releases it: Abort already closed its handle");
    CHECK_MSG(r.Owned(H(0x20), second), "the new request is untouched");
    CHECK(r.Release(H(0x20), second));
}

void TestTagsAndClose() {
    RequestRegistry r;
    const uint64_t a = r.Register(H(0x31), 5);
    const uint64_t b = r.Register(H(0x32), 6);
    const uint64_t c = r.Register(H(0x33), 0);  // untagged
    CHECK(a != 0 && b != 0 && c != 0);
    CHECK(r.TakeTag(0).empty());  // tag 0 names nothing
    const auto t5 = r.TakeTag(5);
    CHECK(t5.size() == 1 && t5[0] == H(0x31));
    CHECK_MSG(r.Register(H(0x34), 5) == 0, "an aborted tag is refused from then on");
    CHECK(r.Refused(5) && !r.Refused(6) && !r.Refused(0));
    CHECK(r.Owned(H(0x32), b) && r.Owned(H(0x33), c));

    const auto all = r.TakeAll();
    CHECK(all.size() == 2);
    CHECK(!r.Owned(H(0x32), b) && !r.Owned(H(0x33), c));
    CHECK_MSG(r.Register(H(0x35), 0) == 0 && r.Register(H(0x36), 6) == 0, "closed: everything is refused");
    CHECK(r.Refused(0) && r.Refused(6));
}

}  // namespace

int main() {
    TestOwnerReleases();
    TestReusedHandleValue();
    TestTagsAndClose();
    return pf_test::TestExitCode();
}
