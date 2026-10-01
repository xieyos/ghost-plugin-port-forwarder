#include "paths.h"

#include "build_info.h"
#include "util_str.h"

#include <windows.h>
#include <knownfolders.h>
#include <shlobj.h>

#include <cstdint>
#include <cstdio>

namespace pf {

std::wstring DefaultStandaloneDataDir() {
    PWSTR base = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DEFAULT, nullptr, &base)) || !base) {
        if (base) CoTaskMemFree(base);
        return std::wstring();
    }
    std::wstring dir(base);
    CoTaskMemFree(base);
    if (dir.empty()) return std::wstring();
    if (dir.back() != L'\\') dir.push_back(L'\\');
    return dir + Utf8ToWide(PF_PLUGIN_ID);
}

std::wstring FullPath(const std::wstring& dir) {
    if (dir.empty()) return std::wstring();
    const DWORD n = GetFullPathNameW(dir.c_str(), 0, nullptr, nullptr);
    if (n == 0) return std::wstring();
    std::wstring out(n, L'\0');
    const DWORD got = GetFullPathNameW(dir.c_str(), n, out.data(), nullptr);
    if (got == 0 || got >= n) return std::wstring();
    out.resize(got);
    // "C:\" keeps its separator; any other trailing one goes.
    while (out.size() > 3 && (out.back() == L'\\' || out.back() == L'/')) out.pop_back();
    return out;
}

bool EnsureDirectory(const std::wstring& dir, std::string* error) {
    if (dir.empty()) {
        if (error) *error = "empty path";
        return false;
    }
    if (!CreateDirectoryW(dir.c_str(), nullptr)) {
        const DWORD e = GetLastError();
        if (e != ERROR_ALREADY_EXISTS) {
            if (error) *error = "CreateDirectoryW failed: Win32 error " + std::to_string(e);
            return false;
        }
    }
    const DWORD attr = GetFileAttributesW(dir.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
        if (error) *error = "exists but is not a directory";
        return false;
    }
    return true;
}

bool SamePath(const std::wstring& a, const std::wstring& b) {
    if (a.empty() || b.empty()) return false;
    if (a.size() > static_cast<size_t>(INT_MAX) || b.size() > static_cast<size_t>(INT_MAX)) return false;
    return CompareStringOrdinal(a.c_str(), static_cast<int>(a.size()), b.c_str(), static_cast<int>(b.size()),
                                TRUE) == CSTR_EQUAL;
}

std::wstring StandaloneMutexName(const std::wstring& dataDir, bool isDefaultDir) {
    std::wstring name = L"Local\\" + Utf8ToWide(PF_PLUGIN_ID) + L".standalone";
    if (isDefaultDir) return name;
    std::wstring lower = dataDir;
    if (!lower.empty()) CharLowerBuffW(lower.data(), static_cast<DWORD>(lower.size()));
    const std::string bytes = WideToUtf8(lower);
    uint64_t h = 1469598103934665603ull;  // FNV-1a 64
    for (unsigned char c : bytes) {
        h ^= c;
        h *= 1099511628211ull;
    }
    wchar_t hex[17];
    swprintf_s(hex, L"%016llx", static_cast<unsigned long long>(h));
    return name + L"." + hex;
}

}  // namespace pf
