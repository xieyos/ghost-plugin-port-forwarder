// UTF-8 <-> UTF-16 conversion. Every string inside the plugin is UTF-8; it becomes
// UTF-16 only at the boundary of a W-suffixed Win32 call, and only through here.
#pragma once

#include <windows.h>

#include <string>

namespace pf {

// Invalid UTF-8 becomes U+FFFD rather than failing: the inputs are paths and names
// that are about to be shown or passed to Windows, never compared as secrets.
inline std::wstring Utf8ToWide(const std::string& s) {
    if (s.empty()) return std::wstring();
    if (s.size() > static_cast<size_t>(INT_MAX)) return std::wstring();
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return std::wstring();
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
    return w;
}

// Unpaired surrogates become U+FFFD.
inline std::string WideToUtf8(const std::wstring& w) {
    if (w.empty()) return std::string();
    if (w.size() > static_cast<size_t>(INT_MAX)) return std::string();
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), nullptr, 0,
                                      nullptr, nullptr);
    if (n <= 0) return std::string();
    std::string s(static_cast<size_t>(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), static_cast<int>(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

// Reads an environment variable through the W API. Returns false when the variable
// does not exist; an existing but empty variable is "present" with an empty value.
inline bool GetEnvUtf8(const wchar_t* name, std::string* value) {
    SetLastError(ERROR_SUCCESS);
    DWORD n = GetEnvironmentVariableW(name, nullptr, 0);
    if (n == 0) {
        if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) return false;
        if (value) value->clear();
        return true;
    }
    std::wstring buf(n, L'\0');
    for (int attempt = 0; attempt < 4; ++attempt) {
        const DWORD got = GetEnvironmentVariableW(name, buf.data(), static_cast<DWORD>(buf.size()));
        if (got == 0) {
            if (GetLastError() == ERROR_ENVVAR_NOT_FOUND) return false;
            if (value) value->clear();
            return true;
        }
        if (got < buf.size()) {
            buf.resize(got);
            if (value) *value = WideToUtf8(buf);
            return true;
        }
        buf.assign(got, L'\0');  // grew between the two calls
    }
    return false;
}

}  // namespace pf
