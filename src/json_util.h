// JSON helpers. The rule is "judge the type, then take the value": json::value() and
// get<T>() throw on a type mismatch, and an exception escaping a worker thread ends
// the process. Every read of untrusted JSON goes through these.
#pragma once

#include <nlohmann/json.hpp>

#include <climits>
#include <string>
#include <vector>

namespace pf {

using json = nlohmann::json;
// Keeps insertion order; for lines whose exact bytes matter (the receipt).
using ordered_json = nlohmann::ordered_json;

// Parses without throwing. Returns a discarded value on any syntax error.
inline json ParseJsonNoThrow(const std::string& text) {
    return json::parse(text, nullptr, /*allow_exceptions=*/false);
}

// Serialises without throwing: invalid UTF-8 in a string becomes U+FFFD instead of
// a type_error escaping into the caller.
template <typename Json>
std::string DumpSafe(const Json& j) {
    return j.dump(-1, ' ', false, Json::error_handler_t::replace);
}

// True when `obj` is an object holding `key` as a string; copies it to `out`.
inline bool JsonGetString(const json& obj, const char* key, std::string* out) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) return false;
    if (out) *out = it->get<std::string>();
    return true;
}

// True when `obj[key]` is an integer (signed or unsigned, never a float or a bool).
inline bool JsonGetInt64(const json& obj, const char* key, long long* out) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end()) return false;
    if (it->is_number_unsigned()) {
        const auto u = it->get<unsigned long long>();
        if (u > static_cast<unsigned long long>(LLONG_MAX)) return false;
        if (out) *out = static_cast<long long>(u);
        return true;
    }
    if (it->is_number_integer()) {
        if (out) *out = it->get<long long>();
        return true;
    }
    return false;
}

// True when `obj[key]` is a boolean (never 0/1, never "true").
inline bool JsonGetBool(const json& obj, const char* key, bool* out) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_boolean()) return false;
    if (out) *out = it->get<bool>();
    return true;
}

// True when `obj` is an object holding `key` (of any type, null included).
inline bool JsonHas(const json& obj, const char* key) {
    return obj.is_object() && obj.find(key) != obj.end();
}

// True when `obj[key]` is an array whose every element is a string.
inline bool JsonGetStringArray(const json& obj, const char* key, std::vector<std::string>* out) {
    if (!obj.is_object()) return false;
    auto it = obj.find(key);
    if (it == obj.end() || !it->is_array()) return false;
    std::vector<std::string> v;
    v.reserve(it->size());
    for (const auto& e : *it) {
        if (!e.is_string()) return false;
        v.push_back(e.get<std::string>());
    }
    if (out) *out = std::move(v);
    return true;
}

}  // namespace pf
