#include "ui_assets.h"

#include <windows.h>

namespace pf {

namespace {

struct Entry {
    const char* name;
    const wchar_t* resource;
    const char* contentType;
};

const Entry kAssets[] = {
    {"index.html", L"PF_UI_INDEX_HTML", "text/html; charset=utf-8"},
    {"app.js", L"PF_UI_APP_JS", "text/javascript; charset=utf-8"},
    {"app.css", L"PF_UI_APP_CSS", "text/css; charset=utf-8"},
};

}  // namespace

bool LoadEmbeddedUiAsset(const std::string& name, UiAsset* out) {
    for (const Entry& e : kAssets) {
        if (name != e.name) continue;
        HMODULE module = GetModuleHandleW(nullptr);
        HRSRC res = FindResourceW(module, e.resource, MAKEINTRESOURCEW(10) /* RT_RCDATA */);
        if (!res) return false;
        const DWORD size = SizeofResource(module, res);
        HGLOBAL h = LoadResource(module, res);
        if (!h) return false;
        const void* data = LockResource(h);
        if (!data && size > 0) return false;
        out->bytes.assign(static_cast<const char*>(data), size);
        out->contentType = e.contentType;
        return true;
    }
    return false;
}

}  // namespace pf
