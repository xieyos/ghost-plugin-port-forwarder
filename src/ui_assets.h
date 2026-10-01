// The page's three files (ui/index.html, ui/app.js, ui/app.css), compiled into the exe as
// RCDATA resources (resources.rc.in). Only these three names exist: the page server has a
// whitelist, not a directory.
#pragma once

#include <string>

namespace pf {

struct UiAsset {
    std::string bytes;
    std::string contentType;
};

// name is "index.html", "app.js" or "app.css". Loads from the resources of the running
// exe. False for any other name, or when the resource is missing.
bool LoadEmbeddedUiAsset(const std::string& name, UiAsset* out);

}  // namespace pf
