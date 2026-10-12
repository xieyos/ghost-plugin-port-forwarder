cmake_minimum_required(VERSION 3.21)

project(port_forwarder LANGUAGES C CXX RC)

# The plugin is a native Windows x64 executable built with MSVC and nothing else:
# Ghost duplicates sockets into it and refuses WOW64 processes, and a release
# ships exactly one binary.
if(NOT MSVC OR NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "port-forwarder: build with MSVC for x64 (e.g. -G \"Visual Studio 17 2022\" -A x64)")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
# Static CRT: the plugin runs on machines that may not have the VC++ redistributable.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---- Slint: the standalone window (src/gui.cpp, src/gui/main_window.slint) ------------
# Built from source -- a Rust toolchain (1.92 or later) is part of the build -- and linked
# statically, so that a release is still one exe that brings no DLL of its own. Only what the
# window uses: the winit backend with the software renderer (no OpenGL), accessibility, and
# the compiler that turns .slint into C++ at build time. Fetched before the compiler flags
# below are set: they are this project's, not Slint's.
#
# Licence: the Slint Royalty-free Desktop, Mobile, and Web Applications License 2.0, whose
# attribution is the AboutSlint widget in Help > About (main_window.slint).
set(PF_SLINT_VERSION "1.18.1")
set(PF_SLINT_COMMIT "372cf0ee5577c3dfec309a45e7b778ba4e81b734")  # the tag v1.18.1
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Slint as a static library" FORCE)
set(SLINT_STYLE "fluent" CACHE STRING "" FORCE)
foreach(feature INTERPRETER LIVE_PREVIEW RENDERER_FEMTOVG RENDERER_FEMTOVG_WGPU RENDERER_SKIA
                RENDERER_SKIA_OPENGL RENDERER_SKIA_VULKAN RENDERER_VELLO BACKEND_QT SYSTEM_TRAY
                TESTING SYSTEM_TESTING GETTEXT MCP)
  set(SLINT_FEATURE_${feature} OFF CACHE BOOL "" FORCE)
endforeach()
foreach(feature COMPILER BACKEND_WINIT RENDERER_SOFTWARE ACCESSIBILITY)
  set(SLINT_FEATURE_${feature} ON CACHE BOOL "" FORCE)
endforeach()
# Slint's own Cargo.lock, as committed at that tag: nothing resolved anew at build time.
set(SLINT_LIBRARY_CARGO_FLAGS "--locked" CACHE STRING "" FORCE)
# Rust on the static CRT too (see CMAKE_MSVC_RUNTIME_LIBRARY above): through the environment
# for the configure-time probe of the Rust standard library's own system libraries, and as
# the library's rustflags (below) for the build.
set(ENV{RUSTFLAGS} "-Ctarget-feature=+crt-static")
include(FetchContent)
FetchContent_Declare(Slint
  GIT_REPOSITORY https://github.com/slint-ui/slint.git
  GIT_TAG v${PF_SLINT_VERSION}
  GIT_SHALLOW TRUE
  SOURCE_SUBDIR api/cpp)
FetchContent_MakeAvailable(Slint)
# A tag can be moved; the commit cannot. (A local checkout given through
# FETCHCONTENT_SOURCE_DIR_SLINT is the developer's own choice and is not checked.)
if(NOT FETCHCONTENT_SOURCE_DIR_SLINT)
  execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${slint_SOURCE_DIR}"
                  OUTPUT_VARIABLE PF_SLINT_HEAD OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT PF_SLINT_HEAD STREQUAL PF_SLINT_COMMIT)
    message(FATAL_ERROR "Slint v${PF_SLINT_VERSION} is commit '${PF_SLINT_HEAD}', expected ${PF_SLINT_COMMIT}")
  endif()
endif()
# What ships with the exe names what is in it: the notices of this Slint, from
# third_party/slint/notices.py.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.txt")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/THIRD_PARTY_NOTICES.txt" PF_NOTICES)
string(FIND "${PF_NOTICES}" "Slint ${PF_SLINT_VERSION}\nhttps://slint.dev/ -- https://github.com/slint-ui/slint (commit ${PF_SLINT_COMMIT})" PF_NOTICES_AT)
if(PF_NOTICES_AT LESS 0)
  message(FATAL_ERROR "THIRD_PARTY_NOTICES.txt does not carry the notices of Slint ${PF_SLINT_VERSION} "
                      "(${PF_SLINT_COMMIT}): run third_party/slint/notices.py")
endif()
corrosion_add_target_rustflags(slint_cpp "-Ctarget-feature=+crt-static")
# What the static library's dependencies call in Windows (windowing, GDI, DirectWrite, UI
# Automation, COM, ...). Corrosion links only what the Rust standard library needs; an
# import library on this list that nothing uses adds no import to the exe (test_imports
# lists what does).
set_property(TARGET slint_cpp APPEND PROPERTY INTERFACE_LINK_LIBRARIES
  advapi32 comctl32 comdlg32 d2d1 dbghelp dwmapi dwrite gdi32 imm32 msimg32 ntdll ole32 oleaut32
  propsys shcore shell32 shlwapi synchronization uiautomationcore user32 userenv uxtheme version
  windowscodecs winmm ws2_32)

# ---- The version has exactly one source: manifest.json -------------------------
set(PF_MANIFEST "${CMAKE_CURRENT_SOURCE_DIR}/manifest.json")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${PF_MANIFEST}")
file(READ "${PF_MANIFEST}" PF_MANIFEST_TEXT)
string(JSON PF_VERSION ERROR_VARIABLE PF_JSON_ERR GET "${PF_MANIFEST_TEXT}" version)
if(PF_JSON_ERR)
  message(FATAL_ERROR "manifest.json: cannot read 'version': ${PF_JSON_ERR}")
endif()
string(JSON PF_PLUGIN_ID ERROR_VARIABLE PF_JSON_ERR GET "${PF_MANIFEST_TEXT}" id)
if(PF_JSON_ERR)
  message(FATAL_ERROR "manifest.json: cannot read 'id': ${PF_JSON_ERR}")
endif()
# "[.]", never "\." -- inside a quoted CMake argument "\." is an escape for a plain ".",
# which the regex then reads as "any character", so "1x0x0" and "100.0" would pass.
set(PF_VERSION_REGEX "^(0|[1-9][0-9]*)[.](0|[1-9][0-9]*)[.](0|[1-9][0-9]*)$")
# Self-check of the regex itself, so a future edit cannot quietly reopen that hole.
foreach(bad IN ITEMS "1x0x0" "100.0" "1.0" "1.0.0.0" "01.0.0" "1.0.0-rc1" "v1.0.0")
  if(bad MATCHES "${PF_VERSION_REGEX}")
    message(FATAL_ERROR "CMakeLists.txt: PF_VERSION_REGEX accepts '${bad}'")
  endif()
endforeach()
if(NOT "1.0.0" MATCHES "${PF_VERSION_REGEX}")
  message(FATAL_ERROR "CMakeLists.txt: PF_VERSION_REGEX rejects '1.0.0'")
endif()
if(NOT PF_VERSION MATCHES "${PF_VERSION_REGEX}")
  message(FATAL_ERROR "manifest.json: 'version' must be three numeric parts, got '${PF_VERSION}'")
endif()
set(PF_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PF_VERSION_MINOR ${CMAKE_MATCH_2})
set(PF_VERSION_PATCH ${CMAKE_MATCH_3})
foreach(part IN ITEMS ${PF_VERSION_MAJOR} ${PF_VERSION_MINOR} ${PF_VERSION_PATCH})
  if(part GREATER 65535)
    message(FATAL_ERROR "manifest.json: each version part must be <= 65535, got '${PF_VERSION}'")
  endif()
endforeach()
message(STATUS "port-forwarder ${PF_VERSION} (${PF_PLUGIN_ID})")

set(PF_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")
configure_file(src/build_info.h.in "${PF_GEN_DIR}/build_info.h" @ONLY)
configure_file(src/version.rc.in "${PF_GEN_DIR}/version.rc" @ONLY)

# The management page: three files compiled into the exe as RCDATA (ui_assets.cpp). The
# resource script is generated so that it can name them by absolute path; OBJECT_DEPENDS
# makes an edited page rebuild the resources.
set(PF_UI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/ui")
set(PF_UI_FILES "${PF_UI_DIR}/index.html" "${PF_UI_DIR}/app.js" "${PF_UI_DIR}/app.css")
configure_file(src/resources.rc.in "${PF_GEN_DIR}/resources.rc" @ONLY)
set_source_files_properties("${PF_GEN_DIR}/resources.rc" PROPERTIES OBJECT_DEPENDS "${PF_UI_FILES}")

# ---- Compiler and linker flags ---------------------------------------------------
add_compile_options(
  "$<$<COMPILE_LANGUAGE:CXX>:/W4;/WX;/permissive-;/utf-8;/guard:cf;/EHsc;/Zc:__cplusplus>")
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
                        JSON_USE_IMPLICIT_CONVERSIONS=0)
add_link_options(/guard:cf /CETCOMPAT)

# ---- pf_core: everything except main.cpp (the tests link it) --------------------
add_library(pf_core STATIC
  src/app.cpp
  src/applog.cpp
  src/engine.cpp
  src/forward_tcp.cpp
  src/forward_udp.cpp
  src/ghost_api.cpp
  src/gui_view.cpp
  src/host_handshake.cpp
  src/local_addrs.cpp
  src/paths.cpp
  src/resolve.cpp
  src/rule_store.cpp
  src/rules.cpp
  src/tunnel_client.cpp
  src/ui_assets.cpp
  src/ui_server.cpp
)
target_include_directories(pf_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
  "${PF_GEN_DIR}")
target_link_libraries(pf_core PUBLIC bcrypt iphlpapi ole32 shell32 winhttp ws2_32)

# ---- pf_gui: the standalone window, the one part built against Slint (C++20) -----------
# Slint's headers and the generated one are included with angle brackets and held to no
# warning level: /W4 /WX is for this project's code.
add_library(pf_gui STATIC src/gui.cpp)
target_link_libraries(pf_gui PRIVATE pf_core Slint::Slint)
slint_target_sources(pf_gui src/gui/main_window.slint)
# Images (the icon, AboutSlint's logo) go into the exe, never as a path on the build machine.
set_property(TARGET pf_gui PROPERTY SLINT_EMBED_RESOURCES embed-files)
target_compile_options(pf_gui PRIVATE /external:anglebrackets /external:W0)

# ---- The plugin executable -------------------------------------------------------
add_executable(port-forwarder
  src/main.cpp
  "${PF_GEN_DIR}/version.rc"
  "${PF_GEN_DIR}/resources.rc")
target_link_libraries(port-forwarder PRIVATE pf_core pf_gui)
set_target_properties(port-forwarder PROPERTIES OUTPUT_NAME "port-forwarder")

enable_testing()
add_subdirectory(tests)
