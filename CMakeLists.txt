cmake_minimum_required(VERSION 3.20)

project(port_forwarder LANGUAGES CXX RC)

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

# ---- Compiler and linker flags ---------------------------------------------------
add_compile_options(
  "$<$<COMPILE_LANGUAGE:CXX>:/W4;/WX;/permissive-;/utf-8;/guard:cf;/EHsc;/Zc:__cplusplus>")
add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00
                        JSON_USE_IMPLICIT_CONVERSIONS=0)
add_link_options(/guard:cf /CETCOMPAT)

# ---- pf_core: everything except main.cpp (the tests link it) --------------------
add_library(pf_core STATIC
  src/applog.cpp
  src/engine.cpp
  src/forward_tcp.cpp
  src/ghost_api.cpp
  src/host_handshake.cpp
  src/local_addrs.cpp
  src/rule_store.cpp
  src/rules.cpp
  src/tunnel_client.cpp
)
target_include_directories(pf_core PUBLIC
  "${CMAKE_CURRENT_SOURCE_DIR}/src"
  "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
  "${PF_GEN_DIR}")
target_link_libraries(pf_core PUBLIC bcrypt iphlpapi winhttp ws2_32)

# ---- The plugin executable -------------------------------------------------------
add_executable(port-forwarder
  src/main.cpp
  "${PF_GEN_DIR}/version.rc")
target_link_libraries(port-forwarder PRIVATE pf_core)
set_target_properties(port-forwarder PROPERTIES OUTPUT_NAME "port-forwarder")

enable_testing()
add_subdirectory(tests)
