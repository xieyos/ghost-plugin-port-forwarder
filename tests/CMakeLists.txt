# Every test carries exactly one layer label, and the label is a required argument rather
# than a property set afterwards: an unlabelled test would still run, belonging to no layer.
#
#   unit         one function or module, no I/O beyond pipes/handles it creates itself
#   functional   one user-visible capability inside a single process
#   integration  across a process or protocol boundary (a real exe, a fake Ghost)

add_library(pf_test_support INTERFACE)
target_include_directories(pf_test_support INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/support")
target_link_libraries(pf_test_support INTERFACE pf_core ws2_32)

# The fake Ghost control interface (support/fake_ghost.h): an HTTP server and a socket
# handover, no proxy protocol. Linked by the tests that talk to "Ghost".
add_library(pf_fake_ghost STATIC support/fake_ghost.cpp)
target_link_libraries(pf_fake_ghost PUBLIC pf_test_support)

function(pf_add_test name label)
  if(NOT label MATCHES "^(unit|functional|integration)$")
    message(FATAL_ERROR "pf_add_test(${name}): label must be unit, functional or integration, got '${label}'")
  endif()
  cmake_parse_arguments(T "" "" "SOURCES;ARGS;DEPENDS;LIBS" ${ARGN})
  if(NOT T_SOURCES)
    message(FATAL_ERROR "pf_add_test(${name}): SOURCES is required")
  endif()
  add_executable(${name} ${T_SOURCES})
  target_link_libraries(${name} PRIVATE pf_test_support ${T_LIBS})
  if(T_DEPENDS)
    add_dependencies(${name} ${T_DEPENDS})
  endif()
  add_test(NAME ${name} COMMAND ${name} ${T_ARGS})
  set_tests_properties(${name} PROPERTIES LABELS ${label} TIMEOUT 60)
endfunction()

pf_add_test(test_handshake unit
  SOURCES test_handshake.cpp)

pf_add_test(test_rules unit
  SOURCES test_rules.cpp)

pf_add_test(test_rule_store functional
  SOURCES test_rule_store.cpp)

pf_add_test(test_local_addrs_filter unit
  SOURCES test_local_addrs_filter.cpp)

pf_add_test(test_local_addrs functional
  SOURCES test_local_addrs.cpp)

pf_add_test(test_main_exe integration
  SOURCES test_main_exe.cpp
  ARGS "$<TARGET_FILE:port-forwarder>" "${PROJECT_SOURCE_DIR}/manifest.json"
  DEPENDS port-forwarder
  LIBS pf_fake_ghost)

pf_add_test(test_api_policy unit
  SOURCES test_api_policy.cpp)

pf_add_test(test_request_registry unit
  SOURCES test_request_registry.cpp)

pf_add_test(test_ghost_api functional
  SOURCES test_ghost_api.cpp
  LIBS pf_fake_ghost)

pf_add_test(test_tunnel_client functional
  SOURCES test_tunnel_client.cpp
  LIBS pf_fake_ghost)

pf_add_test(test_applog functional
  SOURCES test_applog.cpp
  LIBS pf_fake_ghost)

pf_add_test(test_forward_tcp functional
  SOURCES test_forward_tcp.cpp
  LIBS pf_fake_ghost)

pf_add_test(test_forward_udp functional
  SOURCES test_forward_udp.cpp
  LIBS pf_fake_ghost)

# The page server and its API. The test exe carries the page's resources itself, so that
# the real files are what it serves (ui_assets.cpp reads the running exe's resources).
set_source_files_properties("${PF_GEN_DIR}/resources.rc" PROPERTIES OBJECT_DEPENDS "${PF_UI_FILES}")
pf_add_test(test_ui_server functional
  SOURCES test_ui_server.cpp "${PF_GEN_DIR}/resources.rc"
  LIBS pf_fake_ghost)

pf_add_test(test_ui_source unit
  SOURCES test_ui_source.cpp
  ARGS "${PROJECT_SOURCE_DIR}/ui" "${PROJECT_SOURCE_DIR}/src")

# The real exe hosted by a fake Ghost and then standalone, driven through its page API: three
# kinds of rule end to end, fail-closed, restart, and what log.write carries.
pf_add_test(test_end_to_end integration
  SOURCES test_end_to_end.cpp
  ARGS "$<TARGET_FILE:port-forwarder>"
  DEPENDS port-forwarder
  LIBS pf_fake_ghost)

# The shipped exe's load-time imports: static CRT, system DLLs only, nothing newer than 1607.
pf_add_test(test_imports unit
  SOURCES test_imports.cpp
  ARGS "$<TARGET_FILE:port-forwarder>"
  DEPENDS port-forwarder)

# ---- Checks written in Python (standard library only) ----------------------------------
# Python is optional on a developer machine: without it these two are reported Skipped (exit
# 77), never passed. CI sets PF_REQUIRE_PACK_TEST=ON, which turns a missing Python or SDK
# into a failure -- a check that can silently skip is no check in CI.
option(PF_REQUIRE_PACK_TEST "Fail (rather than skip) when Python or the plugin SDK is missing" OFF)
if(DEFINED ENV{GHOST_PLUGIN_SDK} AND NOT "$ENV{GHOST_PLUGIN_SDK}" STREQUAL "")
  set(PF_SDK_DEFAULT "$ENV{GHOST_PLUGIN_SDK}")
else()
  set(PF_SDK_DEFAULT "${PROJECT_SOURCE_DIR}/../ghost-plugin-sdk")
endif()
set(PF_GHOST_SDK_DIR "${PF_SDK_DEFAULT}" CACHE PATH
    "A checkout of liliBestCoder/ghost-plugin-sdk (tools/plugin/gpkg.py) for the packing check")

find_package(Python3 COMPONENTS Interpreter)
if(NOT Python3_Interpreter_FOUND AND PF_REQUIRE_PACK_TEST)
  message(FATAL_ERROR "PF_REQUIRE_PACK_TEST is ON but no Python 3 interpreter was found")
endif()

function(pf_add_py_test name label)
  if(NOT label MATCHES "^(unit|functional|integration)$")
    message(FATAL_ERROR "pf_add_py_test(${name}): label must be unit, functional or integration, got '${label}'")
  endif()
  if(Python3_Interpreter_FOUND)
    add_test(NAME ${name} COMMAND Python3::Interpreter ${ARGN})
  elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 3.29)
    add_test(NAME ${name} COMMAND "${CMAKE_COMMAND}" -P "${CMAKE_CURRENT_SOURCE_DIR}/skip_no_python.cmake")
  else()
    message(STATUS "${name}: no Python 3 interpreter -- not registered")
    return()
  endif()
  set_tests_properties(${name} PROPERTIES LABELS ${label} TIMEOUT 120 SKIP_RETURN_CODE 77)
endfunction()

# The release files through the SDK's packer (gpkg.py pack --min-app-version 1.2.1).
set(PF_PACK_ARGS
  "${CMAKE_CURRENT_SOURCE_DIR}/test_pack.py"
  --sdk "${PF_GHOST_SDK_DIR}"
  --exe "$<TARGET_FILE:port-forwarder>"
  --src "${PROJECT_SOURCE_DIR}")
if(PF_REQUIRE_PACK_TEST)
  list(APPEND PF_PACK_ARGS --require)
endif()
pf_add_py_test(test_pack functional ${PF_PACK_ARGS})

# The workflows parse as YAML (no plain scalar with ": "), actions are pinned, SDK refs agree.
pf_add_py_test(test_workflows unit
  "${CMAKE_CURRENT_SOURCE_DIR}/check_workflows.py" "${PROJECT_SOURCE_DIR}/.github/workflows")
