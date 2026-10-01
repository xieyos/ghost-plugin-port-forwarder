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
  DEPENDS port-forwarder)

pf_add_test(test_api_policy unit
  SOURCES test_api_policy.cpp)

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
