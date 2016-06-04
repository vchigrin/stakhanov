# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_library(sthook SHARED
  dllmain.cc
  functions_interceptor.cc
  functions_interceptor.h
  intercept_helper.cc
  intercept_helper.h
  intercepted_functions.cc
  intercepted_functions.h
  process_proxy_manager.cc
  process_proxy_manager.h
  reading_pipe.cc
  reading_pipe.h
  std_handles_holder.cc
  std_handles_holder.h
)

if(CMAKE_CL_64)
  set_target_properties(sthook PROPERTIES OUTPUT_NAME sthook64)
else()
  set_target_properties(sthook PROPERTIES OUTPUT_NAME sthook32)
endif()

add_custom_command(
  OUTPUT
    gen-cpp/Executor.cpp
    gen-cpp/stexecutor_types.cpp
    gen-cpp/Executor.h
  COMMAND thrift-compiler --gen cpp -r
    ${CMAKE_CURRENT_SOURCE_DIR}/stexecutor.thrift
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/stexecutor.thrift
)

target_compile_definitions(sthook PRIVATE
  # To avoid warnings about MD5. They are fine since we use it not for
  # cryptographic targets.
  CRYPTOPP_ENABLE_NAMESPACE_WEAK=1
)

# Small static library with common code need both for sthook and stexecutor.
add_library(sthook_communication STATIC
  gen-cpp/Executor.cpp
  gen-cpp/stexecutor_types.cpp
  sthook_communication.cc
  sthook_communication.h
)

link_against_thrift_library(sthook_communication thrift)

target_include_directories(sthook_communication PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${BOOST_INCLUDE}
    ${THRIFT_INCLUDE}
    ${LOG4CPLUS_INCLUDE}
)

target_link_libraries(sthook
  ${Boost_LIBRARIES}
  base
  cryptopp-static
  log4cplus
  sthook_communication
  ntdll.lib
)

target_include_directories(sthook PUBLIC ${LOG4CPLUS_INCLUDE})
