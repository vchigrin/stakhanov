# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_custom_command(OUTPUT gen-cpp/Executor.cpp
    COMMAND thrift-compiler --gen cpp -r
    ${CMAKE_CURRENT_SOURCE_DIR}/stexecutor.thrift
)

add_executable(stexecutor
  main.cc
  gen-cpp/Executor.cpp
)

target_link_libraries(stexecutor log4cplus)
link_against_thrift_library(stexecutor thrift)

target_include_directories(stexecutor PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_include_directories(stexecutor PUBLIC ${BOOST_INCLUDE})
target_include_directories(stexecutor PUBLIC ${THRIFT_INCLUDE})
target_include_directories(stexecutor PUBLIC ${LOG4CPLUS_INCLUDE})

