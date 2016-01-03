# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_executable(stexecutor
  main.cc
)

target_link_libraries(stexecutor
  base
  sthook_communication
  log4cplus
)

target_include_directories(stexecutor PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${BOOST_INCLUDE}
    ${THRIFT_INCLUDE}
    ${LOG4CPLUS_INCLUDE}
)
