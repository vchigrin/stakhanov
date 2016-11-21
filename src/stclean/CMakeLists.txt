# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.


add_version_resource(stclean.rc stclean.ver)

add_executable(stclean
  main.cc
  stclean.rc
)

target_link_libraries(stclean
  base
  log4cplus
  redisclient
  stexecutorlib
)

target_include_directories(stclean PUBLIC
  ${CMAKE_CURRENT_BINARY_DIR}
  ${BOOST_INCLUDE}
  ${LOG4CPLUS_INCLUDE}
)

