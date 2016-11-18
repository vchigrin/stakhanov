# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_library(base STATIC
  filesystem_utils.cc
  filesystem_utils.h
  filesystem_utils_win.cc
  filesystem_utils_win.h
  init_logging.cc
  init_logging.h
  interface.cc
  interface.h
  redis_client_pool.cc
  redis_client_pool.h
  redis_key_scanner.cc
  redis_key_scanner.h
  sthook_constants.cc
  sthook_constants.h
  string_utils.cc
  string_utils.h
)

target_link_libraries(base
  ${Boost_LIBRARIES}
  log4cplus
)

target_include_directories(base PUBLIC
  ${BOOST_INCLUDE}
  ${LOG4CPLUS_INCLUDE}
)
