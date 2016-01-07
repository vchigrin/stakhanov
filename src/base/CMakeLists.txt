# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_library(base STATIC
  filesystem_utils.cc
  filesystem_utils.h
  init_logging.cc
  init_logging.h
  sthook_constants.cc
  sthook_constants.h
)

target_link_libraries(base
  ${Boost_LIBRARIES}
  log4cplus
)

target_include_directories(base PUBLIC
  ${BOOST_INCLUDE}
  ${LOG4CPLUS_INCLUDE}
)
