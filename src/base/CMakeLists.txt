# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_library(base STATIC
  init_logging.h
  init_logging.cc
)

target_link_libraries(base log4cplus)
target_include_directories(base PUBLIC ${LOG4CPLUS_INCLUDE})

