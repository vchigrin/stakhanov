# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_library (sthook SHARED
  dllmain.cc
  functions_interceptor.cc
  functions_interceptor.h
)

target_link_libraries (sthook log4cplus)
target_include_directories (sthook PUBLIC ${LOG4CPLUS_INCLUDE})
