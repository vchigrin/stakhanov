# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_version_resource(stproxy.rc stproxy.ver)

add_executable(stproxy
  main.cc
  stproxy.rc
  stproxy_communication.h
)

