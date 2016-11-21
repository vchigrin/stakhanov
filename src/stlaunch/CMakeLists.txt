# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_version_resource(stlaunch.rc stlaunch.ver)

add_executable(stlaunch
  stlaunch.cc
  stlaunch.rc
)
