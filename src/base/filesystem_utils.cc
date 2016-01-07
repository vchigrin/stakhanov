// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/filesystem_utils.h"

#include <windows.h>

namespace base {

boost::filesystem::path GetCurrentExecutableDir() {
  // Must be enough.
  wchar_t buffer[MAX_PATH + 1];
  DWORD result = GetModuleFileName(NULL, buffer, MAX_PATH + 1);
  if (result == 0 || result > MAX_PATH) {
    return boost::filesystem::path();
  }
  boost::filesystem::path exe_path(buffer);
  return exe_path.parent_path();
}

}  // namespace base
