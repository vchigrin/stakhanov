// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/filesystem_utils.h"

#include <windows.h>

namespace base {

boost::filesystem::path GetCurrentExecutablePath() {
  // Must be enough.
  wchar_t buffer[MAX_PATH + 1];
  DWORD result = GetModuleFileName(NULL, buffer, MAX_PATH + 1);
  if (result == 0 || result > MAX_PATH) {
    return boost::filesystem::path();
  }
  boost::filesystem::path exe_path(buffer);
  return exe_path;
}

boost::filesystem::path GetCurrentExecutableDir() {
  return GetCurrentExecutablePath().parent_path();
}

bool IsAncestorOfFile(
    const boost::filesystem::path& may_be_ancesor_path,
    const boost::filesystem::path& object_path) {
  size_t ancestor_path_len = std::distance(
      may_be_ancesor_path.begin(), may_be_ancesor_path.end());
  size_t object_path_len = std::distance(
      object_path.begin(), object_path.end());
  if (ancestor_path_len > object_path_len) {
    // Full path of the object must be longer then or equal to the
    // ancestor path length.
    return false;
  }

  return std::equal(
      may_be_ancesor_path.begin(),
      may_be_ancesor_path.end(), object_path.begin());
}

}  // namespace base
