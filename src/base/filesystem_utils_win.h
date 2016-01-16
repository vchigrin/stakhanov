// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_FILESYSTEM_UTILS_WIN_H_
#define BASE_FILESYSTEM_UTILS_WIN_H_

#include <windows.h>
#include <winternl.h>  // for UNICODE_STRING

#include <string>
#include <vector>

namespace base {

inline std::wstring StringFromAPIString(const UNICODE_STRING& api_string) {
  return std::wstring(
      api_string.Buffer,
      api_string.Buffer + api_string.Length / sizeof(WCHAR));
}

std::vector<std::wstring> GetDriveLetters();
std::wstring GetFilePathFromHandle(HANDLE file_handle);

}  // namespace base

#endif  // BASE_FILESYSTEM_UTILS_WIN_H_
