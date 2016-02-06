// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_FILESYSTEM_UTILS_H_
#define BASE_FILESYSTEM_UTILS_H_

#include <windows.h>

#include <string>
#include <vector>

#include "boost/filesystem.hpp"

namespace base {

boost::filesystem::path GetCurrentExecutableDir();

template <typename CHAR_TYPE>
std::string AbsPathUTF8(const std::basic_string<CHAR_TYPE>& path) {
  boost::filesystem::path file_path(path);
  boost::filesystem::path abs_path = boost::filesystem::absolute(
      file_path);
  return abs_path.string(std::codecvt_utf8_utf16<wchar_t>());
}

template<typename CHAR_TYPE>
DWORD GetLongPathNameImpl(
    const CHAR_TYPE* shord_path, CHAR_TYPE* long_path, DWORD buffer_length);

template<>
inline DWORD GetLongPathNameImpl(
    const CHAR* shord_path, CHAR* long_path, DWORD buffer_length) {
  return GetLongPathNameA(shord_path, long_path, buffer_length);
}

template<>
inline DWORD GetLongPathNameImpl(
    const WCHAR* shord_path, WCHAR* long_path, DWORD buffer_length) {
  return GetLongPathNameW(shord_path, long_path, buffer_length);
}


template<typename CHAR_TYPE>
std::basic_string<CHAR_TYPE> ToLongPathName(
    const std::basic_string<CHAR_TYPE>& src) {
  std::vector<CHAR_TYPE> buffer(src.length() + 1);
  while (true) {
    DWORD api_result = GetLongPathNameImpl(
        src.c_str(), &buffer[0], buffer.size());
    if (api_result > buffer.size()) {
      buffer.resize(api_result);
    }
    if (api_result == 0) {
      return src;  // Failure for any reason - go with original path name.
    }
    return std::basic_string<CHAR_TYPE>(&buffer[0]);
  }
}

struct FilePathHash {
  size_t operator()(const boost::filesystem::path& file_path) const {
    std::hash<std::wstring> hasher;
    return hasher(file_path.generic_wstring());
  }
};

}  // namespace base

#endif  // BASE_FILESYSTEM_UTILS_H_
