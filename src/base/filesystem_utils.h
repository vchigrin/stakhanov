// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_FILESYSTEM_UTILS_H_
#define BASE_FILESYSTEM_UTILS_H_

#include <windows.h>

#include <cassert>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

namespace base {

boost::filesystem::path GetCurrentExecutableDir();
boost::filesystem::path GetCurrentExecutablePath();

template <typename CHAR_TYPE>
std::string AbsPathUTF8(const std::basic_string<CHAR_TYPE>& path) {
  boost::filesystem::path file_path(path);
  boost::filesystem::path abs_path = boost::filesystem::absolute(
      file_path);
  return abs_path.string(std::codecvt_utf8_utf16<wchar_t>());
}

template<typename CHAR_TYPE>
struct LongPathNameHelpers {
};

template<>
struct LongPathNameHelpers<CHAR> {
  static const CHAR kShortPathNameMark = '~';

  static inline DWORD GetLongPathNameImpl(
      const CHAR* shord_path, CHAR* long_path, DWORD buffer_length) {
    return GetLongPathNameA(shord_path, long_path, buffer_length);
  }
};

template<>
struct LongPathNameHelpers<WCHAR> {
  static const WCHAR kShortPathNameMark = L'~';

  static inline DWORD GetLongPathNameImpl(
      const WCHAR* shord_path, WCHAR* long_path, DWORD buffer_length) {
    return GetLongPathNameW(shord_path, long_path, buffer_length);
  }
};


template<typename CHAR_TYPE>
std::basic_string<CHAR_TYPE> ToLongPathName(
    const std::basic_string<CHAR_TYPE>& src) {
  if (src.find(LongPathNameHelpers<CHAR_TYPE>::kShortPathNameMark) ==
      std::basic_string<CHAR_TYPE>::npos) {
    // This path does not look like short path name.
    // TODO(vchigrin): Is it 100% correct?
    return src;
  }

  // Allocate buffer with additional space for NUL character.
  std::basic_string<CHAR_TYPE> buffer(src.length() + 1, '\0');
  while (true) {
    DWORD api_result = LongPathNameHelpers<CHAR_TYPE>::GetLongPathNameImpl(
        src.c_str(), &buffer[0], static_cast<DWORD>(buffer.size()));
    if (api_result == 0) {
      return src;  // Failure for any reason - go with original path name.
    }

    if (api_result > buffer.size()) {
      // Expand the buffer and try again.
      // |api_result| will contain required size of the buffer
      // with a NUL character.
      buffer.resize(api_result);
      continue;
    }

    // Resize the buffer to sync std::string::size() with |api_result| value.
    buffer.resize(api_result);
    return buffer;
  }

  assert(!"Should not reach this line.");
  return src;
}

struct FilePathHash {
  size_t operator()(const boost::filesystem::path& file_path) const {
    std::hash<std::wstring> hasher;
    return hasher(file_path.generic_wstring());
  }
};

bool IsAncestorOfFile(
    const boost::filesystem::path& may_be_ancesor_abs_path,
    const boost::filesystem::path& object_abs_path);

}  // namespace base

#endif  // BASE_FILESYSTEM_UTILS_H_
