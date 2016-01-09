// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_FILESYSTEM_UTILS_H_
#define BASE_FILESYSTEM_UTILS_H_

#include <string>

#include "boost/filesystem.hpp"

namespace base {

boost::filesystem::path GetCurrentExecutableDir();

template <typename CHAR_TYPE>
std::string AbsPathUTF8(const CHAR_TYPE* path) {
  boost::filesystem::path file_path(path);
  boost::filesystem::path abs_path = boost::filesystem::absolute(
      file_path);
  return abs_path.string(std::codecvt_utf8_utf16<wchar_t>());
}

}  // namespace base

#endif  // BASE_FILESYSTEM_UTILS_H_
