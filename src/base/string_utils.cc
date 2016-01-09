// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/string_utils.h"

#include <codecvt>
#include <locale>

namespace base {

std::string ToUTF8FromWide(const std::wstring& wide_string) {
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> cv;
  return cv.to_bytes(wide_string);
}

}  // namespace base

