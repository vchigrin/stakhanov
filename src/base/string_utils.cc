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

std::wstring ToWideFromUTF8(const std::string& utf8_string) {
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> cv;
  return cv.from_bytes(utf8_string);
}

std::string UTF8ToLower(const std::string& src) {
  std::wstring wide_str = ToWideFromUTF8(src);
  std::locale c_locale;
  for (auto& symbol : wide_str) {
    symbol = std::tolower(symbol, c_locale);
  }
  return ToUTF8FromWide(wide_str);
}

}  // namespace base

