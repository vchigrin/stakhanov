// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_STRING_UTILS_H_
#define BASE_STRING_UTILS_H_

#include <string>

namespace base {
std::string ToUTF8FromWide(const std::wstring& wide_string);
std::string ToUTF8FromANSI(const std::string& wide_string);

template <typename CHAR_TYPE>
inline std::string ToUTF8(const std::basic_string<CHAR_TYPE>& src);

template <>
inline std::string ToUTF8(const std::basic_string<wchar_t>& src) {
  return ToUTF8FromWide(src);
}

template <>
inline std::string ToUTF8(const std::basic_string<char>& src) {
  return ToUTF8FromANSI(src);
}

std::wstring ToWideFromUTF8(const std::string& utf8_string);
std::wstring ToWideFromANSI(const std::string& ansi_string);
std::string UTF8ToLower(const std::string& src);
std::string ASCIIToLower(const std::string& src);
}  // namespace base

#endif  // BASE_STRING_UTILS_H_
