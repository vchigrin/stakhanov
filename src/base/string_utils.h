// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_STRING_UTILS_H_
#define BASE_STRING_UTILS_H_

#include <string>

namespace base {
std::string ToUTF8FromWide(const std::wstring& wide_string);
std::wstring ToWideFromUTF8(const std::string& utf8_string);
std::string UTF8ToLower(const std::string& src);
}  // namespace base

#endif  // BASE_STRING_UTILS_H_
