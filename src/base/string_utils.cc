// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/string_utils.h"

#include <codecvt>
#include <locale>
#include <sstream>

#include <windows.h>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {
log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"PathFromHandle");
}  // nnamespace

namespace base {

std::string ToUTF8FromWide(const std::wstring& wide_string) {
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> cv;
  return cv.to_bytes(wide_string);
}

std::wstring ToWideFromUTF8(const std::string& utf8_string) {
  std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t> cv;
  return cv.from_bytes(utf8_string);
}

std::wstring ToWideFromANSI(const std::string& ansi_string) {
  if (ansi_string.empty())
    return std::wstring();
  int required_size = MultiByteToWideChar(
      CP_ACP,
      0,
      ansi_string.c_str(),
      -1,
      NULL,
      0);
  if (required_size == 0) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "MultiByteToWideChar failed, error " << error);
    return std::wstring();
  }
  std::vector<wchar_t> buffer(required_size + 1);
  int result = MultiByteToWideChar(
      CP_ACP,
      0,
      ansi_string.c_str(),
      -1,
      &buffer[0],
      buffer.size());
  if (result == 0) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "MultiByteToWideChar failed, error " << error);
    return std::wstring();
  }
  return std::wstring(&buffer[0]);
}

std::string ToUTF8FromANSI(const std::string& ansi_string) {
  return ToUTF8FromWide(ToWideFromANSI(ansi_string));
}

std::string UTF8ToLower(const std::string& src) {
  std::wstring wide_str = ToWideFromUTF8(src);
  std::locale c_locale;
  for (auto& symbol : wide_str) {
    symbol = std::tolower(symbol, c_locale);
  }
  return ToUTF8FromWide(wide_str);
}

std::string ASCIIToLower(const std::string& src) {
  std::locale c_locale;
  std::string result = src;
  for (auto& symbol : result) {
    symbol = std::tolower(symbol, c_locale);
  }
  return result;
}

std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
  std::ostringstream buffer;
  buffer << std::hex;
  for (uint8_t byte : bytes) {
    buffer << byte;
  }
  return buffer.str();
}

}  // namespace base

