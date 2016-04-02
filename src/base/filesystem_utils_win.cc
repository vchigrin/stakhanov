// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/filesystem_utils_win.h"

#include <windows.h>
#include <winternl.h>

#include <mutex>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"PathFromHandle");

static const int ObjectNameInformation = 1;

#define STATUS_BUFFER_OVERFLOW         ((DWORD)0x80000005L)

typedef struct _OBJECT_NAME_INFORMATION {
  UNICODE_STRING          Name;
  WCHAR                   NameBuffer[1];
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

struct DrivePath {
  std::wstring nt_drive_path;
  std::wstring dos_drive_path;
};

void FillDrivePaths(std::vector<DrivePath>* drive_paths) {
  std::vector<std::wstring> drive_letters = base::GetDriveLetters();
  drive_paths->clear();
  drive_paths->reserve(drive_letters.size());
  std::vector<WCHAR> buffer(100);
  for (const std::wstring& drive_letter : drive_letters) {
    bool success = false;
    while (true) {
      if (QueryDosDeviceW(drive_letter.c_str(), &buffer[0], buffer.size())) {
        success = true;
        break;
      }
      DWORD error = GetLastError();
      if (error == ERROR_INSUFFICIENT_BUFFER) {
        buffer.resize(buffer.size() * 2);
      } else {
        LOG4CPLUS_ERROR(logger_, "QueryDosDeviceW fails, error " << error);
        break;
      }
    }
    if (success) {
      DrivePath item;
      item.nt_drive_path = &buffer[0];
      item.dos_drive_path = drive_letter;
      drive_paths->push_back(item);
    }
  }
}

std::wstring DosPathFromNtPath(const std::wstring& nt_path) {
  static std::mutex dos_path_mutex;
  static std::vector<DrivePath> drive_paths;
  std::lock_guard<std::mutex> dos_path_lock(dos_path_mutex);
  if (drive_paths.empty())
    FillDrivePaths(&drive_paths);
  for (const DrivePath& path  : drive_paths) {
    if (nt_path.find(path.nt_drive_path) == 0) {
      std::wstring result = path.dos_drive_path;
      result += nt_path.substr(path.nt_drive_path.length());
      return result;
    }
  }
  LOG4CPLUS_ERROR(logger_, "Failed find path for " << nt_path);
  return nt_path;
}
}  // namespace

namespace base {

std::vector<std::wstring> GetDriveLetters() {
  DWORD buffer_len = GetLogicalDriveStringsW(0, NULL);
  if (buffer_len == 0) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "GetLogicalDriveStrings fails, error " << error);
    return std::vector<std::wstring>();
  }
  std::vector<WCHAR> buffer(buffer_len + 1);
  buffer_len = GetLogicalDriveStringsW(buffer_len, &buffer[0]);
  if (buffer_len == 0) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "GetLogicalDriveStrings fails, error " << error);
    return std::vector<std::wstring>();
  }
  std::vector<std::wstring> result;
  WCHAR* next_drive = &buffer[0];
  while (*next_drive) {
    std::wstring dos_drive_path = next_drive;
    if (dos_drive_path[dos_drive_path.length() - 1] == L'\\')
      dos_drive_path = dos_drive_path.substr(0, dos_drive_path.length() - 1);
    result.push_back(dos_drive_path);
    next_drive += wcslen(next_drive) + 1;
  }
  return result;
}

std::wstring GetFilePathFromHandle(HANDLE file_handle) {
  std::vector<uint8_t> buffer(100);
  std::wstring nt_path;
  while (true) {
    ULONG result_len = 0;
    NTSTATUS status = NtQueryObject(
        file_handle,
        static_cast<OBJECT_INFORMATION_CLASS>(ObjectNameInformation),
        &buffer[0],
        buffer.size(),
        &result_len);
    if (status == STATUS_BUFFER_OVERFLOW) {
      buffer.resize(buffer.size() * 2);
      continue;
    }
    if (status != 0) {
      LOG4CPLUS_ERROR(
          logger_,
          "NtQueryObject fails with status " << std::hex << status);
      return std::wstring();
    }

    if (status == 0) {
      OBJECT_NAME_INFORMATION* name_info =
          reinterpret_cast<OBJECT_NAME_INFORMATION*>(&buffer[0]);
      nt_path = StringFromAPIString(name_info->Name);
    }
    break;
  }
  return DosPathFromNtPath(nt_path);
}

}  // namespace base
