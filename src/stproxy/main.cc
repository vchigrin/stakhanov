// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <iostream>
#include <sstream>

#include "stproxy/stproxy_communication.h"

int ProcessRequest(const void* file_mapping_data) {
  const STPROXY_SECTION_HEADER* header =
      static_cast<const STPROXY_SECTION_HEADER*>(file_mapping_data);
  const uint8_t* payload = static_cast<const uint8_t*>(file_mapping_data);
  const uint8_t* stdout_data = payload + sizeof(STPROXY_SECTION_HEADER);
  const uint8_t* stderr_data = stdout_data + header->stdout_byte_size;
  HANDLE stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
  DWORD bytes_written = 0;
  WriteFile(
      stdout_handle,
      stdout_data,
      header->stdout_byte_size,
      &bytes_written,
      NULL);
  if (bytes_written != header->stdout_byte_size) {
    DWORD error_code = GetLastError();
    std::cerr << "WriteFile failed, error code "  << error_code << std::endl;
  }
  HANDLE stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
  bytes_written = 0;
  WriteFile(
      stderr_handle,
      stderr_data,
      header->stderr_byte_size,
      &bytes_written,
      NULL);
  if (bytes_written != header->stderr_byte_size) {
    DWORD error_code = GetLastError();
    std::cerr << "WriteFile failed, error code "  << error_code << std::endl;
  }
  return header->exit_code;
}

int wmain(int argc, const wchar_t* argv[]) {
  if (argc < 2) {
    std::cerr << "Usage: " << argv[0] << "<file_mapping_handle>" << std::endl;
    return 1;
  }

#if defined(STAKHANOV_LASTCHANGE)
  if (argc == 2 && std::wstring(L"--version") == argv[1]) {
    std::cout << STAKHANOV_LASTCHANGE << std::endl;
    return 0;
  }
#else
#error "STAKHANOV_LASTCHANGE macro is not defined."
#endif

  std::wistringstream buffer(argv[1]);
  HANDLE file_mapping_handle = NULL;
  buffer >> file_mapping_handle;
  const void* file_mapping_data = MapViewOfFile(
      file_mapping_handle,
      FILE_MAP_READ,
      0, 0,
      0);
  if (!file_mapping_data) {
    DWORD error_code = GetLastError();
    std::cerr << "MapViewOfFile failed " << argv[1]
              << " error code " << error_code << std::endl;
    CloseHandle(file_mapping_handle);
    return 1;
  }
  int exit_code = ProcessRequest(file_mapping_data);
  UnmapViewOfFile(file_mapping_data);
  CloseHandle(file_mapping_handle);
  return exit_code;
}
