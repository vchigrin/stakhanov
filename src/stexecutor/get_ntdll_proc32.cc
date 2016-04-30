// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <iostream>

int main(int argc, const char* argv[]) {
  if (argc != 2) {
    std::cerr << "Usage: get_ntdll_proc32.exe <function_name_from ntdll.dll\n";
  }
  void* result = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), argv[1]);
  return reinterpret_cast<int>(result);
}
