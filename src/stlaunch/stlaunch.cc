// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <iostream>
#include <vector>

static const wchar_t kHookLibraryName[] =
#ifdef _WIN64
    L"sthook64.dll";
#else
    L"sthook32.dll";
#endif

int wmain(int argc, wchar_t* argv[]) {
  if (argc < 2) {
    std::cout << "Usage:" << std::endl
              << "stlaunch command [arguments]" << std::endl;
    std::cout << "Launches command under Stakhanov build system" << std::endl;
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
  std::wstring command_buffer;
  for (int i = 1; i < argc; ++i) {
    if (i > 1)
      command_buffer += L" ";
    command_buffer += argv[i];
  }
  STARTUPINFOW si;
  PROCESS_INFORMATION pi;
  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  memset(&pi, 0, sizeof(pi));
  const wchar_t* data = command_buffer.c_str();
  std::vector<wchar_t> vt_buffer(data, data + command_buffer.length() + 1);
  // Load hook libary. This will install API hook, that will
  // propagate transitively by process tree.
  HMODULE library = LoadLibraryW(kHookLibraryName);
  if (!library) {
    std::wcerr << "LoadLibrary " << kHookLibraryName
               << " failed. Error " << GetLastError() << std::endl;
    return 1;
  }
  BOOL launch_ok = CreateProcessW(
      nullptr,
      &vt_buffer[0],
      nullptr,
      nullptr,
      FALSE,
      0,
      nullptr,
      nullptr,
      &si, &pi);
  if (!launch_ok || !pi.hProcess) {
    DWORD err = GetLastError();
    std::wcerr << "Failed execute \"" << command_buffer.c_str();
    std::wcerr << "\". GetLastError " << err << std::endl;
    return 1;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exit_code = 0;
  if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
    std::wcerr << "Failed get process exit code. Error "
               << GetLastError() << std::endl;
    exit_code = 1;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return exit_code;
}
