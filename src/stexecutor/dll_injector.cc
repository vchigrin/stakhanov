// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/dll_injector.h"

#include <windows.h>

#include "base/scoped_handle.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"DllInjector");

bool Is64BitProcess(const base::ScopedHandle& process_handle) {
  BOOL result = FALSE;
  if (!IsWow64Process(process_handle.Get(), &result)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "IsWow64BitProcess failed, error " << error);
    return false;
  }
  return !result;
}

}  // namespace

DllInjector::DllInjector(
    const boost::filesystem::path& injected_32bit_path,
    const boost::filesystem::path& injected_64bit_path,
    uint32_t load_library_32_addr,
    uint64_t load_library_64_addr)
    : injected_32bit_path_(injected_32bit_path),
      injected_64bit_path_(injected_64bit_path),
      load_library_32_addr_(load_library_32_addr),
      load_library_64_addr_(load_library_64_addr) {
}

bool DllInjector::InjectInto(int child_pid) {
  base::ScopedHandle process_handle(::OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_VM_WRITE |
          PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
      FALSE, child_pid));
  if (!process_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenProcess failed. Error " << error);
    return false;
  }
  bool is_64bit = Is64BitProcess(process_handle);
  const boost::filesystem::path& path_to_inject =
      is_64bit ? injected_64bit_path_ : injected_32bit_path_;
  std::wstring path_to_inject_str = path_to_inject.native();
  const size_t buffer_len = (path_to_inject_str.length() + 1) * sizeof(WCHAR);
  LPVOID remote_addr = VirtualAllocEx(
      process_handle.Get(),
      nullptr,
      buffer_len,
      MEM_COMMIT,
      PAGE_READWRITE);
  if (!remote_addr) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_, "Failed allocate remote memory, error " << error);
    return false;
  }
  SIZE_T bytes_written = 0;
  BOOL result = WriteProcessMemory(
      process_handle.Get(),
      remote_addr,
      path_to_inject_str.c_str(),
      buffer_len,
      &bytes_written);
  if (!result || bytes_written != buffer_len) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "WriteProcessMemory failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }

  LPTHREAD_START_ROUTINE start_addr = is_64bit ?
      reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library_64_addr_) :
      reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library_32_addr_);
  base::ScopedHandle thread_handle(CreateRemoteThread(
      process_handle.Get(),
      nullptr,
      0,
      start_addr,
      remote_addr,
      0,
      nullptr));
  if (!thread_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed create remote thread " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }
  WaitForSingleObject(thread_handle.Get(), INFINITE);
  VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
  return true;
}
