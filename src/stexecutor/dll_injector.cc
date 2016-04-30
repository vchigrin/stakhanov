// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/dll_injector.h"

#include <windows.h>
#include <winternl.h>

#include <vector>

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

typedef NTSTATUS (NTAPI *LdrLoadDllPtr)(
    PWCHAR path_to_file,
    ULONG* flags,
    const UNICODE_STRING *module_file_name,
    HMODULE* module_handle);

typedef NTSTATUS (NTAPI *NtSetEventPtr)(HANDLE event, PLONG prev_state);

struct RemoteData {
  UNICODE_STRING dll;
  HANDLE event;
  LdrLoadDllPtr LdrLoadDll;
  NtSetEventPtr NtSetEvent;
};

#pragma code_seg(push, ".cave")
#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(push, off)
extern "C" static void _fastcall code_cave(const RemoteData* data) {
  HMODULE module;
  ULONG flags = LOAD_WITH_ALTERED_SEARCH_PATH;

  NTSTATUS error = data->LdrLoadDll(NULL, &flags, &data->dll, &module);
  data->NtSetEvent(data->event, NULL);
  while (true) {}
}
extern "C" static void code_cave_end() { }
#pragma strict_gs_check(pop)
#pragma code_seg(pop)


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

bool DllInjector::InjectInto(int child_pid, int child_main_thread_id) {
  base::ScopedHandle process_handle(::OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE |
          PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
      FALSE, child_pid));
  if (!process_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenProcess failed. Error " << error);
    return false;
  }
  base::ScopedHandle thread_handle(OpenThread(
      THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
      FALSE,
      child_main_thread_id));
  if (!thread_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenThread failed, error " << error);
    return false;
  }
  base::ScopedHandle inject_ready_event(CreateEvent(
      NULL, TRUE, FALSE, NULL));
  if (!inject_ready_event.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed create event, error " << error);
    return false;
  }
  bool is_64bit = Is64BitProcess(process_handle);
  const boost::filesystem::path& path_to_inject =
      is_64bit ? injected_64bit_path_ : injected_32bit_path_;
  std::wstring path_to_inject_str = path_to_inject.native();
  const size_t code_cave_len =
      reinterpret_cast<const uint8_t*>(code_cave_end) -
      reinterpret_cast<const uint8_t*>(code_cave);
  size_t buffer_len = (path_to_inject_str.length() + 1) * sizeof(WCHAR);
  buffer_len += sizeof(RemoteData);
  buffer_len += code_cave_len;
  // Buffer structure:
  // <code_cave_code>, <RemoteData struct>, <DLL path buffer>
  std::vector<uint8_t> local_buffer(buffer_len);
  std::copy(
      reinterpret_cast<const uint8_t*>(code_cave),
      reinterpret_cast<const uint8_t*>(code_cave) + code_cave_len,
      local_buffer.begin());
  RemoteData* local_data = reinterpret_cast<RemoteData*>(
      local_buffer.data() + code_cave_len);
  wcscpy(
      reinterpret_cast<WCHAR*>(
          local_buffer.data() + sizeof(RemoteData) + code_cave_len),
      path_to_inject_str.c_str());
  local_data->dll.Length = static_cast<USHORT>(
      path_to_inject_str.length() * sizeof(WCHAR));
  local_data->dll.MaximumLength = local_data->dll.Length;
  HMODULE ntdll_module = GetModuleHandleW(L"ntdll.dll");
  local_data->LdrLoadDll = reinterpret_cast<LdrLoadDllPtr>(
      GetProcAddress(ntdll_module, "LdrLoadDll"));
  local_data->NtSetEvent = reinterpret_cast<NtSetEventPtr>(
      GetProcAddress(ntdll_module, "NtSetEvent"));
  if (!local_data->LdrLoadDll || !local_data->NtSetEvent) {
    LOG4CPLUS_ERROR(logger_, "Failed get some API addresses");
    return false;
  }
  if (!DuplicateHandle(
      GetCurrentProcess(),
      inject_ready_event.Get(),
      process_handle.Get(),
      &local_data->event,
      0,
      FALSE,
      DUPLICATE_SAME_ACCESS)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed duplicate handle, error " << error);
    return false;
  }
  LPVOID remote_addr = VirtualAllocEx(
      process_handle.Get(),
      nullptr,
      buffer_len,
      MEM_COMMIT,
      PAGE_EXECUTE_READWRITE);
  if (!remote_addr) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_, "Failed allocate remote memory, error " << error);
    return false;
  }
  local_data->dll.Buffer = reinterpret_cast<WCHAR*>(
      reinterpret_cast<uint8_t*>(remote_addr) +
      sizeof(RemoteData) + code_cave_len);

  SIZE_T bytes_written = 0;
  BOOL result = WriteProcessMemory(
      process_handle.Get(),
      remote_addr,
      local_buffer.data(),
      buffer_len,
      &bytes_written);
  if (!result || bytes_written != buffer_len) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "WriteProcessMemory failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }
  CONTEXT old_context;
  old_context.ContextFlags = CONTEXT_ALL;
  if (!GetThreadContext(thread_handle.Get(), &old_context)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "GetThreadContext failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }
  CONTEXT new_context = old_context;
#ifdef _M_AMD64
  new_context.Rip = reinterpret_cast<intptr_t>(remote_addr);
  new_context.Rcx = new_context.Rip + code_cave_len;
#else
  new_context.Eip = reinterpret_cast<intptr_t>(remote_addr);
  new_context.Ecx = new_context.Eip + code_cave_len;
#endif
  if (!SetThreadContext(thread_handle.Get(), &new_context)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "SetThreadContext failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }
  if (ResumeThread(thread_handle.Get()) == -1) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "ResumeThread failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }
  if (WaitForSingleObject(
      inject_ready_event.Get(), INFINITE) != WAIT_OBJECT_0) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "WaitForSingleObject failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }
  if (!SetThreadContext(thread_handle.Get(), &old_context)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "SetThreadContext failed, error " << error);
    VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
    return false;
  }

  VirtualFreeEx(process_handle.Get(), remote_addr, 0, MEM_RELEASE);
  return true;
}
