// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/intercepted_functions.h"

#include <windows.h>

#include <codecvt>
#include <memory>
#include <string>

#include "boost/filesystem.hpp"
#include "gen-cpp/Executor.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "sthook/functions_interceptor.h"
#include "sthook/sthook_communication.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TSocket.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

sthook::FunctionsInterceptor* GetInterceptor() {
  static std::unique_ptr<sthook::FunctionsInterceptor> g_interceptor;
  if (!g_interceptor)
    g_interceptor.reset(new sthook::FunctionsInterceptor());
  return g_interceptor.get();
}

ExecutorIf* GetExecutor() {
  using apache::thrift::TException;
  using apache::thrift::protocol::TBinaryProtocol;
  using apache::thrift::transport::TBufferedTransport;
  using apache::thrift::transport::TSocket;

  static std::unique_ptr<ExecutorClient> g_executor;
  if (!g_executor) {
    try {
      boost::shared_ptr<TSocket> socket(new TSocket(
          "localhost", sthook::GetExecutorPort()));
      boost::shared_ptr<TBufferedTransport> transport(
          new TBufferedTransport(socket));
      boost::shared_ptr<TBinaryProtocol> protocol(
          new TBinaryProtocol(transport));
      g_executor.reset(new ExecutorClient(protocol));
      transport->open();
    } catch (TException& ex) {
      LOG4CPLUS_FATAL(logger_, "Thrift initialization failure " << ex.what());
      throw;
    }
  }
  return g_executor.get();
}

std::wstring g_current_module_name;

void InitCurrentModuleName(HMODULE current_module) {
  // Must be enough.
  wchar_t buffer[MAX_PATH + 1];
  DWORD result = GetModuleFileName(current_module, buffer, MAX_PATH + 1);
  if (result == 0 || result > MAX_PATH) {
    LOG4CPLUS_ERROR(
        logger_, "Failed get module file name " << GetLastError());
    return;
  }
  LOG4CPLUS_DEBUG(logger_, "Retrieved dll path  " << buffer);
  g_current_module_name = buffer;
}

std::wstring GetCurrentModuleName() {
  return g_current_module_name;
}

HANDLE WINAPI NewCreateFileA(
    LPCSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file) {
  LOG4CPLUS_DEBUG(logger_, "CreateFileA " << file_name);
  boost::filesystem::path file_path(file_name);
  boost::filesystem::path abs_path = boost::filesystem::absolute(
      file_path);
  std::string abs_path_utf8 = abs_path.string(
      std::codecvt_utf8_utf16<wchar_t>());
  GetExecutor()->HookedCreateFile(
      abs_path_utf8,
      (creation_disposition & GENERIC_WRITE) != 0);
  return CreateFileA(
      file_name,
      desired_access,
      share_mode,
      security_attributes,
      creation_disposition,
      flags_and_attributes,
      template_file);
}

HANDLE WINAPI NewCreateFileW(
    LPCWSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file) {
  LOG4CPLUS_DEBUG(logger_, "CreateFileW " << file_name);
  boost::filesystem::path file_path(file_name);
  boost::filesystem::path abs_path = boost::filesystem::absolute(
      file_path);
  std::string abs_path_utf8 = abs_path.string(
      std::codecvt_utf8_utf16<wchar_t>());
  GetExecutor()->HookedCreateFile(
      abs_path_utf8,
      (creation_disposition & GENERIC_WRITE) != 0);
  return CreateFileW(
      file_name,
      desired_access,
      share_mode,
      security_attributes,
      creation_disposition,
      flags_and_attributes,
      template_file);
}

HMODULE WINAPI NewLoadLibraryA(LPCSTR file_name) {
  HMODULE result = LoadLibraryA(file_name);
  LOG4CPLUS_INFO(logger_, "LoadLubraryA " << file_name);
  if (result) {
    GetInterceptor()->PatchIAT(result);
  }
  return result;
}

HMODULE WINAPI NewLoadLibraryW(LPCWSTR file_name) {
  HMODULE result = LoadLibraryW(file_name);
  LOG4CPLUS_INFO(logger_, "LoadLubraryW " << file_name);
  if (result) {
    GetInterceptor()->PatchIAT(result);
  }
  return result;
}

void InjectDll(HANDLE process_handle) {
  std::wstring current_dll_name = GetCurrentModuleName();
  const size_t buffer_len = (current_dll_name.length() + 1) * sizeof(WCHAR);
  LPVOID remote_addr = VirtualAllocEx(
      process_handle,
      nullptr,
      buffer_len,
      MEM_COMMIT,
      PAGE_READWRITE);
  if (!remote_addr) {
    LOG4CPLUS_ERROR(
        logger_, "Failed allocate remote memory " << GetLastError());
    return;
  }
  SIZE_T bytes_written = 0;
  BOOL result = WriteProcessMemory(
      process_handle,
      remote_addr,
      current_dll_name.c_str(),
      buffer_len,
      &bytes_written);
  if (!result || bytes_written != buffer_len) {
    LOG4CPLUS_ERROR(
        logger_, "WriteProcessMemory failed " << GetLastError());
    VirtualFreeEx(process_handle, remote_addr, 0, MEM_RELEASE);
    return;
  }

  HANDLE thread_handle = CreateRemoteThread(
      process_handle,
      nullptr,
      0,
      reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryW),
      remote_addr,
      0,
      nullptr);
  if (!thread_handle) {
    LOG4CPLUS_ERROR(
        logger_, "Failed create remote thread " << GetLastError());
    VirtualFreeEx(process_handle, remote_addr, 0, MEM_RELEASE);
    return;
  }
  WaitForSingleObject(thread_handle, INFINITE);
  CloseHandle(thread_handle);
  VirtualFreeEx(process_handle, remote_addr, 0, MEM_RELEASE);
}

template<typename CHAR_TYPE, typename STARTUPINFO_TYPE, typename FUNCTION>
BOOL CreateProcessImpl(
    FUNCTION actual_function,
    const CHAR_TYPE* application_name,
    CHAR_TYPE* command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    const CHAR_TYPE* current_directory,
    STARTUPINFO_TYPE* startup_info,
    LPPROCESS_INFORMATION process_information) {
  const CHAR_TYPE* log_info = command_line ? command_line : application_name;
  if (log_info) {
    LOG4CPLUS_INFO(logger_, L"CreateProcess " << log_info);
  }
  bool request_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
  creation_flags |= CREATE_SUSPENDED;
  BOOL result = actual_function(
      application_name,
      command_line,
      process_attributes,
      thread_attributes,
      inherit_handles,
      creation_flags,
      environment,
      current_directory,
      startup_info,
      process_information);
  if (!result)
    return result;
  InjectDll(process_information->hProcess);
  if (!request_suspended)
    ResumeThread(process_information->hThread);
  return result;
}


BOOL WINAPI NewCreateProcessA(
    LPCSTR application_name,
    LPSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCSTR current_directory,
    LPSTARTUPINFOA startup_info,
    LPPROCESS_INFORMATION process_information) {
  return CreateProcessImpl(
      &CreateProcessA,
      application_name,
      command_line,
      process_attributes,
      thread_attributes,
      inherit_handles,
      creation_flags,
      environment,
      current_directory,
      startup_info,
      process_information);
}

BOOL WINAPI NewCreateProcessW(
    LPCWSTR application_name,
    LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCWSTR current_directory,
    LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_information) {
  return CreateProcessImpl(
      &CreateProcessW,
      application_name,
      command_line,
      process_attributes,
      thread_attributes,
      inherit_handles,
      creation_flags,
      environment,
      current_directory,
      startup_info,
      process_information);
}

}  // namespace

namespace sthook {

bool InstallHooks(HMODULE current_module) {
  std::unordered_map<std::string, void*> intercepts;
  intercepts.insert(std::make_pair("CreateFileA", &NewCreateFileA));
  intercepts.insert(std::make_pair("CreateFileW", &NewCreateFileW));
  intercepts.insert(std::make_pair("LoadLibraryA", &NewLoadLibraryA));
  intercepts.insert(std::make_pair("LoadLibraryW", &NewLoadLibraryW));
  intercepts.insert(std::make_pair("CreateProcessA", &NewCreateProcessA));
  intercepts.insert(std::make_pair("CreateProcessW", &NewCreateProcessW));
  InitCurrentModuleName(current_module);
  return GetInterceptor()->Hook("kernel32.dll", intercepts, current_module);
}

}  // namespace sthook

