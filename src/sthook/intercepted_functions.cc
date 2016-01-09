// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/intercepted_functions.h"

#include <windows.h>

#include <codecvt>
#include <memory>
#include <string>

#include "base/filesystem_utils.h"
#include "base/string_utils.h"
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
  // Will leak, but it seems to be less evil then strange crashes
  // during ExitProcess in case when some of patched modules already
  // unloaded.
  static sthook::FunctionsInterceptor* g_interceptor;
  if (!g_interceptor)
    g_interceptor = new sthook::FunctionsInterceptor();
  return g_interceptor;
}

void Init(ExecutorIf* executor) {
  boost::filesystem::path current_path = boost::filesystem::current_path();
  std::string current_path_utf8 = current_path.string(
      std::codecvt_utf8_utf16<wchar_t>());
  std::string command_line_utf8 = base::ToUTF8FromWide(GetCommandLine());
  executor->Initialize(
      GetCurrentProcessId(), command_line_utf8, current_path_utf8);
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
    // TODO(vchigrin): Move to DllMain
    Init(g_executor.get());
  }
  return g_executor.get();
}

HANDLE WINAPI NewCreateFileA(
    LPCSTR file_name,
    DWORD desired_access,
    DWORD share_mode,
    LPSECURITY_ATTRIBUTES security_attributes,
    DWORD creation_disposition,
    DWORD flags_and_attributes,
    HANDLE template_file) {
  std::string abs_path_utf8 = base::AbsPathUTF8(
      base::ToLongPathName(std::string(file_name)));
  GetExecutor()->HookedCreateFile(
      abs_path_utf8,
      (desired_access & GENERIC_WRITE) != 0);
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
  std::string abs_path_utf8 = base::AbsPathUTF8(
      base::ToLongPathName(std::wstring(file_name)));
  GetExecutor()->HookedCreateFile(
      abs_path_utf8,
      (desired_access & GENERIC_WRITE) != 0);
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
  GetExecutor()->OnSuspendedProcessCreated(process_information->dwProcessId);
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
  return GetInterceptor()->Hook("kernel32.dll", intercepts, current_module);
}

}  // namespace sthook
