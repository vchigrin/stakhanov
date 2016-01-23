// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/intercepted_functions.h"

#include <windows.h>

#include <codecvt>
#include <memory>
#include <string>
#include <utility>

#include "base/filesystem_utils.h"
#include "base/string_utils.h"
#include "base/filesystem_utils_win.h"
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

typedef BOOL (WINAPI *LPCREATE_PROCESS_W)(
    LPCWSTR application_name,
    LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCWSTR current_directory,
    LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_information);

typedef BOOL (WINAPI *LPCREATE_PROCESS_A)(
    LPCSTR application_name,
    LPSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCSTR current_directory,
    LPSTARTUPINFOA startup_info,
    LPPROCESS_INFORMATION process_information);

typedef BOOL (WINAPI *LPWRITE_FILE)(
    HANDLE file,
    LPCVOID buffer,
    DWORD number_of_bytes_to_write,
    LPDWORD number_of_bytes_written,
    LPOVERLAPPED overlapped
);

typedef BOOL (WINAPI *LPWRITE_FILE_EX)(
    HANDLE file,
    LPCVOID buffer,
    DWORD number_of_bytes_to_write,
    LPOVERLAPPED overlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE completion_routine
);

typedef BOOL (WINAPI *LPSET_STD_HANDLE)(
    DWORD handle_id,
    HANDLE handle
);

log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

LPCREATE_PROCESS_W g_original_CreateProcessW;
LPCREATE_PROCESS_A g_original_CreateProcessA;
LPWRITE_FILE g_original_WriteFile;
LPWRITE_FILE_EX g_original_WriteFileEx;
LPSET_STD_HANDLE g_original_SetStdHandle;
HANDLE g_stdout;
HANDLE g_stderr;

sthook::FunctionsInterceptor* GetInterceptor() {
  // Will leak, but it seems to be less evil then strange crashes
  // during ExitProcess in case when some of patched modules already
  // unloaded.
  static sthook::FunctionsInterceptor* g_interceptor;
  if (!g_interceptor)
    g_interceptor = new sthook::FunctionsInterceptor();
  return g_interceptor;
}

ExecutorIf* GetExecutor() {
  using apache::thrift::TException;
  using apache::thrift::protocol::TBinaryProtocol;
  using apache::thrift::transport::TBufferedTransport;
  using apache::thrift::transport::TSocket;

  static std::unique_ptr<ExecutorClient> g_executor;
  static bool g_initialize_finished;
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
      g_initialize_finished = true;
    } catch (TException& ex) {
      LOG4CPLUS_FATAL(logger_, "Thrift initialization failure " << ex.what());
      g_executor.reset();
      throw;
    }
  }
  if (!g_initialize_finished)
    return nullptr;
  return g_executor.get();
}


NTSTATUS NTAPI NewNtCreateFile(
    PHANDLE file_handle,
    ACCESS_MASK desired_access,
    POBJECT_ATTRIBUTES object_attributes,
    PIO_STATUS_BLOCK io_status_block,
    PLARGE_INTEGER allocation_size,
    ULONG file_attributes,
    ULONG share_access,
    ULONG create_disposition,
    ULONG create_options,
    PVOID ea_buffer,
    ULONG ea_length) {
  if (object_attributes && object_attributes->ObjectName) {
    ExecutorIf* executor = GetExecutor();
    if (executor) {
      // May be if initialization not finished yet. Although we call
      // Initialize() during DllMain, opening Executor communication
      // internlally causes NtCreateFile call, so avoid recursion.
      std::wstring name_str = base::StringFromAPIString(
          *object_attributes->ObjectName);
      static const wchar_t kPossiblePrefix1[] = L"\\??\\";
      static const wchar_t kPossiblePrefix2[] = L"\\\\?\\";
      if (object_attributes->RootDirectory) {
        std::wstring dir_path = base::GetFilePathFromHandle(
            object_attributes->RootDirectory);
        if (dir_path[dir_path.length() - 1] != L'\\')
          dir_path += L"\\";
        name_str = dir_path + name_str;
      }
      if (name_str.find(kPossiblePrefix1) == 0)
        name_str = name_str.substr(wcslen(kPossiblePrefix1));
      if (name_str.find(kPossiblePrefix2) == 0)
        name_str = name_str.substr(wcslen(kPossiblePrefix2));
      if (name_str[name_str.length() - 1] == L'\\')
        name_str = name_str.substr(0, name_str.length() - 1);
      name_str = base::ToLongPathName(name_str);
      DWORD attributes = ::GetFileAttributesW(name_str.c_str());
      if ((attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        // Don't care about directories.
        std::string abs_path_utf8 = base::ToUTF8FromWide(name_str);
        executor->HookedCreateFile(
            abs_path_utf8,
            (desired_access & GENERIC_WRITE) != 0);
      }
    }
  }
  return NtCreateFile(
      file_handle,
      desired_access,
      object_attributes,
      io_status_block,
      allocation_size,
      file_attributes,
      share_access,
      create_disposition,
      create_options,
      ea_buffer,
      ea_length);
}

extern "C" __kernel_entry NTSTATUS NTAPI LdrLoadDll(
    PWCHAR path_to_file,
    ULONG* flags,
    PUNICODE_STRING module_file_name,
    PHANDLE module_handle);

NTSTATUS NTAPI NewLdrLoadDll(
    PWCHAR path_to_file,
    ULONG* flags,
    PUNICODE_STRING module_file_name,
    PHANDLE module_handle) {
  NTSTATUS result = LdrLoadDll(
      path_to_file,
      flags,
      module_file_name,
      module_handle);
  if (module_handle && *module_handle) {
    GetInterceptor()->NewModuleLoaded(static_cast<HMODULE>(*module_handle));
  }
  return result;
}

std::vector<std::wstring> SplitCommandLineWide(const wchar_t* command_line) {
  // TODO(vchigrin): May be it worth to use some undocumented
  // functions from Visual C++ CRT to avoid dependency from shell32.dll
  int argc = 0;
  WCHAR** argv = CommandLineToArgvW(command_line, &argc);
  if (!argv) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CommandLineToArgv fails, error " << error);
    return std::vector<std::wstring>();
  }
  std::vector<std::wstring> result;
  result.reserve(argc);
  for (int i = 0; i < argc; ++i) {
    result.push_back(argv[i]);
  }
  LocalFree(argv);
  return result;
}

template<typename CHAR_TYPE>
std::vector<std::wstring> SplitCommandLine(
    const CHAR_TYPE* command_line);

std::vector<std::wstring> SplitCommandLine(const wchar_t* command_line) {
  return SplitCommandLineWide(command_line);
}

std::vector<std::wstring> SplitCommandLine(const char* command_line) {
  // TODO(vchigrin): This is terribly inefficient shit-code since uses a LOT
  // of encoding convertions.
  std::wstring command_line_wide = base::ToWideFromANSI(command_line);
  return SplitCommandLineWide(command_line_wide.c_str());
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
  bool request_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
  creation_flags |= CREATE_SUSPENDED;

  std::string exe_path;
  if (application_name) {
    exe_path = base::AbsPathUTF8(
        std::basic_string<CHAR_TYPE>(application_name));
  }
  std::vector<std::string> arguments_utf8;
  if (command_line) {
    std::vector<std::wstring> arguments = SplitCommandLine(command_line);
    for (const std::wstring& argument: arguments) {
      // TODO(vchigrin): Is it OK to convert everything to long path?
      std::wstring native_long_path = base::ToLongPathName(argument);
      arguments_utf8.push_back(base::ToUTF8FromWide(native_long_path));
    }
  }
  if (exe_path.empty() && !arguments_utf8.empty())
    exe_path = arguments_utf8[0];
  std::string startup_dir_utf8;
  if (current_directory) {
    startup_dir_utf8 = base::ToUTF8(
        base::ToLongPathName(std::basic_string<CHAR_TYPE>(current_directory)));
  } else {
    boost::filesystem::path current_dir = boost::filesystem::current_path();
    startup_dir_utf8 = base::ToUTF8FromWide(current_dir.wstring());
  }

  // TODO(vchigrin): Pass environment
  // TODO(vchigrin): Analyze in executor, if we can use cached
  // results of this invokation, create some dummy process driver
  // instead of actual process creation.
  GetExecutor()->OnBeforeProcessCreate(
      exe_path,
      arguments_utf8,
      startup_dir_utf8);

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
      g_original_CreateProcessA,
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
      g_original_CreateProcessW,
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

BOOL WINAPI NewWriteFile(
    HANDLE file,
    LPCVOID buffer,
    DWORD number_of_bytes_to_write,
    LPDWORD number_of_bytes_written,
    LPOVERLAPPED overlapped) {
  if (file == g_stdout || file == g_stderr) {
    std::string data(
        static_cast<const char*>(buffer),
        number_of_bytes_to_write);
    GetExecutor()->PushStdOutput(
        file == g_stdout ? StdHandles::StdOutput : StdHandles::StdError,
        data);
  }
  return g_original_WriteFile(
      file,
      buffer,
      number_of_bytes_to_write,
      number_of_bytes_written,
      overlapped);
}

BOOL WINAPI NewWriteFileEx(
    HANDLE file,
    LPCVOID buffer,
    DWORD number_of_bytes_to_write,
    LPOVERLAPPED overlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
  if (file == g_stdout || file == g_stderr) {
    std::string data(
        static_cast<const char*>(buffer),
        number_of_bytes_to_write);
    GetExecutor()->PushStdOutput(
        file == g_stdout ? StdHandles::StdOutput : StdHandles::StdError,
        data);
  }
  return g_original_WriteFileEx(
      file,
      buffer,
      number_of_bytes_to_write,
      overlapped,
      completion_routine);
}

BOOL WINAPI NewSetStdHandle(
    DWORD handle_id,
    HANDLE handle_val) {
  BOOL result = g_original_SetStdHandle(handle_id, handle_val);
  if (result) {
    if (handle_id == STD_OUTPUT_HANDLE)
      g_stdout = handle_val;
    if (handle_id == STD_ERROR_HANDLE)
      g_stderr = handle_val;
  }
  return result;
}

}  // namespace

namespace sthook {

bool InstallHooks(HMODULE current_module) {
  FunctionsInterceptor::DllInterceptedFunctions ntdll_intercepts;
  // Intercepted either from kernelbase.dll on system that has it or
  // from kernel32.dll on older systems. We must hook kernelbase since some
  // processes link directly with it, skipping kernel32.dll (e.g. cmd.exe).
  FunctionsInterceptor::DllInterceptedFunctions kernel_intercepts;
  ntdll_intercepts.insert(std::make_pair("NtCreateFile", &NewNtCreateFile));
  ntdll_intercepts.insert(std::make_pair("LdrLoadDll", &NewLdrLoadDll));
  kernel_intercepts.insert(
      std::make_pair("CreateProcessA", &NewCreateProcessA));
  kernel_intercepts.insert(
      std::make_pair("CreateProcessW", &NewCreateProcessW));
  kernel_intercepts.insert(
      std::make_pair("WriteFile", &NewWriteFile));
  kernel_intercepts.insert(
      std::make_pair("WriteFileEx", &NewWriteFileEx));
  kernel_intercepts.insert(
      std::make_pair("SetStdHandle", &NewSetStdHandle));
  FunctionsInterceptor::Intercepts intercepts;
  intercepts.insert(
      std::pair<std::string, FunctionsInterceptor::DllInterceptedFunctions>(
          "ntdll.dll", ntdll_intercepts));
  HMODULE kernel_module = GetModuleHandleA("kernelbase.dll");
  if (kernel_module) {
    intercepts.insert(
        std::pair<std::string, FunctionsInterceptor::DllInterceptedFunctions>(
            "kernelbase.dll", kernel_intercepts));
  } else {
    intercepts.insert(
        std::pair<std::string, FunctionsInterceptor::DllInterceptedFunctions>(
            "kernel32.dll", kernel_intercepts));
    kernel_module = GetModuleHandleA("kernel32.dll");
  }
  LOG4CPLUS_ASSERT(logger_, kernel_module);
  g_original_CreateProcessW = reinterpret_cast<LPCREATE_PROCESS_W>(
      GetProcAddress(kernel_module, "CreateProcessW"));
  g_original_CreateProcessA = reinterpret_cast<LPCREATE_PROCESS_A>(
      GetProcAddress(kernel_module, "CreateProcessA"));
  g_original_WriteFile = reinterpret_cast<LPWRITE_FILE>(
      GetProcAddress(kernel_module, "WriteFile"));
  g_original_WriteFileEx = reinterpret_cast<LPWRITE_FILE_EX>(
      GetProcAddress(kernel_module, "WriteFileEx"));
  g_original_SetStdHandle = reinterpret_cast<LPSET_STD_HANDLE>(
      GetProcAddress(kernel_module, "SetStdHandle"));
  LOG4CPLUS_ASSERT(logger_, g_original_CreateProcessW);
  LOG4CPLUS_ASSERT(logger_, g_original_CreateProcessA);
  LOG4CPLUS_ASSERT(logger_, g_original_WriteFile);
  LOG4CPLUS_ASSERT(logger_, g_original_WriteFileEx);
  LOG4CPLUS_ASSERT(logger_, g_original_SetStdHandle);
  return GetInterceptor()->Hook(intercepts, current_module);
}

void Initialize() {
  boost::filesystem::path current_path = boost::filesystem::current_path();
  std::string current_path_utf8 = current_path.string(
      std::codecvt_utf8_utf16<wchar_t>());
  std::string command_line_utf8 = base::ToUTF8FromWide(GetCommandLine());
  GetExecutor()->Initialize(
      GetCurrentProcessId(), command_line_utf8, current_path_utf8);
  g_stdout = GetStdHandle(STD_OUTPUT_HANDLE);
  g_stderr = GetStdHandle(STD_ERROR_HANDLE);
  LOG4CPLUS_ASSERT(logger_, g_stdout);
  LOG4CPLUS_ASSERT(logger_, g_stderr);
}

}  // namespace sthook
