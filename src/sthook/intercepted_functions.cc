// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/intercepted_functions.h"

#include <algorithm>
#include <shellapi.h>
#include <versionhelpers.h>
#include <windows.h>

#include <codecvt>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "base/timed_block.h"
#include "base/filesystem_utils.h"
#include "base/scoped_handle.h"
#include "base/string_utils.h"
#include "base/filesystem_utils_win.h"
#include "boost/filesystem.hpp"
#include "gen-cpp/Executor.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "sthook/functions_interceptor.h"
#include "sthook/intercept_helper.h"
#include "sthook/sthook_communication.h"
#include "sthook/std_handles_holder.h"
#include "sthook/process_proxy_manager.h"
#include "third_party/cryptopp/md5.h"
#include "thrift/protocol/TBinaryProtocol.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TPipe.h"

namespace {

const wchar_t kStLaunchExeName[] = L"stlaunch.exe";

std::mutex g_executor_call_mutex;
int32_t g_main_executor_command_id;
bool g_should_buffer_std_streams = false;
bool g_should_ignore_output_files = false;
std::string g_std_output_buffer;
std::string g_std_error_buffer;

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

typedef BOOL (WINAPI *LPGET_EXIT_CODE_PROCESS)(
    HANDLE process_handle,
    LPDWORD exit_code);

typedef struct _FILE_RENAME_INFORMATION {
  BOOLEAN ReplaceIfExists;
  HANDLE  RootDirectory;
  ULONG   FileNameLength;
  WCHAR   FileName[1];
} FILE_RENAME_INFORMATION, *PFILE_RENAME_INFORMATION;

typedef NTSTATUS (NTAPI *LPNTSET_INFORMATION_FILE)(
    HANDLE file_handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    int file_information_class
);

static const int FileRenameInformation = 10;

#define FOR_EACH_INTERCEPTS(DO_IT) \
    DO_IT(CloseHandle, nullptr, &AfterCloseHandle, BOOL, HANDLE) \
    DO_IT(ExitProcess, &BeforeExitProcess, nullptr, VOID, UINT) \
    DO_IT(TerminateProcess, &BeforeTerminateProcess, nullptr, VOID, \
          HANDLE, UINT) \
    DO_IT(WriteFile, &BeforeWriteFile, nullptr, BOOL, \
          HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) \
    DO_IT(WriteFileEx, &BeforeWriteFileEx, nullptr, BOOL, \
          HANDLE, LPCVOID, DWORD, LPOVERLAPPED, \
          LPOVERLAPPED_COMPLETION_ROUTINE) \
    DO_IT(DuplicateHandle, nullptr, &AfterDuplicateHandle, BOOL, \
          HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD) \
    DO_IT(DeleteFileA, nullptr, &AfterDeleteFileA, BOOL, LPCSTR) \
    DO_IT(DeleteFileW, nullptr, &AfterDeleteFileW, BOOL, LPCWSTR)


log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

LPGET_EXIT_CODE_PROCESS g_original_GetExitCodeProcess;
LPNTSET_INFORMATION_FILE g_original_NtSetInformationFile;
LPCREATE_PROCESS_W g_original_CreateProcessW;


std::wstring LongPathNameFromRootDirAndString(
      HANDLE root_directory, const std::wstring& name) {
  static const wchar_t kPossiblePrefix1[] = L"\\??\\";
  static const wchar_t kPossiblePrefix2[] = L"\\\\?\\";
  std::wstring result;
  if (root_directory) {
    std::wstring dir_path = base::GetFilePathFromHandle(
        root_directory);
    if (dir_path[dir_path.length() - 1] != L'\\')
      dir_path += L"\\";
    result = dir_path + name;
  } else {
    result = name;
  }
  if (result.find(kPossiblePrefix1) == 0)
    result = result.substr(wcslen(kPossiblePrefix1));
  if (result.find(kPossiblePrefix2) == 0)
    result = result.substr(wcslen(kPossiblePrefix2));
  if (result[result.length() - 1] == L'\\')
    result = result.substr(0, result.length() - 1);
  return base::ToLongPathName(result);
}

sthook::FunctionsInterceptor* GetInterceptor() {
  // Will leak, but it seems to be less evil then strange crashes
  // during ExitProcess in case when some of patched modules already
  // unloaded.
  static sthook::FunctionsInterceptor* g_interceptor;
  if (!g_interceptor)
    g_interceptor = new sthook::FunctionsInterceptor();
  return g_interceptor;
}

std::unique_ptr<ExecutorClient> CreateInitializedExecutor(bool is_main) {
  using apache::thrift::TException;
  using apache::thrift::protocol::TBinaryProtocol;
  using apache::thrift::transport::TBufferedTransport;
  using apache::thrift::transport::TPipe;

  std::unique_ptr<ExecutorClient> result_client;
  boost::shared_ptr<TPipe> socket(new TPipe(sthook::kExecutorPipeName));
  boost::shared_ptr<TBufferedTransport> transport(
      new TBufferedTransport(socket));
  boost::shared_ptr<TBinaryProtocol> protocol(
      new TBinaryProtocol(transport));
  result_client.reset(new ExecutorClient(protocol));
  transport->open();
  if (is_main) {
    boost::filesystem::path current_exe = base::GetCurrentExecutablePath();
    const bool is_st_launch = (current_exe.filename() == kStLaunchExeName);
    g_main_executor_command_id = result_client->InitializeMainExecutor(
        GetCurrentProcessId(),
        is_st_launch);
  } else {
    result_client->InitializeHelperExecutor(
        g_main_executor_command_id);
  }
  return result_client;
}

ExecutorIf* GetExecutor() {
  static std::unique_ptr<ExecutorClient> g_executor;
  static bool inside_initialize;
  if (!g_executor) {
    if (inside_initialize)
      return nullptr;  // Avoid infinite recursion from hooked CreateFile
    inside_initialize = true;
    try {
      g_executor = CreateInitializedExecutor(true);
      inside_initialize = false;
    } catch (std::exception& ex) {
      inside_initialize = false;
      LOG4CPLUS_FATAL(logger_, "Thrift initialization failure " << ex.what());
      throw;
    }
  }
  return g_executor.get();
}

ExecutorIf* GetExecutorForCurrentThread() {
  static thread_local std::unique_ptr<ExecutorClient> executor;
  if (!executor)
    executor = CreateInitializedExecutor(false);
  return executor.get();
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
  // HACK: Always add "FILE_SHARE_READ" to allow stexecutor
  // read file before process exit. If it ever breaks something, we'll have
  // to save handles of all files and manually close them in
  // OnBeforeExitProcess.
  share_access |= FILE_SHARE_READ;
  NTSTATUS result = NtCreateFile(
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
  if (!NT_SUCCESS(result))
     return result;
  if (create_options & FILE_DELETE_ON_CLOSE)
     return result;  // Do not process temporary files.
  const bool for_writing = (desired_access & GENERIC_WRITE) != 0;
  if (for_writing && g_should_ignore_output_files)
    return result;
  if (object_attributes && object_attributes->ObjectName) {
    ExecutorIf* executor = GetExecutor();
    if (executor) {
      // Executor may be nullptr if initialization not finished yet.
      // Although we call Initialize() during DllMain, opening Executor
      // communication internlally causes NtCreateFile call, so avoid recursion.
      std::wstring name_str = LongPathNameFromRootDirAndString(
          object_attributes->RootDirectory,
          base::StringFromAPIString(*object_attributes->ObjectName));

      DWORD attributes = ::GetFileAttributesW(name_str.c_str());
      // It is OK for attributes to be invalid, for newly created file.
      if (attributes == INVALID_FILE_ATTRIBUTES ||
          (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
        // Don't care about directories.
        std::string abs_path_utf8 = base::ToUTF8FromWide(name_str);
        {
          std::lock_guard<std::mutex> lock(g_executor_call_mutex);
          executor->HookedCreateFile(
              abs_path_utf8,
              for_writing);
        }
      }
    }
  }
  return result;
}

NTSTATUS NTAPI NewNtSetInformationFile(
    HANDLE file_handle,
    PIO_STATUS_BLOCK io_status_block,
    PVOID file_information,
    ULONG length,
    int file_information_class) {
  if (file_information_class != FileRenameInformation) {
    return g_original_NtSetInformationFile(
        file_handle,
        io_status_block,
        file_information,
        length,
        file_information_class);
  }
  std::wstring old_name_str = base::GetFilePathFromHandle(file_handle);
  NTSTATUS result = g_original_NtSetInformationFile(
      file_handle,
      io_status_block,
      file_information,
      length,
      file_information_class);
  if (!NT_SUCCESS(result) || file_information_class != FileRenameInformation)
    return result;
  ExecutorIf* executor = GetExecutor();
  if (!executor)
    return result;
  const FILE_RENAME_INFORMATION* rename_info =
      reinterpret_cast<const FILE_RENAME_INFORMATION*>(file_information);
  std::wstring new_name_str = LongPathNameFromRootDirAndString(
      rename_info->RootDirectory,
      std::wstring(
          rename_info->FileName,
          rename_info->FileNameLength / sizeof(WCHAR)));
  {
    std::lock_guard<std::mutex> lock(g_executor_call_mutex);
    executor->HookedRenameFile(
        base::ToUTF8FromWide(old_name_str),
        base::ToUTF8FromWide(new_name_str));
  }
  return result;
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

std::vector<std::wstring> SplitCommandLine(const wchar_t* command_line) {
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
size_t EnvBlockCharLength(const CHAR_TYPE* env_block) {
  const CHAR_TYPE* p = env_block;
  while (*p) {
    p += (base::StringCharLen(p) + 1);
  }
  return p - env_block;
}

std::string ComputeEnvironmentHash(void* may_be_arg_environ, bool is_unicode) {
  static thread_local std::vector<wchar_t> last_seen_env_block;
  static thread_local std::string last_hash;
  std::vector<std::wstring> strings;
  std::vector<wchar_t> current_env_block;
  if (may_be_arg_environ) {
    if (is_unicode) {
      const wchar_t* p = static_cast<const wchar_t*>(may_be_arg_environ);
      while (*p) {
        strings.emplace_back(p);
        p += (wcslen(p) + 1);
      }
    } else {
      const char* p = static_cast<const char*>(may_be_arg_environ);
      while (*p) {
        strings.emplace_back(base::ToWideFromANSI(p));
        p += (strlen(p) + 1);
      }
    }
  } else {
    const wchar_t* env_block = GetEnvironmentStringsW();
    if (!env_block) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(
          logger_, "GetEnvironmentStringsW failed, error " << error);
      return std::string();
    }
    size_t len = EnvBlockCharLength(env_block);
    current_env_block = std::vector<wchar_t>(env_block, env_block + len);
    if (current_env_block.size() == last_seen_env_block.size() &&
      std::equal(
          current_env_block.begin(),
          current_env_block.end(),
          last_seen_env_block.begin())) {
      return last_hash;
    }

    const wchar_t* p = env_block;
    while (*p) {
      strings.emplace_back(p);
      p += (wcslen(p) + 1);
    }
  }

  std::sort(strings.begin(), strings.end());
  CryptoPP::Weak::MD5 hasher;
  for (const std::wstring& str : strings) {
    // Windows has some "special" env variables like
    // "=ExitCode", "=C:", etc., that greatly vary, preventing caching.
    // Hope programs will not use them and skip them. Return in case
    // any problems.
    if (str.empty() || str[0] == L'=')
      continue;
    // Some helper variables, set by TeamCity. They may vary from build
    // to build.
    // TODO(vchigrin): Move env. vars exclusion rules to config file.
    if (str.find(L"BUILD_") == 0 || str.find(L"TEAMCITY_") == 0)
      continue;
    hasher.Update(
        reinterpret_cast<const uint8_t*>(str.data()),
        str.length() * sizeof(wchar_t));
  }
  std::vector<uint8_t> digest(hasher.DigestSize());
  hasher.Final(&digest[0]);
  std::string result = base::BytesToHexString(digest);
  if (!may_be_arg_environ) {
    // Cache only current thread env. blocks.
    last_seen_env_block = std::move(current_env_block);
    last_hash = result;
  }
  return result;
}

bool ShouldAppendStdStreams(DWORD startup_info_flags) {
  bool append_std_streams = (
      startup_info_flags & STARTF_USESTDHANDLES) == 0;
  StdHandlesHolder* instance = StdHandlesHolder::GetInstance();
  if (instance) {
    StdHandles::type handle_type = StdHandles::StdOutput;
    // Child process will use same handles for stdout/stderr as currently
    // set by SetStdHandle. So check, if these handles relate to original
    // stdout/stderr of current process or not.
    append_std_streams &= instance->IsStdHandle(
        GetStdHandle(STD_OUTPUT_HANDLE), &handle_type);
    append_std_streams &= instance->IsStdHandle(
        GetStdHandle(STD_ERROR_HANDLE), &handle_type);
  }
  return append_std_streams;
}

class CreateProcessInvoker {
 public:
  CreateProcessInvoker(
    const WCHAR* application_name,
    const WCHAR* command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    const WCHAR* current_directory,
    STARTUPINFOW* startup_info)
      : application_name_(CopyStringIfNeed(application_name)),
        command_line_(CopyStringIfNeed(command_line)),
        process_attributes_(CopyStructIfNeed(process_attributes)),
        thread_attributes_(CopyStructIfNeed(thread_attributes)),
        inherit_handles_(inherit_handles),
        creation_flags_(creation_flags),
        utf8_strings_filled_(false) {
    if (environment) {
      size_t env_block_byte_size;
      if (creation_flags & CREATE_UNICODE_ENVIRONMENT) {
        env_block_byte_size = (EnvBlockCharLength(
            static_cast<const wchar_t*>(environment)) + 1) * sizeof(wchar_t);
      } else {
        env_block_byte_size = EnvBlockCharLength(
            static_cast<const char*>(environment)) + 1;
      }
      environment_.reset(new uint8_t[env_block_byte_size]);
      memcpy(environment_.get(), environment, env_block_byte_size);
    }
    if (current_directory) {
      current_directory_ = CopyStringIfNeed(current_directory);
    } else {
      // Grab directory now, since in case deffered execution
      // process may already change directory after CreateProcess invokation.
      boost::filesystem::path current_dir = boost::filesystem::current_path();
      current_directory_ = CopyStringIfNeed(current_dir.wstring().c_str());
    }

    environment_hash_ = ComputeEnvironmentHash(
        environment, creation_flags & CREATE_UNICODE_ENVIRONMENT);
    // NOTE, startup_info pointer may be greater then sizeof(STARTUPINFO)
    // it may be STARTUPINFOEX, so use byte count pointer to avoid slicing.
    startup_info_buffer_.reset(new uint8_t[startup_info->cb]);
    memcpy(startup_info_buffer_.get(), startup_info, startup_info->cb);
  }

  ~CreateProcessInvoker() {
    if (attr_list_buffer_) {
      DeleteProcThreadAttributeList(
          reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(
              attr_list_buffer_.get()));
    }
  }

  BOOL InvokeActualFunction(PROCESS_INFORMATION* process_information) {
    BOOL result = g_original_CreateProcessW(
        application_name_.get(),
        command_line_.get(),
        process_attributes_.get(),
        thread_attributes_.get(),
        inherit_handles_,
        creation_flags_,
        environment_.get(),
        current_directory_.get(),
        startup_info(),
        process_information);
    if (!result) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "CreateProcess failed error " << error);
    }
    return result;
  }

  const std::string& environment_hash() const {
    return environment_hash_;
  }

  bool IsStdStreamsUsed() const {
    return startup_info()->dwFlags & STARTF_USESTDHANDLES;
  }

  bool CanBeDeferred() const {
    // We can not defer execution calls that use STARTUPINFOEX, since
    // WinAPI does not provode wayt to quesy ProcThreadAttributeList structure,
    // but we need this to update inheritable handle list.
    // Moreover, we will encounter lifetime issues since
    // ProcThreadAttributeList contain pointers to memory that is managed by
    // client process.
    return startup_info()->cb == sizeof(STARTUPINFOW);
  }

  bool PrepareForDeferredExecution(
      HANDLE stdinput_handle,
      HANDLE stdout_handle, HANDLE stderr_handle) {
    // We must disable handle inheritance to avoid accidental catching
    // handles to files, created by other threads (thus preventing
    // deletion of these files). But we do need inherit handles for
    // stdout, stderr, etc. So use new feature of selectable handles
    // inheritance.
    std::unique_ptr<uint8_t[]> new_startup_info_buffer(
        new uint8_t[sizeof(STARTUPINFOEXW)]);
    memcpy(new_startup_info_buffer.get(),
           startup_info_buffer_.get(),
           startup_info()->cb);
    STARTUPINFOEXW* new_startupinfo =
        reinterpret_cast<STARTUPINFOEXW*>(new_startup_info_buffer.get());
    new_startupinfo->StartupInfo.cb = sizeof(STARTUPINFOEXW);
    SIZE_T attr_list_size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attr_list_size);
    if (!attr_list_size) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(
          logger_,
          "InitializeProcThreadAttributeList 1 failed error " << error);
      return false;
    }
    attr_list_buffer_.reset(new uint8_t[attr_list_size]);
    new_startupinfo->lpAttributeList =
        reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(attr_list_buffer_.get());
    if (!InitializeProcThreadAttributeList(
        new_startupinfo->lpAttributeList, 1, 0, &attr_list_size)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(
          logger_,
          "InitializeProcThreadAttributeList 2 failed error " << error);
      return false;
    }
    inherited_handles_.clear();
    if (stdinput_handle)
      inherited_handles_.push_back(stdinput_handle);
    if (stdout_handle)
      inherited_handles_.push_back(stdout_handle);
    if (stderr_handle)
      inherited_handles_.push_back(stderr_handle);
    if (!UpdateProcThreadAttribute(
        new_startupinfo->lpAttributeList,
        0,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        inherited_handles_.data(),
        inherited_handles_.size() * sizeof(HANDLE),
        NULL,
        NULL)) {
      LOG4CPLUS_ERROR(logger_, "UpdateProcThreadAttribute failed");
      return false;
    }
    startup_info_buffer_ = std::move(new_startup_info_buffer);
    creation_flags_ |= EXTENDED_STARTUPINFO_PRESENT;
    startup_info()->hStdInput = stdinput_handle;
    startup_info()->hStdOutput = stdout_handle;
    startup_info()->hStdError = stderr_handle;
    return true;
  }

  const std::string& startup_dir_utf8() {
    FillUTF8StringsIfNeed();
    return startup_dir_utf8_;
  }

  const std::string& exe_path_utf8() {
    FillUTF8StringsIfNeed();
    return exe_path_utf8_;
  }

  const std::vector<std::string>& arguments_utf8() {
    FillUTF8StringsIfNeed();
    return arguments_utf8_;
  }

 private:
  void FillUTF8StringsIfNeed() {
    if (utf8_strings_filled_)
      return;
    if (application_name_) {
      exe_path_utf8_ = base::ToUTF8FromWide(application_name_.get());
    }
    if (command_line_) {
      std::vector<std::wstring> arguments = SplitCommandLine(
          command_line_.get());
      for (const std::wstring& argument : arguments) {
        arguments_utf8_.push_back(base::ToUTF8FromWide(argument));
      }
      if (exe_path_utf8_.empty() && !arguments_utf8_.empty())
        exe_path_utf8_ = arguments_utf8_[0];
    }
    startup_dir_utf8_ = base::ToUTF8FromWide(
        base::ToLongPathName(std::wstring(current_directory_.get())));
    utf8_strings_filled_ = true;
  }

  static std::unique_ptr<WCHAR[]> CopyStringIfNeed(const WCHAR* str) {
    if (!str)
      return nullptr;
    size_t len = base::StringCharLen(str);
    ++len;  // For zero terminator.
    std::unique_ptr<WCHAR[]> result(new WCHAR[len]);
    memcpy(result.get(), str, len * sizeof(WCHAR));
    return result;
  }

  template<typename T>
  static std::unique_ptr<T> CopyStructIfNeed(const T* ptr) {
    if (!ptr)
      return nullptr;
    std::unique_ptr<T> result(new T);
    *result = *ptr;
    return result;
  }

  STARTUPINFOW* startup_info() {
    return reinterpret_cast<STARTUPINFOW*>(startup_info_buffer_.get());
  }

  const STARTUPINFOW* startup_info() const {
    return reinterpret_cast<const STARTUPINFOW*>(
        startup_info_buffer_.get());
  }

  std::unique_ptr<WCHAR[]> application_name_;
  std::unique_ptr<WCHAR[]> command_line_;
  std::unique_ptr<SECURITY_ATTRIBUTES> process_attributes_;
  std::unique_ptr<SECURITY_ATTRIBUTES> thread_attributes_;
  BOOL inherit_handles_;
  DWORD creation_flags_;
  std::unique_ptr<uint8_t[]> environment_;
  std::string environment_hash_;
  std::unique_ptr<WCHAR[]> current_directory_;
  std::unique_ptr<uint8_t[]> startup_info_buffer_;
  std::unique_ptr<uint8_t[]> attr_list_buffer_;
  std::vector<HANDLE> inherited_handles_;
  bool utf8_strings_filled_;
  std::string startup_dir_utf8_;
  std::string exe_path_utf8_;
  std::vector<std::string> arguments_utf8_;
};

struct CreateProcessThreadPoolProcCtx {
  std::unique_ptr<CreateProcessInvoker> invoker;
  bool append_std_streams;
  bool request_suspended;
  void* hoax_proxy_id;
};

DWORD WINAPI CreateProcessThreadPoolProc(VOID* ctx_ptr) {
  std::unique_ptr<CreateProcessThreadPoolProcCtx> ctx(
      static_cast<CreateProcessThreadPoolProcCtx*>(ctx_ptr));
  ExecutorIf* executor = GetExecutorForCurrentThread();

  CacheHitInfo cache_hit_info;
  CreateProcessInvoker* invoker = ctx->invoker.get();
  executor->OnBeforeProcessCreate(
      cache_hit_info,
      invoker->exe_path_utf8(),
      invoker->arguments_utf8(),
      invoker->startup_dir_utf8(),
      invoker->environment_hash());
  if (cache_hit_info.cache_hit) {
    ProcessProxyManager::GetInstance()->SyncFinishHoaxProxy(
        ctx->hoax_proxy_id,
        cache_hit_info);
    return 0;
  }
  PROCESS_INFORMATION process_information;
  base::ScopedHandle read_stdout_pipe;
  base::ScopedHandle read_stderr_pipe;
  base::ScopedHandle write_stdout_pipe;
  base::ScopedHandle write_stderr_pipe;
  if (invoker->IsStdStreamsUsed()) {
    SECURITY_ATTRIBUTES security_attributes;
    memset(&security_attributes, 0, sizeof(security_attributes));
    security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    security_attributes.bInheritHandle = TRUE;

    if (!CreatePipe(
        read_stdout_pipe.Receive(),
        write_stdout_pipe.Receive(),
        &security_attributes,
        0)) {
      DWORD error = GetLastError();
      LOG4CPLUS_FATAL(logger_, "CreatePipe fails, error " << error);
      return 0;
    }
    if (!CreatePipe(
        read_stderr_pipe.Receive(),
        write_stderr_pipe.Receive(),
        &security_attributes,
        0)) {
      DWORD error = GetLastError();
      LOG4CPLUS_FATAL(logger_, "CreatePipe fails, error " << error);
      return 0;
    }
    invoker->PrepareForDeferredExecution(
        NULL,
        write_stdout_pipe.Get(),
        write_stderr_pipe.Get());
  }
  if (!invoker->InvokeActualFunction(&process_information))
    return 0;
  executor->OnSuspendedProcessCreated(
      process_information.dwProcessId,
      process_information.dwThreadId,
      cache_hit_info.executor_command_id,
      ctx->append_std_streams,
      ctx->request_suspended);
  write_stdout_pipe.Close();
  write_stderr_pipe.Close();
  ProcessProxyManager::GetInstance()->SyncDriveRealProcess(
      ctx->hoax_proxy_id,
      process_information.hProcess,
      read_stdout_pipe,
      read_stderr_pipe);
  if (!CloseHandle(process_information.hThread)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed close thread handle error " << error);
  }
  if (!CloseHandle(process_information.hProcess)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed close process handle error " << error);
  }
  return 0;
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
  const bool append_std_streams = ShouldAppendStdStreams(
      startup_info->dwFlags);
  std::unique_ptr<CreateProcessInvoker> actual_function_invoker(
      new CreateProcessInvoker(
          application_name,
          command_line,
          process_attributes,
          thread_attributes,
          inherit_handles,
          creation_flags | CREATE_SUSPENDED,  // Create suspended to inject dll
          environment,
          current_directory,
          startup_info));

  ProcessProxyManager* proxy_manager = ProcessProxyManager::GetInstance();
  const bool request_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
  if (proxy_manager->is_safe_to_use_hoax_proxy() &&
      actual_function_invoker->CanBeDeferred()) {
    void* hoax_proxy_id = proxy_manager->PrepareHoaxProxy(
        startup_info->hStdOutput,
        startup_info->hStdError,
        process_information);
    if (!hoax_proxy_id) {
      LOG4CPLUS_ERROR(logger_, "Failed create hoax proxy");
      return FALSE;
    }

    CreateProcessThreadPoolProcCtx* ctx = new CreateProcessThreadPoolProcCtx;
    ctx->invoker = std::move(actual_function_invoker);
    ctx->hoax_proxy_id = hoax_proxy_id;
    ctx->append_std_streams = append_std_streams;
    ctx->request_suspended = request_suspended;
    if (!QueueUserWorkItem(
        CreateProcessThreadPoolProc,
        ctx,
        WT_EXECUTEDEFAULT)) {
      DWORD error = GetLastError();
      LOG4CPLUS_FATAL(
          logger_, "QueueUserWorkItem fails, error " << error);
      return FALSE;
    }
    return TRUE;
  }

  CacheHitInfo cache_hit_info;
  {
    std::lock_guard<std::mutex> lock(g_executor_call_mutex);
    GetExecutor()->OnBeforeProcessCreate(
        cache_hit_info,
        actual_function_invoker->exe_path_utf8(),
        actual_function_invoker->arguments_utf8(),
        actual_function_invoker->startup_dir_utf8(),
        actual_function_invoker->environment_hash());
  }
  if (cache_hit_info.cache_hit) {
    // Cache hits should not go through all pipeline with
    // injecting interceptor DLLs, tracking files, etc.
    return ProcessProxyManager::GetInstance()->CreateProxyProcess(
        cache_hit_info,
        creation_flags,
        startup_info->hStdInput,
        startup_info->hStdOutput,
        startup_info->hStdError,
        process_information);
  }
  if (!actual_function_invoker->InvokeActualFunction(process_information))
    return FALSE;

  {
    std::lock_guard<std::mutex> lock(g_executor_call_mutex);
    GetExecutor()->OnSuspendedProcessCreated(
        process_information->dwProcessId,
        process_information->dwThreadId,
        cache_hit_info.executor_command_id,
        append_std_streams,
        request_suspended);
  }
  return TRUE;
}

// Helper class for converting from ANSI to wide characters of hooked
// CreateProcessA.
class ToWideConvertWithBuffer {
 public:
  explicit ToWideConvertWithBuffer(const char* ansi_string) {
    if (ansi_string) {
      std::wstring wide_string = base::ToWideFromANSI(ansi_string);
      buffer_.reset(new wchar_t[wide_string.length() + 1]);
      std::copy(wide_string.begin(), wide_string.end(), &buffer_[0]);
      buffer_[wide_string.length()] = L'\0';
    }
  }

  wchar_t* wide_buffer() {
    // Non-const buffer since command_line parameter of CreateProcess
    // requires non-const buffer.
    return buffer_.get();
  }
 private:
  std::unique_ptr<wchar_t[]> buffer_;
};

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
  ToWideConvertWithBuffer application_name_wide(application_name);
  ToWideConvertWithBuffer command_line_wide(command_line);
  ToWideConvertWithBuffer current_directory_wide(current_directory);
  STARTUPINFOEXW startup_info_wide;
  memset(&startup_info_wide, 0, sizeof(startup_info_wide));
  if (startup_info->cb == sizeof(STARTUPINFOA)) {
    startup_info_wide.StartupInfo.cb = sizeof(STARTUPINFOW);
  } else if (startup_info->cb == sizeof(STARTUPINFOEXA)) {
    startup_info_wide.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    startup_info_wide.lpAttributeList =
        reinterpret_cast<const STARTUPINFOEXA*>(startup_info)->lpAttributeList;
  } else {
    LOG4CPLUS_FATAL(
        logger_, "Unexpected size of STARTUPINFO " << startup_info->cb);
    return FALSE;
  }
  ToWideConvertWithBuffer reserved_wide(startup_info->lpReserved);
  ToWideConvertWithBuffer desktop_wide(startup_info->lpDesktop);
  ToWideConvertWithBuffer title_wide(startup_info->lpTitle);


  startup_info_wide.StartupInfo.lpReserved = reserved_wide.wide_buffer();
  startup_info_wide.StartupInfo.lpDesktop = desktop_wide.wide_buffer();
  startup_info_wide.StartupInfo.lpTitle = title_wide.wide_buffer();
  startup_info_wide.StartupInfo.dwX = startup_info->dwX;
  startup_info_wide.StartupInfo.dwY = startup_info->dwY;
  startup_info_wide.StartupInfo.dwXSize = startup_info->dwXSize;
  startup_info_wide.StartupInfo.dwYSize = startup_info->dwYSize;
  startup_info_wide.StartupInfo.dwXCountChars = startup_info->dwXCountChars;
  startup_info_wide.StartupInfo.dwYCountChars = startup_info->dwYCountChars;
  startup_info_wide.StartupInfo.dwFillAttribute =
      startup_info->dwFillAttribute;
  startup_info_wide.StartupInfo.dwFlags = startup_info->dwFlags;
  startup_info_wide.StartupInfo.wShowWindow = startup_info->wShowWindow;
  startup_info_wide.StartupInfo.cbReserved2 = startup_info->cbReserved2;
  startup_info_wide.StartupInfo.lpReserved2 = startup_info->lpReserved2;
  startup_info_wide.StartupInfo.hStdInput = startup_info->hStdInput;
  startup_info_wide.StartupInfo.hStdOutput = startup_info->hStdOutput;
  startup_info_wide.StartupInfo.hStdError = startup_info->hStdError;


  return NewCreateProcessW(
      application_name_wide.wide_buffer(),
      command_line_wide.wide_buffer(),
      process_attributes,
      thread_attributes,
      inherit_handles,
      creation_flags,
      environment,
      current_directory_wide.wide_buffer(),
      &startup_info_wide.StartupInfo,
      process_information);
}

FARPROC WINAPI NewGetProcAddress(HMODULE module, LPCSTR proc_name) {
  void* result = GetProcAddress(module, proc_name);
  void* replacement = GetInterceptor()->GetReplacement(result);
  return static_cast<FARPROC>(replacement ? replacement : result);
}

BOOL WINAPI NewGetExitCodeProcess(
    HANDLE process_handle,
    LPDWORD exit_code) {
  auto* process_proxy_manager = ProcessProxyManager::GetInstance();
  if (process_proxy_manager) {
    if (process_proxy_manager->TryGetExitCodeProcess(
        process_handle, exit_code)) {
      return TRUE;
    }
  }
  return g_original_GetExitCodeProcess(process_handle, exit_code);
}

void BeforeWriteFile(
    HANDLE file,
    LPCVOID buffer,
    DWORD number_of_bytes_to_write,
    LPDWORD number_of_bytes_written,
    LPOVERLAPPED overlapped) {
  StdHandles::type handle_type = StdHandles::StdOutput;
  StdHandlesHolder* instance = StdHandlesHolder::GetInstance();
  if (instance && instance->IsStdHandle(file, &handle_type)) {
    std::string data(
        static_cast<const char*>(buffer),
        number_of_bytes_to_write);
    if (g_should_buffer_std_streams) {
      if (handle_type == StdHandles::StdOutput)
        g_std_output_buffer += data;
      else
        g_std_error_buffer += data;
    } else {
      std::lock_guard<std::mutex> lock(g_executor_call_mutex);
      GetExecutor()->PushStdOutput(handle_type, data);
    }
  }
}

void BeforeWriteFileEx(
    HANDLE file,
    LPCVOID buffer,
    DWORD number_of_bytes_to_write,
    LPOVERLAPPED overlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE completion_routine) {
  StdHandles::type handle_type = StdHandles::StdOutput;
  StdHandlesHolder* instance = StdHandlesHolder::GetInstance();
  if (instance && instance->IsStdHandle(file, &handle_type)) {
    std::string data(
        static_cast<const char*>(buffer),
        number_of_bytes_to_write);
    if (g_should_buffer_std_streams) {
      if (handle_type == StdHandles::StdOutput)
        g_std_output_buffer += data;
      else
        g_std_error_buffer += data;
    } else {
      std::lock_guard<std::mutex> lock(g_executor_call_mutex);
      GetExecutor()->PushStdOutput(handle_type, data);
    }
  }
}

void AfterDuplicateHandle(
    BOOL result,
    HANDLE source_process_handle,
    HANDLE source_handle,
    HANDLE target_process_handle,
    LPHANDLE target_handle,
    DWORD desired_access,
    BOOL inherit_handle,
    DWORD options) {
  if (!result)
    return;
  const HANDLE current_process = GetCurrentProcess();
  StdHandlesHolder* instance = StdHandlesHolder::GetInstance();
  if (source_process_handle == current_process &&
     target_process_handle == current_process &&
     instance) {
    instance->MarkDuplicatedHandle(source_handle, *target_handle);
    if (options & DUPLICATE_CLOSE_SOURCE)
      instance->MarkHandleClosed(source_handle);
  }
}

void AfterCloseHandle(BOOL result, HANDLE handle) {
  if (!result)
    return;
  StdHandlesHolder* handles_holder = StdHandlesHolder::GetInstance();
  if (handles_holder)
    handles_holder->MarkHandleClosed(handle);
  auto* process_proxy_manager = ProcessProxyManager::GetInstance();
  if (process_proxy_manager)
    process_proxy_manager->NotifyHandleClosed(handle);
}

void FlushUCRTIfPossible() {
  // HACK: Manually flush CRT buffers where possible.
  // We experience problems with some programs, like re2c.exe, that
  // buffer some output, and ucrt flush it only during
  // DllMain(DLL_PROCESS_DETACH) call. Without manual flushing stexecutor
  // caches not fully written files.
  // Current approach with manual flush fixes *SOME* problems. Since
  // theoretically there might be other modules buffering output till
  // DllMain call. Proper solution is to find a way to directly hook
  // ZwTerminateProcess in ntdll.dll and notify executor from there, when
  // all DllMain calls done. We can not do that hook through IAT since
  // source of that call is ntdll...
  // TODO(vchigrin): Find some generic solution.
  HMODULE ucrt_dll = GetModuleHandleW(L"ucrtbase.dll");
  if (!ucrt_dll)
    return;
  typedef int (*FCLOSEAPP_PTR)();
  FCLOSEAPP_PTR fclose_all = reinterpret_cast<FCLOSEAPP_PTR>(
      GetProcAddress(ucrt_dll, "_fcloseall"));
  if (fclose_all)
    fclose_all();
}

void BeforeExitProcess(UINT exit_code) {
  FlushUCRTIfPossible();
  {
    std::lock_guard<std::mutex> lock(g_executor_call_mutex);
    if (g_should_buffer_std_streams) {
      GetExecutor()->PushStdOutput(
          StdHandles::StdOutput, std::move(g_std_output_buffer));
      GetExecutor()->PushStdOutput(
          StdHandles::StdError, std::move(g_std_error_buffer));
    }
    GetExecutor()->OnBeforeExitProcess();
  }
  // Must disable all hooks, since during ExitProcess there may be
  // CloseHandle() calls when some modules already unloaded.
  // May cause strange crashes of python interpreter.
  sthook::InterceptHelperBase::DisableAll();
}

void BeforeTerminateProcess(HANDLE process_handle, UINT exit_code) {
  // Cygwin for some reason uses TerminateProcess(GetCurrentProcess()..);
  if (GetProcessId(process_handle) == GetCurrentProcessId())
    BeforeExitProcess(exit_code);
}

void AfterDeleteFileA(BOOL result, LPCSTR file_path) {
  if (!result)
    return;
  if (g_should_ignore_output_files)
    return;
  std::string abs_path_utf8 = base::AbsPathUTF8(
      base::ToLongPathName(std::string(file_path)));
  {
    std::lock_guard<std::mutex> lock(g_executor_call_mutex);
    GetExecutor()->OnFileDeleted(abs_path_utf8);
  }
}

void AfterDeleteFileW(BOOL result, LPCWSTR file_path) {
  if (!result)
    return;
  if (g_should_ignore_output_files)
    return;
  std::string abs_path_utf8 = base::AbsPathUTF8(
      base::ToLongPathName(std::wstring(file_path)));
  {
    std::lock_guard<std::mutex> lock(g_executor_call_mutex);
    GetExecutor()->OnFileDeleted(abs_path_utf8);
  }
}

}  // namespace

namespace sthook {


#define DEFINE_INTERCEPT(function_name, before_call, after_call, result, ...) \
extern InterceptHelperData function_name##_InterceptData = { \
    #function_name, before_call, after_call };

  FOR_EACH_INTERCEPTS(DEFINE_INTERCEPT)
#undef DEFINE_INTERCEPT

REGISTRATION_PTR g_intercepts_table[] = {
#define DEFINE_REGISER(function_name, before_call, after_call, result, ...) \
  InterceptHelper< \
      &function_name##_InterceptData, result, __VA_ARGS__>::Register,
  FOR_EACH_INTERCEPTS(DEFINE_REGISER)
#undef DEFINE_INTERCEPT
};

bool InstallHooks(HMODULE current_module) {
  FunctionsInterceptor::DllInterceptedFunctions ntdll_intercepts;
  FunctionsInterceptor::DllInterceptedFunctions kernel_intercepts;
  ntdll_intercepts.insert(std::make_pair("NtCreateFile", &NewNtCreateFile));
  ntdll_intercepts.insert(std::make_pair(
      "NtSetInformationFile", &NewNtSetInformationFile));
  ntdll_intercepts.insert(std::make_pair("LdrLoadDll", &NewLdrLoadDll));
  kernel_intercepts.insert(
      std::make_pair("CreateProcessA", &NewCreateProcessA));
  kernel_intercepts.insert(
      std::make_pair("CreateProcessW", &NewCreateProcessW));
  kernel_intercepts.insert(
      std::make_pair("GetExitCodeProcess", &NewGetExitCodeProcess));
  kernel_intercepts.insert(
      std::make_pair("GetProcAddress", &NewGetProcAddress));
  FunctionsInterceptor::Intercepts intercepts;
  intercepts.insert(
      std::pair<std::string, FunctionsInterceptor::DllInterceptedFunctions>(
          "ntdll.dll", ntdll_intercepts));
  // Why we hook different kernel modules:
  // On Windows7 some functions, like CreateProcess* are not exported by
  // kernelbase.dll, and kernel32 should be used.
  // On Windows 10, Windows Server 2012, we must hook kernelbase, since
  // cmd.exe on these systems links directly with it, and kernel32 hooks is not
  // enough. Fortunately, on these systems CreateProces* functions are
  // exported by kernelbase.
  std::string kernel_module_name =
      (IsWindows8OrGreater() ? "kernelbase.dll" : "kernel32.dll");
  HMODULE kernel_module = GetModuleHandleA(kernel_module_name.c_str());
  LOG4CPLUS_ASSERT(logger_, kernel_module);
  for (size_t i = 0;
      i < sizeof(g_intercepts_table) / sizeof(g_intercepts_table[0]); ++i) {
    g_intercepts_table[i](kernel_module, &kernel_intercepts);
  }

  intercepts.insert(
      std::pair<std::string, FunctionsInterceptor::DllInterceptedFunctions>(
          kernel_module_name, kernel_intercepts));
  // We do need get original addresses through GetProcAddress since
  // on Windows Server 2012 we hook directly kernelbase.dll, but this module
  // calls kernel32.dll. While this module protected from hooking, kernel32
  // is not, so we can get infinite recursion.
  g_original_CreateProcessW = reinterpret_cast<LPCREATE_PROCESS_W>(
      GetProcAddress(kernel_module, "CreateProcessW"));
  g_original_GetExitCodeProcess = reinterpret_cast<LPGET_EXIT_CODE_PROCESS>(
      GetProcAddress(kernel_module, "GetExitCodeProcess"));
  g_original_NtSetInformationFile = reinterpret_cast<LPNTSET_INFORMATION_FILE>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSetInformationFile"));
  LOG4CPLUS_ASSERT(logger_, g_original_GetExitCodeProcess);
  LOG4CPLUS_ASSERT(logger_, g_original_NtSetInformationFile);
  LOG4CPLUS_ASSERT(logger_, g_original_CreateProcessW);
  return GetInterceptor()->Hook(intercepts, current_module);
}

void Initialize(HMODULE current_module) {
  if (!InstallHooks(current_module)) {
    LOG4CPLUS_ERROR(logger_, "Hook installation failed");
  }
  ProcessConfigInfo process_config;
  GetExecutor()->GetProcessConfig(process_config);
  ProcessProxyManager::Initialize(
      current_module,
      process_config.should_use_hoax_proxy,
      g_original_CreateProcessW);
  g_should_buffer_std_streams =
      process_config.should_buffer_std_streams;
  g_should_ignore_output_files =
      process_config.should_ignore_output_files;
  StdHandlesHolder::Initialize();
}

}  // namespace sthook
