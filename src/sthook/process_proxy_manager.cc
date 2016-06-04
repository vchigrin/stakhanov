// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/process_proxy_manager.h"

#include <vector>

#include "boost/filesystem.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stproxy/stproxy_communication.h"
#include "sthook/reading_pipe.h"

namespace {

const wchar_t kStProxyExeName[] = L"stproxy.exe";
log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"ProcessProxyManager");

bool PutData(const base::ScopedHandle& write_handle,
             const char* data,
             int data_size) {
  if (data_size <= 0)
    return true;
  DWORD bytes_written = 0;
  BOOL success = WriteFile(
      write_handle.Get(),
      data,
      data_size,
      &bytes_written,
      NULL);
  if (!success || bytes_written != data_size) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed write std stream. Error " << error);
    return false;
  }
  return true;
}

bool TransferDataAndReissueReadIfNeed(
    const base::ScopedHandle& write_handle,
    const std::unique_ptr<ReadingPipe>& pipe) {
  int bytes_read = pipe->CompleteReadAndGetBytesTransfered();
  if (bytes_read > 0) {
    PutData(write_handle, pipe->buffer().data(), bytes_read);
    return pipe->IssueRead();
  }
  return false;
}

struct HoaxWorkItemContext {
  std::string result_stdout;
  std::string result_stderr;
  base::ScopedHandle std_output_handle;
  base::ScopedHandle std_error_handle;
  base::ScopedHandle process_handle;
  base::ScopedHandle thread_handle;
  // Owned and closed by our client. We have no right to invoke any
  // "handle" functions on it, including CloseHandle().
  void* client_process_handle = nullptr;
};

DWORD CALLBACK HoaxThreadPoolProc(void* param) {
  HoaxWorkItemContext* ctx = static_cast<HoaxWorkItemContext*>(param);
  PutData(ctx->std_output_handle,
          ctx->result_stdout.data(),
          static_cast<int>(ctx->result_stdout.size()));
  PutData(ctx->std_error_handle,
          ctx->result_stderr.data(),
          static_cast<int>(ctx->result_stderr.size()));
  SetEvent(ctx->process_handle.Get());
  SetEvent(ctx->thread_handle.Get());
  delete ctx;
  return 0;
}

}  // namespace

ProcessProxyManager* ProcessProxyManager::instance_ = nullptr;

// static
void ProcessProxyManager::Initialize(
    HMODULE current_module,
    bool is_safe_to_use_hoax_proxy,
    LPCREATE_PROCESS_W original_create_process) {
  instance_ = new ProcessProxyManager(
      current_module,
      is_safe_to_use_hoax_proxy,
      original_create_process);
}

ProcessProxyManager::ProcessProxyManager(
    HMODULE current_module,
    bool is_safe_to_use_hoax_proxy,
    LPCREATE_PROCESS_W original_create_process)
    : is_safe_to_use_hoax_proxy_(is_safe_to_use_hoax_proxy),
      original_create_process_(original_create_process) {
  InitStProxyPath(current_module);
}

bool ProcessProxyManager::CreateProxyProcess(
    const CacheHitInfo& cache_hit_info,
    DWORD creation_flags,
    HANDLE std_input_handle,
    HANDLE std_output_handle,
    HANDLE std_error_handle,
    PROCESS_INFORMATION* process_information) {
  if (is_safe_to_use_hoax_proxy_) {
    return CreateHoaxProxy(
        cache_hit_info,
        std_output_handle,
        std_error_handle,
        process_information);
  } else {
    return CreateRealProxyProcess(
        cache_hit_info,
        creation_flags,
        std_input_handle,
        std_output_handle,
        std_error_handle,
        process_information);
  }
}

bool ProcessProxyManager::TryGetExitCodeProcess(
    HANDLE process_handle, DWORD* exit_code) {
  if (!exit_code)
    return false;

  std::lock_guard<std::mutex> lock(process_handle_to_exit_code_lock_);
  auto it = process_handle_to_exit_code_.find(process_handle);
  if (it != process_handle_to_exit_code_.end()) {
    *exit_code = it->second;
    return true;
  }
  return false;
}

void ProcessProxyManager::NotifyHandleClosed(HANDLE handle) {
  std::lock_guard<std::mutex> lock(process_handle_to_exit_code_lock_);
  process_handle_to_exit_code_.erase(handle);
}

void* ProcessProxyManager::PrepareHoaxProxy(
    HANDLE std_output_handle,
    HANDLE std_error_handle,
    PROCESS_INFORMATION* process_information) {
  base::ScopedHandle process_handle(CreateEvent(NULL, FALSE, FALSE, NULL));
  base::ScopedHandle thread_handle(CreateEvent(NULL, FALSE, FALSE, NULL));
  if (!process_handle.IsValid() || !thread_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CreateEvent failed. Error " << error);
    return nullptr;
  }
  process_information->hProcess = process_handle.Get();
  process_information->hThread = thread_handle.Get();
  process_information->dwProcessId = 0;
  process_information->dwThreadId = 0;

  // Write string content asynchronously, then signal event
  // that represent "process" handle.
  // We must use async write since in case using Pipes for interprocess
  // communication WriteFile call may hang until our process issues ReadFile
  // call on other side.
  std::unique_ptr<HoaxWorkItemContext> ctx(new HoaxWorkItemContext);
  // We must duplicate handles since caller can close them immediately
  // after CreateProcess returns (since these handles already "passed" to
  // child process).
  HANDLE current_process = GetCurrentProcess();
  if (std_output_handle != NULL && std_output_handle != INVALID_HANDLE_VALUE) {
    if (!DuplicateHandle(
        current_process,
        std_output_handle,
        current_process,
        ctx->std_output_handle.Receive(),
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "DuplicateHandle failed. Error " << error);
    }
  }
  if (std_error_handle != NULL && std_error_handle != INVALID_HANDLE_VALUE) {
    if (!DuplicateHandle(
        current_process,
        std_error_handle,
        current_process,
        ctx->std_error_handle.Receive(),
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "DuplicateHandle failed. Error " << error);
    }
  }
  // We must use duplicated handles for process and thread. In other case
  // we risk get weird errors in cases when client closes one of these handles,
  // then system reuse handle value for other event and we signal wrong event.
  if (!DuplicateHandle(
      current_process,
      process_handle.Get(),
      current_process,
      ctx->process_handle.Receive(),
      0,
      FALSE,
      DUPLICATE_SAME_ACCESS)) {
    DWORD error = GetLastError();
    LOG4CPLUS_INFO(logger_, "DuplicateHandle failed. Error " << error);
    return nullptr;
  }
  if (!DuplicateHandle(
      current_process,
      thread_handle.Get(),
      current_process,
      ctx->thread_handle.Receive(),
      0,
      FALSE,
      DUPLICATE_SAME_ACCESS)) {
    DWORD error = GetLastError();
    LOG4CPLUS_INFO(logger_, "DuplicateHandle failed. Error " << error);
    return nullptr;
  }
  // Non-duplicated handle to fill process_handle_to_exit_code_ map.
  ctx->client_process_handle = process_handle.Get();
  // It is responsibility of the client to close process and thread handles.
  process_handle.Release();
  thread_handle.Release();
  return ctx.release();
}

void ProcessProxyManager::SyncFinishHoaxProxy(
    void* hoax_proxy_id,
    const CacheHitInfo& cache_hit_info) {
  HoaxWorkItemContext* ctx = static_cast<HoaxWorkItemContext*>(hoax_proxy_id);
  ctx->result_stdout = cache_hit_info.result_stdout;
  ctx->result_stderr = cache_hit_info.result_stderr;
  {
    std::lock_guard<std::mutex> lock(process_handle_to_exit_code_lock_);
    process_handle_to_exit_code_[ctx->client_process_handle] =
        cache_hit_info.exit_code;
  }
  HoaxThreadPoolProc(ctx);
}

void ProcessProxyManager::SyncDriveRealProcess(
    void* hoax_proxy_id,
    HANDLE process_handle,
    const std::unique_ptr<ReadingPipe>& stdout_pipe,
    const std::unique_ptr<ReadingPipe>& stderr_pipe) {
  std::unique_ptr<HoaxWorkItemContext> ctx(
      static_cast<HoaxWorkItemContext*>(hoax_proxy_id));
  std::vector<HANDLE> wait_handles;
  wait_handles.reserve(3);
  // Ensure stream handles go first, so in case process termination
  // they will be signales first.
  if (stdout_pipe && ctx->std_output_handle.IsValid()) {
    stdout_pipe->IssueRead();
    wait_handles.push_back(stdout_pipe->wait_handle());
  }
  if (stderr_pipe && ctx->std_error_handle.IsValid()) {
    stderr_pipe->IssueRead();
    wait_handles.push_back(stderr_pipe->wait_handle());
  }
  wait_handles.push_back(process_handle);
  while (!wait_handles.empty()) {
    DWORD wait_result = WaitForMultipleObjects(
        static_cast<DWORD>(wait_handles.size()),
        wait_handles.data(),
        FALSE,
        INFINITE);
    if (wait_result == WAIT_FAILED) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(
          logger_, "WaitForMultipleObjects failed. Error " << error);
      return;
    }
    DWORD index = wait_result - WAIT_OBJECT_0;
    if (stdout_pipe && wait_handles[index] == stdout_pipe->wait_handle()) {
      if (!TransferDataAndReissueReadIfNeed(
          ctx->std_output_handle, stdout_pipe)) {
        wait_handles.erase(wait_handles.begin() + index);
        continue;
      }
    }
    if (stderr_pipe && wait_handles[index] == stderr_pipe->wait_handle()) {
      if (!TransferDataAndReissueReadIfNeed(
          ctx->std_error_handle, stderr_pipe)) {
        wait_handles.erase(wait_handles.begin() + index);
        continue;
      }
    }
    if (wait_handles[index] == process_handle) {
      DWORD exit_code = 0;
      if (!GetExitCodeProcess(process_handle, &exit_code)) {
        DWORD error = GetLastError();
        LOG4CPLUS_ERROR(
            logger_, "GetExitCodeProcess failed. Error " << error);
        return;
      }
      LOG4CPLUS_ASSERT(logger_, exit_code != STILL_ACTIVE);
      {
        std::lock_guard<std::mutex> lock(process_handle_to_exit_code_lock_);
        process_handle_to_exit_code_[ctx->client_process_handle] = exit_code;
      }
      wait_handles.erase(wait_handles.begin() + index);
    }
  }
  if (!SetEvent(ctx->process_handle.Get())) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed set process event, error " << error);
  }
  if (!SetEvent(ctx->thread_handle.Get())) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed set process event, error " << error);
  }
}

bool ProcessProxyManager::CreateHoaxProxy(
    const CacheHitInfo& cache_hit_info,
    HANDLE std_output_handle,
    HANDLE std_error_handle,
    PROCESS_INFORMATION* process_information) {
  HoaxWorkItemContext* ctx = static_cast<HoaxWorkItemContext*>(
      PrepareHoaxProxy(
          std_output_handle,
          std_error_handle,
          process_information));
  if (!ctx)
    return false;
  ctx->result_stdout = cache_hit_info.result_stdout;
  ctx->result_stderr = cache_hit_info.result_stderr;
  if (!QueueUserWorkItem(
      HoaxThreadPoolProc,
      ctx,
      WT_EXECUTEDEFAULT)) {
    DWORD error = GetLastError();

    LOG4CPLUS_ERROR(logger_, "QueueUserWorkItem failed. Error " << error);
    delete ctx;
    return false;
  }
  {
    std::lock_guard<std::mutex> lock(process_handle_to_exit_code_lock_);
    process_handle_to_exit_code_[ctx->client_process_handle] =
        cache_hit_info.exit_code;
  }
  return true;
}

bool ProcessProxyManager::CreateRealProxyProcess(
    const CacheHitInfo& cache_hit_info,
    DWORD creation_flags,
    HANDLE std_input_handle,
    HANDLE std_output_handle,
    HANDLE std_error_handle,
    PROCESS_INFORMATION* process_information) {
  base::ScopedHandle file_mapping_handle = PrepareFileMapping(cache_hit_info);
  if (!file_mapping_handle.IsValid())
    return false;
  std::wostringstream buffer;
  buffer << std::hex << file_mapping_handle.Get();
  std::wstring handle_str = buffer.str();
  std::vector<wchar_t> command_line;
  // stproxy_path + 1 space + file_mapping_handle + zero terminator.
  command_line.reserve(stproxy_path_.length() + 1 + handle_str.length() + 1);
  std::copy(
      stproxy_path_.begin(), stproxy_path_.end(),
      std::back_inserter(command_line));
  command_line.push_back(L' ');
  std::copy(
      handle_str.begin(), handle_str.end(),
      std::back_inserter(command_line));
  command_line.push_back(L'\0');
  STARTUPINFO startup_info = {0};
  startup_info.cb = sizeof(startup_info);
  startup_info.hStdInput = std_input_handle;
  startup_info.hStdOutput = std_output_handle;
  startup_info.hStdError = std_error_handle;
  if (std_output_handle || std_error_handle || std_input_handle) {
    startup_info.dwFlags = STARTF_USESTDHANDLES;
  }
  BOOL result = original_create_process_(
        NULL,
        &command_line[0],
        NULL,
        NULL,
        TRUE,  // Inherit handles
        creation_flags & ~EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &startup_info,
        process_information);
  if (!result) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed  create proxy process, error " << error);
  }
  return result;
}

base::ScopedHandle ProcessProxyManager::PrepareFileMapping(
    const CacheHitInfo& cache_hit_info) {
  DWORD required_file_mapping_size =
      sizeof(STPROXY_SECTION_HEADER) +
      static_cast<DWORD>(cache_hit_info.result_stdout.length() +
                         cache_hit_info.result_stderr.length());
  SECURITY_ATTRIBUTES security_attributes = {0};
  security_attributes.nLength = sizeof(security_attributes);
  security_attributes.lpSecurityDescriptor = NULL;
  security_attributes.bInheritHandle = TRUE;
  base::ScopedHandle file_mapping_handle(CreateFileMapping(
      INVALID_HANDLE_VALUE,
      &security_attributes,
      PAGE_READWRITE,
      0,
      required_file_mapping_size,
      NULL));
  if (!file_mapping_handle.IsValid()) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CreateFileMapping failed, error " << error_code);
    return base::ScopedHandle();
  }
  void* file_mapping_data = MapViewOfFile(
      file_mapping_handle.Get(),
      FILE_MAP_WRITE,
      0, 0,
      required_file_mapping_size);
  if (!file_mapping_data) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "MapViewOfFile failed, error " << error_code);
    return base::ScopedHandle();
  }
  STPROXY_SECTION_HEADER* header = static_cast<STPROXY_SECTION_HEADER*>(
      file_mapping_data);
  header->exit_code = cache_hit_info.exit_code;
  header->stdout_byte_size = static_cast<DWORD>(
      cache_hit_info.result_stdout.length());
  header->stderr_byte_size = static_cast<DWORD>(
      cache_hit_info.result_stderr.length());
  uint8_t* dest_data = static_cast<uint8_t*>(file_mapping_data);
  dest_data += sizeof(STPROXY_SECTION_HEADER);
  memcpy(dest_data,
         cache_hit_info.result_stdout.c_str(),
         cache_hit_info.result_stdout.length());
  dest_data += cache_hit_info.result_stdout.length();
  memcpy(dest_data,
         cache_hit_info.result_stderr.c_str(),
         cache_hit_info.result_stderr.length());
  UnmapViewOfFile(file_mapping_data);
  return file_mapping_handle;
}


void ProcessProxyManager::InitStProxyPath(HMODULE current_module) {
  std::vector<wchar_t> buffer(MAX_PATH + 1);
  GetModuleFileName(current_module, &buffer[0], MAX_PATH);
  buffer[MAX_PATH] = L'\0';
  boost::filesystem::path cur_dll_path(&buffer[0]);
  boost::filesystem::path result =
      cur_dll_path.parent_path() / kStProxyExeName;
  stproxy_path_ = result.native();
}

