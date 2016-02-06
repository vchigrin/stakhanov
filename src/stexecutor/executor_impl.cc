// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_impl.h"

#include "base/string_utils.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/process_creation_request.h"
#include "stexecutor/process_creation_response.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutorImpl");

#ifdef _WINDOWS
boost::filesystem::path NormalizePath(const std::string& abs_path) {
  if (abs_path.find(':') == std::string::npos) {
    // Passed in path are always absolute. If it does not contain column,
    // than usually means that this is reserved file name lie "con", "nul",
    // or some pipe name. Just ignore them.
    LOG4CPLUS_INFO(logger_, "Invalid special path " << abs_path.c_str());
    return boost::filesystem::path();
  }
  std::string lower_path = base::UTF8ToLower(abs_path);
  std::wstring wide_path = base::ToWideFromUTF8(lower_path);
  return boost::filesystem::path(wide_path);
}
#else
#error "This function at present implemented for Windows only"
#endif

}  // namespace

ExecutorImpl::ExecutorImpl(
    DllInjector* dll_injector,
    ExecutingEngine* executing_engine)
    : dll_injector_(dll_injector),
      executing_engine_(executing_engine) {
}

bool ExecutorImpl::HookedCreateFile(
    const std::string& abs_path, const bool for_writing) {
  boost::filesystem::path norm_path = NormalizePath(abs_path);
  if (norm_path.empty()) {  // May be if path is "invalid" for intercept
    return true;
  }
  if (for_writing)
    command_info_.output_files.insert(norm_path);
  else
    command_info_.input_files.insert(norm_path);
  return true;
}

void ExecutorImpl::Initialize(
    const int32_t current_pid,
    const std::string& command_line,
    const std::string& startup_directory) {
  /*
  command_info_.id = current_pid;
  command_info_.command_line = command_line;
  command_info_.startup_directory = startup_directory;
  */
  process_handle_ = base::ScopedHandle(
      OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
      FALSE, current_pid));
  if (!process_handle_.IsValid()) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenProcess failed. Error " << error_code);
  }
}

void ExecutorImpl::OnSuspendedProcessCreated(const int32_t child_pid) {
  LOG4CPLUS_INFO(logger_, "Created process " << child_pid);
  if (!dll_injector_->InjectInto(child_pid)) {
    LOG4CPLUS_ERROR(logger_, "Failed inject dll into process " << child_pid);
  }
  command_info_.child_command_ids.push_back(child_pid);
}

void ExecutorImpl::OnBeforeProcessCreate(
    CacheHitInfo& result,
    const std::string& exe_path,
    const std::vector<std::string>& arguments,
    const std::string& startup_directory,
    const std::vector<std::string>& environment_strings) {
  ProcessCreationRequest creation_request(
      NormalizePath(exe_path),
      NormalizePath(startup_directory),
      arguments,
      std::unordered_set<std::string>(
          environment_strings.begin(), environment_strings.end()));
  ProcessCreationResponse response = executing_engine_->AttemptCacheExecute(
      creation_request);
  result.cache_hit = response.is_cache_hit();
  result.exit_code = response.exit_code();
  result.result_stdout = response.result_stdout();
  result.result_stderr = response.result_stderr();
}

void ExecutorImpl::PushStdOutput(
    const StdHandles::type handle, const std::string& data) {
  if (handle == StdHandles::StdOutput)
    command_info_.result_stdout += data;
  else
    command_info_.result_stderr += data;
}

void ExecutorImpl::FillExitCode() {
  DWORD exit_code = 0;
  LOG4CPLUS_ASSERT(logger_, process_handle_.IsValid());
  while (true) {
    if (!GetExitCodeProcess(process_handle_.Get(), &exit_code)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "GetExitCodeProcess failed, error " << error);
    }
    if (exit_code != STILL_ACTIVE) {
      break;
    } else {
      LOG4CPLUS_INFO(logger_, "Waiting for process ");
      if (WaitForSingleObject(
          process_handle_.Get(), INFINITE) != WAIT_OBJECT_0) {
        DWORD error = GetLastError();
        LOG4CPLUS_ERROR(
            logger_, "WaitForSingleObject failed, error " << error);
        break;
      }
      LOG4CPLUS_INFO(logger_, "Wait done");
    }
  }
  command_info_.exit_code = exit_code;
}
