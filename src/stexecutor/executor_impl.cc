// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_impl.h"

#include "base/string_utils.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/dll_injector.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutorImpl");

#ifdef _WINDOWS
std::string NormalizePath(const std::string& abs_path) {
  if (abs_path.find(':') == std::string::npos) {
    // Passed in path are always absolute. If it does not contain column,
    // than usually means that this is reserved file name lie "con", "nul",
    // or some pipe name. Just ignore them.
    LOG4CPLUS_INFO(logger_, "Invalid special path " << abs_path.c_str());
    return std::string();
  }
  std::string result = abs_path;
  // Use consistent delimeters in path - WinAPI seems to support both
  std::replace(result.begin(), result.end(), '\\', '/');
  return base::UTF8ToLower(result);
}
#else
#error "This function at present implemented for Windows only"
#endif

}  // namespace

ExecutorImpl::ExecutorImpl(DllInjector* dll_injector)
    : dll_injector_(dll_injector) {
}

bool ExecutorImpl::HookedCreateFile(
    const std::string& abs_path, const bool for_writing) {
  std::string norm_path = NormalizePath(abs_path);
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
  command_info_.id = current_pid;
  command_info_.command_line = command_line;
  command_info_.startup_directory = startup_directory;
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
    const std::string& exe_path,
    const std::vector<std::string>& arguments,
    const std::string& startup_dir,
    const std::vector<std::string>& environment_strings) {
  std::string buffer;
  for (const std::string& x : arguments) {
    buffer += x;
    buffer += " ";
  }
  std::string env_buffer;
  for (const std::string& x : environment_strings) {
    env_buffer += x;
    env_buffer += " ";
  }
  LOG4CPLUS_INFO(
      logger_,
      "Create child " << exe_path.c_str() <<
      " ARGS " << buffer.c_str() <<
      " IN " << startup_dir.c_str() <<
      " ENV " << env_buffer.c_str());
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
      LOG4CPLUS_INFO(logger_, "Waiting for process " << command_info_.id);
      if (WaitForSingleObject(
          process_handle_.Get(), INFINITE) != WAIT_OBJECT_0) {
        DWORD error = GetLastError();
        LOG4CPLUS_ERROR(
            logger_, "WaitForSingleObject failed, error " << error);
        break;
      }
      LOG4CPLUS_INFO(logger_, "Wait done, process " << command_info_.id);
    }
  }
  command_info_.exit_code = exit_code;
}
