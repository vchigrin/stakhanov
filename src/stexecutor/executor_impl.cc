// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_impl.h"

#include <algorithm>

#include "base/string_utils.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/executor_factory.h"
#include "stexecutor/process_creation_request.h"
#include "stexecutor/process_creation_response.h"
#include "third_party/cryptopp/md5.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutorImpl");

#ifdef _WINDOWS
boost::filesystem::path NormalizePath(const std::string& abs_path) {
  if (abs_path.find(':') == std::string::npos) {
    // Passed in path are always absolute. If it does not contain column,
    // than usually means that this is reserved file name like "con", "nul",
    // or some pipe name. Just ignore them.
    LOG4CPLUS_INFO(logger_, "Met special path " << abs_path.c_str());
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
    ExecutingEngine* executing_engine,
    ExecutorFactory* executor_factory)
    : dll_injector_(dll_injector),
      executing_engine_(executing_engine),
      executor_factory_(executor_factory) {
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

void ExecutorImpl::HookedRenameFile(
    const std::string& old_name_str,
    const std::string& new_name_str) {
  boost::filesystem::path norm_old_path = NormalizePath(old_name_str);
  boost::filesystem::path norm_new_path = NormalizePath(new_name_str);
  auto it_output = command_info_.output_files.find(norm_old_path);
  if (it_output != command_info_.output_files.end()) {
    // One of existing outputs renamed.
    command_info_.output_files.erase(it_output);
  } else {
    // This is not our output - add both "input" andn "output" to
    // describe rename.
    command_info_.input_files.insert(norm_old_path);
  }
  command_info_.output_files.insert(norm_new_path);
}

void ExecutorImpl::Initialize(
    const int32_t current_pid, const bool is_root_process) {
  process_handle_ = base::ScopedHandle(
      OpenProcess(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
      FALSE, current_pid));
  if (!process_handle_.IsValid()) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenProcess failed. Error " << error_code);
  }
  if (is_root_process) {
    command_info_.command_id = ExecutingEngine::kRootCommandId;
  } else {
     std::vector<int> command_ids_should_append;
     executing_engine_->RegisterByPID(
         current_pid,
         &command_info_.command_id,
         &command_ids_should_append);
     executors_should_append_std_streams_ = executor_factory_->GetExecutors(
         command_ids_should_append);
  }
  executor_factory_->RegisterExecutor(command_id(), this);
}

void ExecutorImpl::OnSuspendedProcessCreated(
    const int32_t child_pid,
    const int32_t executor_command_id,
    const bool append_std_streams) {
  LOG4CPLUS_INFO(logger_, "Created process " << child_pid);
  executing_engine_->AssociatePIDWithCommandId(
      command_info_.command_id,
      child_pid, executor_command_id, append_std_streams);
  if (!dll_injector_->InjectInto(child_pid)) {
    LOG4CPLUS_ERROR(logger_, "Failed inject dll into process " << child_pid);
  }
  command_info_.child_command_ids.push_back(child_pid);
}

void ExecutorImpl::OnFileDeleted(const std::string& abs_path) {
  boost::filesystem::path norm_path = NormalizePath(abs_path);
  // Need to avoid attempts to hash temp. files.
  command_info_.output_files.erase(norm_path);
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
      ComputeEnvironmentHash(environment_strings));
  ProcessCreationResponse response = executing_engine_->AttemptCacheExecute(
      command_info_.command_id, creation_request);
  result.cache_hit = response.is_cache_hit();
  result.exit_code = response.exit_code();
  result.result_stdout = response.result_stdout();
  result.result_stderr = response.result_stderr();
  result.executor_command_id = response.real_command_id();
}

std::string ExecutorImpl::ComputeEnvironmentHash(
    const std::vector<std::string>& env) {
  std::vector<std::string> sorted_env(env);
  std::sort(sorted_env.begin(), sorted_env.end());
  CryptoPP::Weak::MD5 hasher;
  for (const std::string& str : sorted_env) {
    // Windows has some "special" env variables like
    // "=ExitCode", "=C:", etc., that greatly vary, preventing caching.
    // Hope programs will not use them and skip them. Return in case
    // any problems.
    if (!str.empty() && str[0] != '=') {
      hasher.Update(
          reinterpret_cast<const uint8_t*>(str.data()), str.length());
    }
  }
  std::vector<uint8_t> digest(hasher.DigestSize());
  hasher.Final(&digest[0]);
  std::string result = base::BytesToHexString(digest);
  DumpEnvIfNeed(result, sorted_env);
  return result;
}

void ExecutorImpl::DumpEnvIfNeed(
    const std::string& env_hash, const std::vector<std::string>& sorted_env) {
  if (dump_env_dir_.empty())
    return;
  boost::filesystem::path file_path = dump_env_dir_ / env_hash;
  boost::filesystem::filebuf filebuf;
  if (boost::filesystem::exists(file_path))
    return;
  if (!filebuf.open(file_path, std::ios::out | std::ios::binary)) {
    LOG4CPLUS_ERROR(logger_, "Failed open file " << file_path.c_str());
    return;
  }
  for (const std::string& str : sorted_env) {
    if (!str.empty() && str[0] != '=') {
      filebuf.sputn(str.data(), str.length());
      filebuf.sputc('\n');
    }
  }
}

void ExecutorImpl::PushStdOutput(
    const StdHandles::type handle, const std::string& data) {
  {
    std::lock_guard<std::mutex> std_handles_lock(std_handles_lock_);
    if (handle == StdHandles::StdOutput)
      command_info_.result_stdout += data;
    else
      command_info_.result_stderr += data;
  }
  for (const auto& executor : executors_should_append_std_streams_) {
    executor->PushStdOutput(handle, data);
  }
}

void ExecutorImpl::FillExitCode() {
  // Root process - stlaunch.exe is a special, we don't save results for it
  // (actually it is meaningless - only results of child processes
  // (on many levels) of stlaunch can be retrieved from cache).
  if (command_info_.command_id == ExecutingEngine::kRootCommandId)
    return;
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
  executing_engine_->SaveCommandResults(command_info_);
}
