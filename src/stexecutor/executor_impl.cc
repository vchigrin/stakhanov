// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_impl.h"

#include <algorithm>

#include "base/string_utils.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/executor_factory.h"
#include "stexecutor/files_filter.h"
#include "stexecutor/process_creation_request.h"
#include "stexecutor/process_creation_response.h"
#include "stexecutorlib/files_storage.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutorImpl");

#ifdef _WINDOWS
boost::filesystem::path NormalizePath(const std::string& abs_path) {
  if (abs_path.find(':') == std::string::npos) {
    // Passed in path are always absolute. If it does not contain column,
    // than usually means that this is reserved file name like "con", "nul",
    // or some pipe name. Just ignore them.
    return boost::filesystem::path();
  }
  std::string lower_path = base::UTF8ToLower(abs_path);
  std::wstring wide_path = base::ToWideFromUTF8(lower_path);
  boost::filesystem::path source(wide_path);
  // boost::filesystem::canonical requires path to exist, that is not
  // always acceptable. So remove ".." and "." entries by-hand
  boost::filesystem::path result;
  boost::filesystem::path root(source.root_path());
  for (const auto& component : source) {
    if (component == L".")
      continue;
    if (component == L"..") {
      if (result != root)
        result.remove_filename();
      continue;
    }
    result /= component;
  }
  return result;
}
#else
#error "This function at present implemented for Windows only"
#endif

}  // namespace

ExecutorImpl::ExecutorImpl(
    DllInjector* dll_injector,
    ExecutingEngine* executing_engine,
    ExecutorFactory* executor_factory,
    FilesFilter* files_filter)
    : dll_injector_(dll_injector),
      executing_engine_(executing_engine),
      executor_factory_(executor_factory),
      files_filter_(files_filter),
      files_infos_filled_(false),
      is_helper_executor_(false) {
  memset(&process_config_info_, 0, sizeof(process_config_info_));
}

bool ExecutorImpl::HookedCreateFile(
    const std::string& abs_path, const bool for_writing) {
  LOG4CPLUS_ASSERT(logger_, !is_helper_executor_);
  boost::filesystem::path norm_path = NormalizePath(abs_path);
  if (norm_path.empty()) {  // May be if path is "invalid" for intercept
    return true;
  }
  auto* build_dir_state = executing_engine_->build_dir_state();
  boost::filesystem::path rel_path = build_dir_state->MakeRelativePath(
      norm_path);
  if (rel_path.empty())
    return true;
  if (for_writing) {
    build_dir_state->NotifyFileChanged(rel_path);
    if (!files_filter_->CanDropOutput(norm_path)) {
      removed_files_.erase(norm_path);
      output_files_.insert(norm_path);
    }
  } else {
    if (input_files_.count(rel_path) != 0)
      return true;  // Already marked as "input"
    // That is our output file. Some commands like linkers from NaCl toolchain
    // re-open their outputs for reading for some reason. Avoid adding
    // them as inputs - in other case we'll never will get cache hit
    // for them.
    if (output_files_.count(norm_path) != 0)
      return true;
    if (files_filter_->CanDropInput(norm_path))
      return true;
    // We must hash input files ASAP, since some commands
    // use files both as "input" and "output", so hashing them at
    // ExitProcess() time will produce invalid results.
    std::string content_id = build_dir_state->GetFileContentId(
        rel_path);
    if (content_id.empty()) {
      LOG4CPLUS_ERROR(logger_, "Failed hash input file " << rel_path);
      return true;
    }
    input_files_.insert(std::make_pair(rel_path,
        rules_mappers::FileInfo(
            rel_path, content_id, std::chrono::steady_clock::now())));
  }
  return true;
}

void ExecutorImpl::HookedRenameFile(
    const std::string& old_name_str,
    const std::string& new_name_str) {
  LOG4CPLUS_ASSERT(logger_, !is_helper_executor_);
  boost::filesystem::path norm_old_path = NormalizePath(old_name_str);
  boost::filesystem::path norm_new_path = NormalizePath(new_name_str);
  auto it_output = output_files_.find(norm_old_path);
  if (it_output != output_files_.end()) {
    // One of existing outputs renamed.
    output_files_.erase(it_output);
  } else {
    // This is not our output - add both "input" andn "output" to
    // describe rename.
    removed_files_.insert(norm_old_path);
    if (!files_filter_->CanDropInput(norm_old_path)) {
      BuildDirectoryState* build_dir_state =
          executing_engine_->build_dir_state();
      boost::filesystem::path rel_old_path = build_dir_state->MakeRelativePath(
          norm_old_path);
      boost::filesystem::path rel_new_path = build_dir_state->MakeRelativePath(
          norm_new_path);
      if (!rel_old_path.empty() && !rel_new_path.empty()) {
        // We're called after rename took place, so use new path to get
        // content id.
        std::string content_id = build_dir_state->GetFileContentId(
            rel_new_path);
        input_files_.insert(std::make_pair(
            rel_old_path,
            rules_mappers::FileInfo(
                rel_old_path, content_id, std::chrono::steady_clock::now())));
      }
    }
  }
  if (!files_filter_->CanDropOutput(norm_new_path)) {
    removed_files_.erase(norm_new_path);
    output_files_.insert(norm_new_path);
  }
}

int32_t ExecutorImpl::InitializeMainExecutor(
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
         &command_ids_should_append,
         &process_config_info_.should_use_hoax_proxy,
         &process_config_info_.should_buffer_std_streams,
         &process_config_info_.should_ignore_output_files);
     executors_should_append_std_streams_ = executor_factory_->GetExecutors(
         command_ids_should_append);
  }
  executor_factory_->RegisterExecutor(command_id(), this);
  return command_info_.command_id;
}

void ExecutorImpl::InitializeHelperExecutor(
    const int32_t main_executor_command_id) {
  is_helper_executor_ = true;
  command_info_.command_id = main_executor_command_id;
  // Only main executors should be registered in executor_factory,
  // so don't do it here. We do need append std streams only to main executors,
  // and registration used only for this.
}

void ExecutorImpl::GetProcessConfig(ProcessConfigInfo& result) {
  result = process_config_info_;
}

void ExecutorImpl::OnSuspendedProcessCreated(
    const int32_t child_pid,
    const int32_t child_main_thread_id,
    const int32_t executor_command_id,
    const bool append_std_streams,
    const bool leave_suspended) {
  LOG4CPLUS_INFO(logger_, "Created process " << child_pid);
  bool do_not_track = false;
  executing_engine_->AssociatePIDWithCommandId(
      child_pid, executor_command_id, append_std_streams, &do_not_track);
  if (do_not_track) {
    if (!leave_suspended) {
      if (!dll_injector_->Resume(child_pid, child_main_thread_id)) {
        LOG4CPLUS_ERROR(logger_, "Failed resume process " << child_pid);
      }
    }
  } else {
    if (!dll_injector_->InjectInto(
        child_pid, child_main_thread_id, leave_suspended)) {
      LOG4CPLUS_ERROR(logger_, "Failed inject dll into process " << child_pid);
    }
  }
}

void ExecutorImpl::OnFileDeleted(const std::string& abs_path) {
  LOG4CPLUS_ASSERT(logger_, !is_helper_executor_);
  boost::filesystem::path norm_path = NormalizePath(abs_path);
  // Need to avoid attempts to hash temp. files.
  output_files_.erase(norm_path);
  // rc.exe re-opens some temp files without write bit set, causing
  // they appear both as input and output.
  // TODO(vchigrin): Consider better handling of deleted files, we should
  // be able cache commands like "del foo.txt" where "foo.txt" must be
  // considered as input.

  BuildDirectoryState* build_dir_state =
      executing_engine_->build_dir_state();
  boost::filesystem::path rel_old_path = build_dir_state->MakeRelativePath(
      norm_path);
  input_files_.erase(rel_old_path);
  removed_files_.insert(norm_path);
}

void ExecutorImpl::OnBeforeExitProcess() {
  // We must perform hashing of all files synchronously here.
  // After we return our peer process will exit and other processes
  // may change these files.
  FillFileInfos();
}

void ExecutorImpl::FillFileInfos() {
  LOG4CPLUS_ASSERT(logger_, !is_helper_executor_);
  files_infos_filled_ = true;
  BuildDirectoryState* build_dir_state = executing_engine_->build_dir_state();
  FilesStorage* files_storage = executing_engine_->files_storage();
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  for (const boost::filesystem::path& output_path : output_files_) {
    if (removed_files_.count(output_path) > 0) {
      // Do not take into account temporary files.
      continue;
    }
    boost::filesystem::path rel_path = build_dir_state->MakeRelativePath(
        output_path);
    if (rel_path.empty()) {
      continue;
    }
    std::string storage_id = files_storage->StoreFile(output_path);
    if (storage_id.empty()) {
      // It is normal situation e.g. if file is too big.
      LOG4CPLUS_INFO(
          logger_,
          "Don't save file to storage, skip command results caching "
          << output_path);
      command_info_.has_errors = true;
      return;
    }
    command_info_.output_files.push_back(
        rules_mappers::FileInfo(rel_path, storage_id, now));
  }
  command_info_.input_files.reserve(input_files_.size());
  std::transform(
      input_files_.begin(),
      input_files_.end(),
      std::back_inserter(command_info_.input_files),
      [] (const auto& input_path_and_file) {
          return input_path_and_file.second;
      });
  command_info_.removed_rel_paths.reserve(removed_files_.size());
  for (const boost::filesystem::path& removed_path : removed_files_) {
    boost::filesystem::path rel_path = build_dir_state->MakeRelativePath(
        removed_path);
    if (rel_path.empty()) {
      continue;
    }
    command_info_.removed_rel_paths.push_back(rel_path);
  }
}

void ExecutorImpl::OnBeforeProcessCreate(
    CacheHitInfo& result,
    const std::string& exe_path,
    const std::vector<std::string>& arguments,
    const std::string& startup_directory,
    const std::string& environment_hash) {
  ProcessCreationRequest creation_request(
      exe_path,
      NormalizePath(startup_directory),
      arguments,
      environment_hash);
  ProcessCreationResponse response = executing_engine_->AttemptCacheExecute(
      command_info_.command_id, creation_request);
  result.cache_hit = response.is_cache_hit();
  result.exit_code = response.exit_code();
  result.result_stdout = response.result_stdout();
  result.result_stderr = response.result_stderr();
  result.executor_command_id = response.real_command_id();
}

void ExecutorImpl::PushStdOutput(
    const StdHandles::type handle, const std::string& data) {
  LOG4CPLUS_ASSERT(logger_, !is_helper_executor_);
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
  if (is_helper_executor_)
    return;
  // Root process - stlaunch.exe is a special, we don't save results for it
  // (actually it is meaningless - only results of child processes
  // (on many levels) of stlaunch can be retrieved from cache).
  if (command_info_.command_id == ExecutingEngine::kRootCommandId)
    return;
  if (!files_infos_filled_) {
    LOG4CPLUS_WARN(
        logger_,
        "Warning, ExitProcess() track failed. for "
            << command_info_.command_id);
    FillFileInfos();
  }

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

  if (exit_code != 0) {
    // Temporary disable saving all failed commands. Theoretically there is
    // no problem to cache them, but now we have some bugs in
    // sthook/stexecutor, so disabling that cache may simplify developing.
    command_info_.has_errors = true;
  }

  executing_engine_->SaveCommandResults(command_info_);
}
