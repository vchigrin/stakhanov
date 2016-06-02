// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executing_engine.h"

#include <vector>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/cumulative_execution_response_builder.h"
#include "stexecutor/files_storage.h"
#include "stexecutor/process_creation_request.h"
#include "stexecutor/process_creation_response.h"
#include "stexecutor/process_management_config.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/rules_mapper.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutingEngine");

}  // namespace

ExecutingEngine::ExecutingEngine(
    std::unique_ptr<FilesStorage> files_storage,
    std::unique_ptr<rules_mappers::RulesMapper> rules_mapper,
    std::unique_ptr<BuildDirectoryState> build_dir_state,
    std::unique_ptr<ProcessManagementConfig> process_management_config)
     : files_storage_(std::move(files_storage)),
       rules_mapper_(std::move(rules_mapper)),
       build_dir_state_(std::move(build_dir_state)),
       process_management_config_(std::move(process_management_config)),
       next_command_id_(kFirstUserCommandId) {
}

ExecutingEngine::~ExecutingEngine() {
}

ProcessCreationResponse ExecutingEngine::AttemptCacheExecute(
    int parent_command_id,
    const ProcessCreationRequest& process_creation_request) {
  std::vector<rules_mappers::FileInfo> input_files;
  std::shared_ptr<const rules_mappers::CachedExecutionResponse>
       execution_response = rules_mapper_->FindCachedResults(
            process_creation_request, *build_dir_state_, &input_files);


  int command_id = 0;
  bool new_request_ignores_std_streams_from_children = false;
  bool parent_ignores_std_streams_from_children = false;
  if (!execution_response) {
    // This variable is used only for cache misses.
    new_request_ignores_std_streams_from_children =
        process_management_config_->ShouldIgnoreStdStreamsFromChildren(
            process_creation_request);
  }

  CumulativeExecutionResponseBuilder* parent_builder = nullptr;
  {
    std::lock_guard<std::mutex> instance_lock(instance_lock_);
    command_id = next_command_id_++;
    parent_builder = GetResponseBuilder(parent_command_id);
    LOG4CPLUS_ASSERT(
        logger_, parent_builder || parent_command_id == kRootCommandId);
    if (!execution_response) {
      return HandleCacheMissUnderInstanceLock(
          parent_builder,
          command_id,
          new_request_ignores_std_streams_from_children,
          process_creation_request);
    }
    LOG4CPLUS_INFO(logger_,
         "Using cached response for " << process_creation_request <<
         " Assigned id " << command_id);
    LOG4CPLUS_ASSERT(
        logger_, parent_builder || parent_command_id == kRootCommandId);
    if (parent_builder) {
      parent_ignores_std_streams_from_children =
          parent_builder->should_ignore_std_streams_from_children();
    }
  }
  bool success = true;
  // TODO(vchigrin): Handle errors, if we'll fail to take any file from
  // storage we should fall-back to CacheMiss.
  for (const rules_mappers::FileInfo& file_info :
      execution_response->output_files) {
    success &= build_dir_state_->TakeFileFromStorage(
        files_storage_.get(),
        file_info.storage_content_id,
        file_info.rel_file_path);
  }
  for (const boost::filesystem::path& removed_path :
       execution_response->removed_rel_paths) {
    success &= build_dir_state_->RemoveFile(removed_path);
  }
  std::string stdout_content, stderr_content;

  if (!parent_ignores_std_streams_from_children) {
    success &= files_storage_->RetrieveContent(
        execution_response->stdout_content_id,
        &stdout_content);
    success &= files_storage_->RetrieveContent(
        execution_response->stderr_content_id,
        &stderr_content);
  }

  {
    std::lock_guard<std::mutex> instance_lock(instance_lock_);
    if (success) {
      if (parent_builder) {
        parent_builder->AddChildResponse(
            kCacheHitCommandId,
            input_files, *execution_response);
      }
    } else {
      LOG4CPLUS_INFO(
          logger_,
          "Failed handle cached response for " << process_creation_request <<
          " fall back to real execution");
      return HandleCacheMissUnderInstanceLock(
          parent_builder,
          command_id,
          new_request_ignores_std_streams_from_children,
          process_creation_request);
    }
  }
  return ProcessCreationResponse::BuildCacheHitResponse(
      command_id,
      execution_response->exit_code,
      std::move(stdout_content),
      std::move(stderr_content));
}

void ExecutingEngine::SaveCommandResults(
    const ExecutedCommandInfo& command_info) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  LOG4CPLUS_ASSERT(logger_, command_info.command_id >= kFirstUserCommandId);
  LOG4CPLUS_INFO(
      logger_, "Saving command results for " << command_info.command_id);
  CumulativeExecutionResponseBuilder* response_builder =
      GetResponseBuilder(command_info.command_id);
  if (!response_builder) {
    LOG4CPLUS_ERROR(
        logger_, "Invalid command id passed " << command_info.command_id);
    return;
  }
  if (command_info.has_errors) {
    response_builder->MarkOwnCommandFailed();
  } else {
    std::string stdout_id, stderr_id;

    CumulativeExecutionResponseBuilder* parent_builder =
        response_builder->ancestor();
    if (parent_builder &&
        parent_builder->should_ignore_std_streams_from_children()) {
      // During cache hit we will ignore stdout/stderr in any case,
      // so just drop them before save.
      stdout_id = files_storage_->StoreContent(std::string());
      stderr_id = stdout_id;
    } else {
      stdout_id = files_storage_->StoreContent(command_info.result_stdout);
      stderr_id = files_storage_->StoreContent(command_info.result_stderr);
    }

    std::unique_ptr<rules_mappers::CachedExecutionResponse> execution_response(
        new rules_mappers::CachedExecutionResponse(
            command_info.output_files,
            command_info.removed_rel_paths,
            command_info.exit_code,
            stdout_id,
            stderr_id));

    response_builder->SetOwnExecutionResponse(
        command_info.input_files,
        *execution_response);
  }
  if (response_builder->IsComplete()) {
    CompleteCumulativeResponse(response_builder);
  }
}

void ExecutingEngine::CompleteCumulativeResponse(
    CumulativeExecutionResponseBuilder* builder) {
  const ProcessCreationRequest& request = builder->process_creation_request();
  LOG4CPLUS_INFO(
      logger_, "All commands for cumulative command completed " << request);

  std::vector<rules_mappers::FileInfo> input_files =
      builder->BuildAllInputFiles();
  std::unique_ptr<rules_mappers::CachedExecutionResponse> execution_response =
      builder->BuildExecutionResponse();
  CumulativeExecutionResponseBuilder* parent = builder->ancestor();
  ProcessCreationRequest parent_request;
  if (parent) {
    parent_request = parent->process_creation_request();
    if (builder->is_failed()) {
      parent->MarkChildCommandFailed(builder->command_id());
    } else {
      parent->AddChildResponse(
          builder->command_id(),
          input_files, *execution_response);
    }
    if (parent->IsComplete())
      CompleteCumulativeResponse(parent);
  }
  if (process_management_config_->ShouldStickToParent(
        request, parent_request)) {
    LOG4CPLUS_INFO(
        logger_,
        "Don't save results - stick to parent command " << request);
  } else {
    if (builder->is_failed()) {
      LOG4CPLUS_INFO(logger_ , "Dont save failed command " << request);
    } else {
      LOG4CPLUS_INFO(logger_ , "Saving command " << request);
      rules_mapper_->AddRule(
          request,
          std::move(input_files),
          std::move(execution_response));
    }
  }
  active_commands_.erase(builder->command_id());
}

void ExecutingEngine::AssociatePIDWithCommandId(
    int32_t pid,
    int child_command_id,
    bool should_append_std_streams,
    bool* do_not_track) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  CumulativeExecutionResponseBuilder* command_builder = GetResponseBuilder(
      child_command_id);
  if (!command_builder) {
    LOG4CPLUS_ERROR(logger_, "Invalid command id" << child_command_id);
    return;
  }
  command_builder->set_should_append_std_streams_to_parent(
      should_append_std_streams);
  if (process_management_config_->ShouldDoNotTrack(
      command_builder->process_creation_request())) {
    // We will never receive SaveCommandResults() or any other call
    // for this command, so we should complete everything now.
    *do_not_track = true;
    command_builder->MarkOwnCommandFailed();
    if (command_builder->IsComplete()) {
      CompleteCumulativeResponse(command_builder);
    }
    // TODO(vchigrin): We should track outputs in some way to invalidate
    // build_dir_state_
  } else {
    pid_to_unassigned_command_id_.insert(
        std::make_pair(pid, child_command_id));
  }
}

void ExecutingEngine::RegisterByPID(
      int32_t pid,
      int* command_id,
      std::vector<int>* command_ids_should_append_std_streams,
      bool* is_safe_to_use_hoax_proxy,
      bool* should_buffer_std_streams,
      bool* should_ignore_output_files) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  auto it = pid_to_unassigned_command_id_.find(pid);
  if (it == pid_to_unassigned_command_id_.end()) {
    LOG4CPLUS_ERROR(logger_, "No command id for pid " << pid);
    *command_id = kInvalidCommandId;
    return;
  }
  *command_id = it->second;
  pid_to_unassigned_command_id_.erase(it);

  CumulativeExecutionResponseBuilder* cur_builder = GetResponseBuilder(
      *command_id);
  if (!cur_builder) {
    LOG4CPLUS_ERROR(logger_, "Invalid command id " << *command_id);
    return;
  }
  const ProcessCreationRequest& process_creation_request =
      cur_builder->process_creation_request();
  *is_safe_to_use_hoax_proxy = process_management_config_->ShouldUseHoaxProxy(
      process_creation_request);
  *should_buffer_std_streams =
      process_management_config_->ShouldBufferStdStreams(
          process_creation_request);
  *should_ignore_output_files =
      process_management_config_->ShouldIgnoreOutputFiles(
          process_creation_request);
  while (cur_builder && cur_builder->should_append_std_streams_to_parent()) {
    CumulativeExecutionResponseBuilder* parent = cur_builder->ancestor();
    if (!parent) {
      // May be only if our parent in root command.
      break;
    }
    command_ids_should_append_std_streams->push_back(
        parent->command_id());
    cur_builder = parent;
  }
}

ProcessCreationResponse ExecutingEngine::HandleCacheMissUnderInstanceLock(
    CumulativeExecutionResponseBuilder* parent_builder,
    int command_id,
    bool new_request_ignores_std_streams_from_children,
    const ProcessCreationRequest& process_creation_request) {
  LOG4CPLUS_INFO(logger_,
       "No cached response for " << process_creation_request <<
       " Assigned id " << command_id);

  std::unique_ptr<CumulativeExecutionResponseBuilder> result_builder(
      new CumulativeExecutionResponseBuilder(
          command_id,
          process_creation_request,
          new_request_ignores_std_streams_from_children,
          parent_builder));

  // Emulate "child-parent" relations between all processes in tree,
  // So top-level process will grab all input-output files.
  if (parent_builder) {
    // We add association only to direct ancestor.
    // Since parent can not complete until all it children complete, that
    // seems safe.
    parent_builder->ChildProcessCreated(command_id);
  }
  active_commands_.insert(
      std::make_pair(command_id, std::move(result_builder)));
  return ProcessCreationResponse::BuildCacheMissResponse(command_id);
}
