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
#include "stexecutor/build_directory_state.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/rules_mapper.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutingEngine");

}  // namespace

ExecutingEngine::ExecutingEngine(
    std::unique_ptr<FilesStorage> files_storage,
    std::unique_ptr<rules_mappers::RulesMapper> rules_mapper,
    std::unique_ptr<BuildDirectoryState> build_dir_state)
     : files_storage_(std::move(files_storage)),
       rules_mapper_(std::move(rules_mapper)),
       build_dir_state_(std::move(build_dir_state)),
       next_command_id_(kFirstUserCommandId) {
}

ExecutingEngine::~ExecutingEngine() {
}

ProcessCreationResponse ExecutingEngine::AttemptCacheExecute(
    int parent_command_id,
    const ProcessCreationRequest& process_creation_request) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  const int command_id = next_command_id_++;
  std::vector<rules_mappers::FileInfo> input_files;
  std::shared_ptr<const rules_mappers::CachedExecutionResponse>
       execution_response = rules_mapper_->FindCachedResults(
            process_creation_request, *build_dir_state_, &input_files);
  if (!execution_response) {
    LOG4CPLUS_INFO(logger_,
         "No cached response for " << process_creation_request <<
         " Assigned id " << command_id);
    running_commands_.insert(
        std::make_pair(
            command_id,
            std::unique_ptr<ProcessCreationRequest>(
                new ProcessCreationRequest(process_creation_request))));
    return ProcessCreationResponse::BuildCacheMissResponse(command_id);
  }
  LOG4CPLUS_INFO(logger_,
       "Using cached response for " << process_creation_request <<
       " Assigned id " << command_id);
  for (const rules_mappers::FileInfo& file_info :
      execution_response->output_files) {
    build_dir_state_->TakeFileFromStorage(
        files_storage_.get(),
        file_info.storage_content_id,
        file_info.rel_file_path);
  }
  for (const boost::filesystem::path& removed_path :
       execution_response->removed_rel_paths) {
    build_dir_state_->RemoveFile(removed_path);
  }
  UpdateAllParentResponses(
      parent_command_id,
      kCacheHitCommandId,
      input_files,
      *execution_response);
  return ProcessCreationResponse::BuildCacheHitResponse(
      command_id,
      execution_response->exit_code,
      files_storage_->RetrieveContent(execution_response->stdout_content_id),
      files_storage_->RetrieveContent(execution_response->stderr_content_id));
}

void ExecutingEngine::SaveCommandResults(
    const ExecutedCommandInfo& command_info) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  LOG4CPLUS_ASSERT(logger_, command_info.command_id >= kFirstUserCommandId);
  LOG4CPLUS_INFO(
      logger_, "Saving command results for " << command_info.command_id);
  auto it = running_commands_.find(command_info.command_id);
  if (it == running_commands_.end()) {
    LOG4CPLUS_ERROR(
        logger_, "Invalid command id passed " << command_info.command_id);
    return;
  }
  const ProcessCreationRequest* request = it->second.get();

  std::string stdout_id = files_storage_->StoreContent(
      command_info.result_stdout);
  std::string stderr_id = files_storage_->StoreContent(
      command_info.result_stderr);
  std::unique_ptr<rules_mappers::CachedExecutionResponse> execution_response(
      new rules_mappers::CachedExecutionResponse(
          command_info.output_files,
          command_info.removed_rel_paths,
          command_info.exit_code,
          stdout_id,
          stderr_id));
  if (!command_info.child_command_ids.empty() ||
      // There may be CumulativeExecutionResponseBuilder event when
      // child_command_ids is empty - when all childs are cache hits.
      parent_command_id_to_results_.count(command_info.command_id) > 0) {
    CumulativeExecutionResponseBuilder* builder = GetCumulativeResponseBuilder(
        command_info.command_id);
    builder->SetParentExecutionResponse(
        *request,
        command_info.input_files,
        *execution_response);
    if (builder->IsComplete()) {
      LOG4CPLUS_INFO(logger_, "Parent command completed " << * request);
      rules_mapper_->AddRule(
          *request,
          builder->BuildAllInputFiles(),
          builder->BuildExecutionResponse());
      parent_command_id_to_results_.erase(command_info.command_id);
      UpdateAllParentResponsesForCompletedChild(
          command_info.command_id,
          command_info.input_files,
          *execution_response);
    }
  } else {
    UpdateAllParentResponsesForCompletedChild(
        command_info.command_id,
        command_info.input_files,
        *execution_response);
    LOG4CPLUS_INFO(logger_,
        "Saving command " << *request
        << " it has "
        << command_info.input_files.size() << " input files and "
        << command_info.output_files.size() << " output files");
    rules_mapper_->AddRule(
        *request,
        command_info.input_files,
        std::move(execution_response));
  }
  running_commands_.erase(it);
}

void ExecutingEngine::UpdateAllParentResponsesForCompletedChild(
    int child_command_id,
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  auto it_parent_id = child_command_id_to_parent_.find(child_command_id);
  if (it_parent_id != child_command_id_to_parent_.end()) {
    UpdateAllParentResponses(
        it_parent_id->second.command_id,
        child_command_id,
        input_files,
        execution_response);
    child_command_id_to_parent_.erase(it_parent_id);
  }
}

void ExecutingEngine::UpdateAllParentResponses(
    int first_parent_command_id,
    int child_command_id,
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  int current_command_id = first_parent_command_id;
  while (current_command_id != kRootCommandId) {
    CumulativeExecutionResponseBuilder* parent_builder =
        GetCumulativeResponseBuilder(current_command_id);
    parent_builder->AddChildResponse(
        child_command_id,
        input_files, execution_response);
    auto it_parent_id = child_command_id_to_parent_.find(
        current_command_id);
    if (it_parent_id == child_command_id_to_parent_.end())
      break;
    current_command_id = it_parent_id->second.command_id;
  }
}

void ExecutingEngine::AssociatePIDWithCommandId(
    int parent_command_id,
    int32_t pid, int command_id, bool should_append_std_streams) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  LOG4CPLUS_ASSERT(
      logger_, child_command_id_to_parent_.count(command_id) == 0);
  child_command_id_to_parent_.insert(
      std::make_pair(
          command_id,
          ParentInfo{parent_command_id, should_append_std_streams}));
  pid_to_command_id_.insert(std::make_pair(pid, command_id));
  // Emulate "child-parent" relations between all processes in tree,
  // So top-level process will grab all input-output files.
  int cur_parent_id = parent_command_id;
  // Avoid creating cumulative builder for root command - stlaunch.
  while (cur_parent_id != kRootCommandId) {
    CumulativeExecutionResponseBuilder* parent_builder =
        GetCumulativeResponseBuilder(cur_parent_id);
    parent_builder->ChildProcessCreated(command_id);
    auto it = child_command_id_to_parent_.find(cur_parent_id);
    if (it == child_command_id_to_parent_.end())
      break;
    cur_parent_id = it->second.command_id;
  }
}

void ExecutingEngine::RegisterByPID(
      int32_t pid,
      int* command_id,
      std::vector<int>* command_ids_should_append_std_streams) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  auto it = pid_to_command_id_.find(pid);
  if (it == pid_to_command_id_.end()) {
    LOG4CPLUS_ERROR(logger_, "No command id for pid " << pid);
    *command_id = kInvalidCommandId;
    return;
  }
  *command_id = it->second;
  pid_to_command_id_.erase(it);

  int current_command_id = *command_id;
  while (true) {
    auto it_parent_command = child_command_id_to_parent_.find(
        current_command_id);
    if (it_parent_command == child_command_id_to_parent_.end())
      break;
    if (!it_parent_command->second.should_append_std_streams)
      break;
    command_ids_should_append_std_streams->push_back(
        it_parent_command->second.command_id);
    current_command_id = it_parent_command->second.command_id;
  }
}

CumulativeExecutionResponseBuilder*
ExecutingEngine::GetCumulativeResponseBuilder(int command_id) {
  auto it = parent_command_id_to_results_.find(command_id);
  if (it != parent_command_id_to_results_.end())
    return it->second.get();
  LOG4CPLUS_ASSERT(logger_, command_id >= kFirstUserCommandId);
  std::unique_ptr<CumulativeExecutionResponseBuilder> result(
      new CumulativeExecutionResponseBuilder());
  auto* result_ptr = result.get();
  parent_command_id_to_results_.insert(std::make_pair(
      command_id, std::move(result)));
  return result_ptr;
}
