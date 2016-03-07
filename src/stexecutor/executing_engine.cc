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
       next_command_id_(kCacheHitCommandId + 1) {
}

ExecutingEngine::~ExecutingEngine() {
}

ProcessCreationResponse ExecutingEngine::AttemptCacheExecute(
    int parent_command_id,
    const ProcessCreationRequest& process_creation_request) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  const int command_id = next_command_id_++;
  std::vector<rules_mappers::FileInfo> input_files;
  const rules_mappers::CachedExecutionResponse* execution_response =
      rules_mapper_->FindCachedResults(
          process_creation_request, *build_dir_state_, &input_files);
  if (!execution_response) {
    LOG4CPLUS_INFO(logger_,
         "No cached response for " << process_creation_request);
    running_commands_.insert(
        std::make_pair(
            command_id,
            std::unique_ptr<ProcessCreationRequest>(
                new ProcessCreationRequest(process_creation_request))));
    return ProcessCreationResponse::BuildCacheMissResponse(command_id);
  }
  LOG4CPLUS_INFO(logger_,
       "Using cached response for " << process_creation_request);
  for (const rules_mappers::FileInfo& file_info :
      execution_response->output_files) {
    build_dir_state_->TakeFileFromStorage(
        files_storage_.get(),
        file_info.storage_content_id,
        file_info.rel_file_path);
  }
  UpdateAllParentResponses(
      parent_command_id,
      kCacheHitCommandId,
      input_files,
      *execution_response);
  return ProcessCreationResponse::BuildCacheHitResponse(
      command_id,
      execution_response->exit_code,
      execution_response->result_stdout,
      execution_response->result_stderr);
}

void ExecutingEngine::SaveCommandResults(
    const ExecutedCommandInfo& command_info) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  auto it = running_commands_.find(command_info.command_id);
  if (it == running_commands_.end()) {
    LOG4CPLUS_ERROR(
        logger_, "Invalid command id passed " << command_info.command_id);
    return;
  }
  const ProcessCreationRequest* request = it->second.get();
  std::vector<rules_mappers::FileInfo> output_files, input_files;
  for (const boost::filesystem::path& output_path : command_info.output_files) {
    boost::filesystem::path rel_path = build_dir_state_->MakeRelativePath(
        output_path);
    if (rel_path.empty()) {
      LOG4CPLUS_INFO(
          logger_, "Output file is not storage file " << output_path);
      continue;
    }
    std::string storage_id = files_storage_->StoreFile(output_path);
    if (storage_id.empty()) {
      LOG4CPLUS_ERROR(
          logger_,
          "Failed save file to storage, skip command results caching ");
      return;
    }
    output_files.push_back(rules_mappers::FileInfo(rel_path, storage_id));
  }
  for (const boost::filesystem::path& input_path : command_info.input_files) {
    boost::filesystem::path rel_path = build_dir_state_->MakeRelativePath(
        input_path);
    if (rel_path.empty()) {
      LOG4CPLUS_INFO(logger_, "Input file is not storage file " << input_path);
      continue;
    }
    std::string content_id = build_dir_state_->GetFileContentId(rel_path);
    if (content_id.empty()) {
      LOG4CPLUS_ERROR(logger_, "Failed hash input file " << input_path);
      continue;
    }
    input_files.push_back(rules_mappers::FileInfo(rel_path, content_id));
  }
  std::unique_ptr<rules_mappers::CachedExecutionResponse> execution_response(
      new rules_mappers::CachedExecutionResponse(
          output_files,
          command_info.exit_code,
          command_info.result_stdout,
          command_info.result_stderr));
  if (!command_info.child_command_ids.empty())  {
    CumulativeExecutionResponseBuilder* builder = GetCumulativeResponseBuilder(
        command_info.command_id);
    builder->SetParentExecutionResponse(
        *request,
        input_files,
        *execution_response);
    if (builder->IsComplete()) {
      LOG4CPLUS_INFO(logger_, "Parent command completed " << * request);
      rules_mapper_->AddRule(
          *request,
          builder->BuildAllInputFiles(),
          builder->BuildExecutionResponse());
      parent_command_id_to_results_.erase(command_info.command_id);
    }
  } else {
    auto it_parent_id = child_command_id_to_parent_.find(
        command_info.command_id);
    if (it_parent_id != child_command_id_to_parent_.end()) {
      UpdateAllParentResponses(
          it_parent_id->second,
          command_info.command_id,
          input_files,
          *execution_response);
    }
    LOG4CPLUS_INFO(logger_,
        "Saving command " << *request
        << " it has "
        << input_files.size() << " input files and "
        << output_files.size() << " output files");
    rules_mapper_->AddRule(
        *request,
        input_files,
        std::move(execution_response));
  }
  running_commands_.erase(it);
}

void ExecutingEngine::UpdateAllParentResponses(
    int first_parent_command_id,
    int child_command_id,
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  int current_command_id = first_parent_command_id;
  while (true) {
    CumulativeExecutionResponseBuilder* parent_builder =
        GetCumulativeResponseBuilder(current_command_id);
    parent_builder->AddChildResponse(
        child_command_id,
        input_files, execution_response);
    auto it_parent_id = child_command_id_to_parent_.find(
        current_command_id);
    if (it_parent_id == child_command_id_to_parent_.end())
      break;
    current_command_id = it_parent_id->second;
  }
}

void ExecutingEngine::AssociatePIDWithCommandId(
    int parent_command_id,
    int32_t pid, int command_id) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  LOG4CPLUS_ASSERT(
      logger_, child_command_id_to_parent_.count(command_id) == 0);
  child_command_id_to_parent_.insert(
      std::make_pair(command_id, parent_command_id));
  pid_to_command_id_.insert(std::make_pair(pid, command_id));
  // Emulate "child-parent" relations between all processes in tree,
  // So top-level process will grab all input-output files.
  int cur_parent_id = parent_command_id;
  while (true) {
    CumulativeExecutionResponseBuilder* parent_builder =
        GetCumulativeResponseBuilder(cur_parent_id);
    parent_builder->ChildProcessCreated(command_id);
    auto it = child_command_id_to_parent_.find(cur_parent_id);
    if (it == child_command_id_to_parent_.end())
      break;
    cur_parent_id = it->second;
  }
}

int ExecutingEngine::TakeCommandIDForPID(int32_t pid) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  auto it = pid_to_command_id_.find(pid);
  if (it == pid_to_command_id_.end()) {
    LOG4CPLUS_ERROR(logger_, "No command id for pid " << pid);
    return 0;
  }
  int result = it->second;
  pid_to_command_id_.erase(it);
  return result;
}

CumulativeExecutionResponseBuilder*
ExecutingEngine::GetCumulativeResponseBuilder(int command_id) {
  auto it = parent_command_id_to_results_.find(command_id);
  if (it != parent_command_id_to_results_.end())
    return it->second.get();
  std::unique_ptr<CumulativeExecutionResponseBuilder> result(
      new CumulativeExecutionResponseBuilder());
  auto* result_ptr = result.get();
  parent_command_id_to_results_.insert(std::make_pair(
      command_id, std::move(result)));
  return result_ptr;
}
