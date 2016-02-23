// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executing_engine.h"

#include <vector>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
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
       next_command_id_(1) {
}

ExecutingEngine::~ExecutingEngine() {
}

ProcessCreationResponse ExecutingEngine::AttemptCacheExecute(
    const ProcessCreationRequest& process_creation_request) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  const int command_id = next_command_id_++;
  const rules_mappers::CachedExecutionResponse* execution_response =
      rules_mapper_->FindCachedResults(
          process_creation_request, *build_dir_state_);
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
  LOG4CPLUS_INFO(logger_, "Saving command with "
                       << input_files.size() << " input files and "
                       << output_files.size() << " output files");
  rules_mapper_->AddRule(
      *request,
      input_files,
      std::unique_ptr<rules_mappers::CachedExecutionResponse>(
          new rules_mappers::CachedExecutionResponse(
              output_files,
              command_info.exit_code,
              command_info.result_stdout,
              command_info.result_stderr)));
  running_commands_.erase(it);
}

void ExecutingEngine::AssociatePIDWithCommandId(int32_t pid, int command_id) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  pid_to_command_id_.insert(std::make_pair(pid, command_id));
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
