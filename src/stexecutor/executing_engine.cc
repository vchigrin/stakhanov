// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executing_engine.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/process_creation_request.h"
#include "stexecutor/process_creation_response.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/rules_mappers/rules_mapper.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutingEngine");

} // namespace

ExecutingEngine::ExecutingEngine(
   std::unique_ptr<FilesStorage> files_storage,
   std::unique_ptr<rules_mappers::RulesMapper> rules_mapper,
   std::unique_ptr<BuildDirectoryState> build_dir_state)
    : files_storage_(std::move(files_storage))
      rules_mapper_(std::move(rules_mapper)),
      build_dir_state_(std::move(build_dir_state)) {
}

~ExecutingEngine() {
}


ProcessCreationResponse ExecutingEngine::AttemptCacheExecute(
   const ProcessCreationRequest& request) {
  std::unique_lock<std::mutex> instance_lock(instance_lock_);
  const int command_id = next_command_id_++;
  scoped_ptr<CachedExecutionResponse> execution_response(
      rules_mapper_->FindCachedResults(
          process_creation_request, *build_dir_state_));
  if (!execution_response) {
    running_commands_.insert(
        std::make_pair(
            command_id,
            std::make_unique_ptr<ProcessCreationRequest>(request)));
    return ProcessCreationResponse::BuildCacheMissResponse(
        command_id);
  }
  for (const FileInfo& file_info : execution_response->output_files) {
    build_dir_state_->TakeFileFromStorage(
        *files_storage_,
        file_info.storage_id,
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
  const ProcessCreationRequest& request = it->second;
  std::vector<FileInfo> output_files, input_files;
  for (const boost::filesystem::path& output_path : command_info.output_files) {
    std::string storage_id = files_storage_->StoreFile(output_path);
    if (storage_id.empty()) {
      LOG4CPLUS_ERROR(
          logger_, "Failed save file to storage, skip command results caching ");
      return;
    }
    boost::filesystem::path rel_path = build_dir_state_->MakeRelativePath(
        output_path);
    output_files.push_back(FileInfo(rel_path, storage_id));
  }
  for (const boost::filesystem::path& input_path : command_info.input_files) {
    std::string content_id = build_dir_state_->GetFileContentId(input_path);
    if (content_id.empty()) {
      LOG4CPLUS_WARNING(
          logger_, "File is not storage file " << input_path);
    }
    boost::filesystem::path rel_path = build_dir_state_->MakeRelativePath(
        input_path);
    input_files.push_back(FileInfo(rel_path, storage_id));
  }
  rules_mapper_->AddRule(
      request,
      input_files,
      CachedExecutionResponse(
          output_files,
          command_info.exit_code,
          command_info.result_stdout,
          command_info.result_stderr));
  running_commands_->erase(it);
}
