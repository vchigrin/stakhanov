// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/cumulative_execution_response_builder.h"

#include <algorithm>
#include <iterator>
#include <vector>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"CumulativeExecutionResponseBuilder");

}  // namespace

CumulativeExecutionResponseBuilder::CumulativeExecutionResponseBuilder(
    int command_id,
    CumulativeExecutionResponseBuilder* ancestor)
    : exit_code_(0),
      parent_completed_(false),
      command_id_(command_id),
      ancestor_(ancestor) {
}

void CumulativeExecutionResponseBuilder::SetParentExecutionResponse(
    const ProcessCreationRequest& request,
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  LOG4CPLUS_ASSERT(logger_, !parent_completed_);
  parent_completed_ = true;
  exit_code_ = execution_response.exit_code;
  stdout_content_id_ = execution_response.stdout_content_id;
  stderr_content_id_ = execution_response.stderr_content_id;
  AddFileSets(input_files, execution_response);
  process_creation_request_ = request;
}

void CumulativeExecutionResponseBuilder::AddChildResponse(
    int command_id,
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  if (command_id != ExecutingEngine::kCacheHitCommandId) {
    auto it = running_child_ids_.find(command_id);
    LOG4CPLUS_ASSERT(logger_, it != running_child_ids_.end());
    if (it != running_child_ids_.end())
      running_child_ids_.erase(it);
  }
  AddFileSets(input_files, execution_response);
}

std::vector<rules_mappers::FileInfo>
CumulativeExecutionResponseBuilder::BuildAllInputFiles() {
  std::vector<rules_mappers::FileInfo> result;
  result.reserve(input_files_.size());
  // Check, if any file is present both in input and output, then it
  // can not be treated as "input" for cumulative command. This most probably
  // indicates that one child command creates intermediate file, that other
  // child command uses.
  for (const auto& file_path_and_info : input_files_) {
    if (output_files_.count(file_path_and_info.first) == 0 &&
        removed_rel_paths_.count(file_path_and_info.first) == 0) {
      result.push_back(file_path_and_info.second);
    }
  }
  return result;
}

std::unique_ptr<rules_mappers::CachedExecutionResponse>
    CumulativeExecutionResponseBuilder::BuildExecutionResponse() {
  std::vector<rules_mappers::FileInfo> output_files;
  output_files.reserve(output_files_.size());
  for (const auto& file_path_and_info : output_files_) {
    if (removed_rel_paths_.count(file_path_and_info.first) == 0)
      output_files.push_back(file_path_and_info.second);
  }
  return std::unique_ptr<rules_mappers::CachedExecutionResponse>(
      new rules_mappers::CachedExecutionResponse(
          output_files,
          std::vector<boost::filesystem::path>(
              removed_rel_paths_.begin(), removed_rel_paths_.end()),
          exit_code_,
          stdout_content_id_,
          stderr_content_id_));
}

bool CumulativeExecutionResponseBuilder::IsComplete() const {
  return parent_completed_ && running_child_ids_.empty();
}

void CumulativeExecutionResponseBuilder::ChildProcessCreated(int command_id) {
  running_child_ids_.insert(command_id);
}

void CumulativeExecutionResponseBuilder::AddFileSets(
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  for (const auto& file_info : input_files) {
    input_files_.insert(std::make_pair(file_info.rel_file_path, file_info));
  }
  for (const auto& file_info : execution_response.output_files) {
    output_files_.insert(std::make_pair(file_info.rel_file_path, file_info));
  }
  removed_rel_paths_.insert(
      execution_response.removed_rel_paths.begin(),
      execution_response.removed_rel_paths.end());
}
