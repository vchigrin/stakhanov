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
    const ProcessCreationRequest& request,
    bool should_ignore_std_streams_from_children,
    CumulativeExecutionResponseBuilder* ancestor)
    : exit_code_(0),
      own_process_completed_(false),
      is_failed_(false),
      command_id_(command_id),
      ancestor_(ancestor),
      process_creation_request_(request),
      should_append_std_streams_to_parent_(false),
      should_ignore_std_streams_from_children_(
          should_ignore_std_streams_from_children) {
}

void CumulativeExecutionResponseBuilder::SetOwnExecutionResponse(
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  LOG4CPLUS_ASSERT(logger_, !own_process_completed_);
  own_process_completed_ = true;
  exit_code_ = execution_response.exit_code;
  stdout_content_id_ = execution_response.stdout_content_id;
  stderr_content_id_ = execution_response.stderr_content_id;
  AddFileSets(input_files, execution_response);
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
    // Save output file even if it present in removed set.
    // This is neccessary since NaCl build_nexe.py script removes existing
    // files before build. At present we do not take into account timestamps,
    // so without this we will lost valuable outputs.
    // TODO(vchigrin): We have to re-design whole this stuff, and should handle
    // all these cases correctly
    // Case A:
    // 1. Parent process deletes foo.obj
    // 2. Child process creates foo.obj
    // Case B:
    // 1. Child process created foo.tmp
    // 2. Parent process deletes foo.tmp
    // Case C:
    // 1. Child process created foo.dat
    // 2. Parent process moved foo.dat to bar.dat

    removed_rel_paths_.erase(file_path_and_info.first);
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
  return own_process_completed_ && running_child_ids_.empty();
}

void CumulativeExecutionResponseBuilder::ChildProcessCreated(int command_id) {
  running_child_ids_.insert(command_id);
}

void CumulativeExecutionResponseBuilder::MarkChildCommandFailed(
    int command_id) {
  is_failed_ = true;
  LOG4CPLUS_ASSERT(logger_, command_id != ExecutingEngine::kCacheHitCommandId);
  auto it = running_child_ids_.find(command_id);
  LOG4CPLUS_ASSERT(logger_, it != running_child_ids_.end());
  if (it != running_child_ids_.end())
    running_child_ids_.erase(it);
}

void CumulativeExecutionResponseBuilder::AddFileSets(
    const std::vector<rules_mappers::FileInfo>& input_files,
    const rules_mappers::CachedExecutionResponse& execution_response) {
  for (const auto& file_info : input_files) {
    input_files_.insert(std::make_pair(file_info.rel_file_path, file_info));
  }
  for (const auto& file_info : execution_response.output_files) {
    // Allow later completed commands overwrite inputs for previous.
    // E.g. cumulative command for protoc_wrapper.py from Chromium build
    // will have save output paths for resulting .h file, but with different
    // content IDs (since python script overwrites protoc.exe output).
    auto it = output_files_.find(file_info.rel_file_path);
    if (it == output_files_.end() ||
        it->second.construction_time < file_info.construction_time) {
      output_files_[file_info.rel_file_path] = file_info;
    }
  }
  removed_rel_paths_.insert(
      execution_response.removed_rel_paths.begin(),
      execution_response.removed_rel_paths.end());
}
