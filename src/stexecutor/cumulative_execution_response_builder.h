// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_CUMULATIVE_EXECUTION_RESPONSE_BUILDER_H_
#define STEXECUTOR_CUMULATIVE_EXECUTION_RESPONSE_BUILDER_H_

#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "base/filesystem_utils.h"
#include "stexecutor/rules_mappers/file_info.h"
#include "stexecutor/process_creation_request.h"

namespace rules_mappers {
struct CachedExecutionResponse;
}

class ProcessCreationRequest;

class CumulativeExecutionResponseBuilder {
 public:
  CumulativeExecutionResponseBuilder(
      int command_id,
      const ProcessCreationRequest& request,
      bool should_ignore_std_streams_from_children,
      CumulativeExecutionResponseBuilder* ancestor);
  void SetOwnExecutionResponse(
       const std::vector<rules_mappers::FileInfo>& input_files,
       const rules_mappers::CachedExecutionResponse& execution_response);
  void AddChildResponse(
      int command_id,
      const std::vector<rules_mappers::FileInfo>& input_files,
      const rules_mappers::CachedExecutionResponse& execution_response);
  std::vector<rules_mappers::FileInfo> BuildAllInputFiles();
  std::unique_ptr<rules_mappers::CachedExecutionResponse>
      BuildExecutionResponse();
  bool IsComplete() const;
  void ChildProcessCreated(int command_id);
  const ProcessCreationRequest& process_creation_request() const {
    return process_creation_request_;
  }
  CumulativeExecutionResponseBuilder* ancestor() const {
    // We must not delete parent builder while child is not finshed,
    // so that pointer should be always valid.
    return ancestor_;
  }
  int command_id() const {
    return command_id_;
  }
  bool should_append_std_streams_to_parent() const {
    return should_append_std_streams_to_parent_;
  }
  void set_should_append_std_streams_to_parent(bool value) {
    should_append_std_streams_to_parent_ = value;
  }
  bool is_failed() const {
    return is_failed_;
  }
  bool should_ignore_std_streams_from_children() const {
    return should_ignore_std_streams_from_children_;\
  }

  void MarkOwnCommandFailed() {
    is_failed_ = true;
    own_process_completed_ = true;
  }

  void MarkChildCommandFailed(int command_id);

 private:
  void AddFileSets(
      const std::vector<rules_mappers::FileInfo>& input_files,
      const rules_mappers::CachedExecutionResponse& execution_response);

  using FileInfoMap = std::unordered_map<
      boost::filesystem::path,
      rules_mappers::FileInfo,
      base::FilePathHash>;
  using FilePathSet = std::unordered_set<
      boost::filesystem::path, base::FilePathHash>;
  FileInfoMap input_files_;
  FileInfoMap output_files_;
  FilePathSet removed_rel_paths_;
  int exit_code_;
  bool own_process_completed_;
  bool is_failed_;
  const int command_id_;
  CumulativeExecutionResponseBuilder* ancestor_;
  std::unordered_set<int> running_child_ids_;
  std::string stdout_content_id_;
  std::string stderr_content_id_;
  ProcessCreationRequest process_creation_request_;
  bool should_append_std_streams_to_parent_;
  bool should_ignore_std_streams_from_children_;
};

#endif  // STEXECUTOR_CUMULATIVE_EXECUTION_RESPONSE_BUILDER_H_
