// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_CUMULATIVE_EXECUTION_RESPONSE_BUILDER_H_
#define STEXECUTOR_CUMULATIVE_EXECUTION_RESPONSE_BUILDER_H_

#include <memory>
#include <string>
#include <unordered_set>
#include <vector>

#include "stexecutor/rules_mappers/file_info.h"

namespace rules_mappers {
struct CachedExecutionResponse;
}

class ProcessCreationRequest;

class CumulativeExecutionResponseBuilder {
 public:
  CumulativeExecutionResponseBuilder();
  void SetParentExecutionResponse(
       const ProcessCreationRequest& request,
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

 private:
  void AddFileSets(
      const std::vector<rules_mappers::FileInfo>& input_files,
      const std::vector<rules_mappers::FileInfo>& output_files);

  using FileInfoSet = std::unordered_set<
      rules_mappers::FileInfo,
      rules_mappers::FileInfoHasher>;
  FileInfoSet input_files_;
  FileInfoSet output_files_;
  int exit_code_;
  bool parent_completed_;
  std::unordered_set<int> running_child_ids_;
  std::string stdout_content_id_;
  std::string stderr_content_id_;
};

#endif  // STEXECUTOR_CUMULATIVE_EXECUTION_RESPONSE_BUILDER_H_
