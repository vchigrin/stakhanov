// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTING_ENGINE_H_
#define STEXECUTOR_EXECUTING_ENGINE_H_

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/scoped_handle.h"
#include "boost/filesystem.hpp"
#include "stexecutor/executed_command_info.h"

class BuildDirectoryState;
class CumulativeExecutionResponseBuilder;
class ProcessCreationRequest;
class ProcessCreationResponse;
class FilesStorage;

namespace rules_mappers {
class RulesMapper;
struct CachedExecutionResponse;
struct FileInfo;
}

// Thread-safe class, incapsulating main decision-making
// logic about executing child commands.
class ExecutingEngine {
 public:
  enum SpecialCommandIds {
    kInvalidCommandId =-1,
    kCacheHitCommandId,
    kRootCommandId,
    // Must be the last member of enum.
    kFirstUserCommandId
  };

  ExecutingEngine(
      std::unique_ptr<FilesStorage> files_storage,
      std::unique_ptr<rules_mappers::RulesMapper> rules_mapper,
      std::unique_ptr<BuildDirectoryState> build_dir_state);
  ~ExecutingEngine();

  ProcessCreationResponse AttemptCacheExecute(
      int parent_command_id,
      const ProcessCreationRequest& resuest);
  void SaveCommandResults(const ExecutedCommandInfo& command_info);
  void AssociatePIDWithCommandId(
      int parent_command_id,
      int32_t pid, int command_id,
      bool should_append_std_streams);
  void RegisterByPID(
      int32_t pid,
      int* command_id,
      std::vector<int>* command_ids_should_append_std_streams);

 private:
  std::mutex instance_lock_;

  void UpdateAllParentResponsesForCompletedChild(
      int child_command_id,
      const std::vector<rules_mappers::FileInfo>& input_files,
      const rules_mappers::CachedExecutionResponse& execution_response);

  void UpdateAllParentResponses(
      int first_parent_command_id,
      int child_command_id,
      const std::vector<rules_mappers::FileInfo>& input_files,
      const rules_mappers::CachedExecutionResponse& execution_response);

  CumulativeExecutionResponseBuilder* GetCumulativeResponseBuilder(
      int command_id);
  std::unique_ptr<FilesStorage> files_storage_;
  std::unique_ptr<rules_mappers::RulesMapper> rules_mapper_;
  std::unique_ptr<BuildDirectoryState> build_dir_state_;
  std::unordered_map<
      int, std::unique_ptr<ProcessCreationRequest>> running_commands_;
  // Contains cumulative executing response for parent command.
  std::unordered_map<
      int, std::unique_ptr<CumulativeExecutionResponseBuilder>>
          parent_command_id_to_results_;
  struct ParentInfo {
    int command_id;
    bool should_append_std_streams;
  };
  std::unordered_map<int, ParentInfo> child_command_id_to_parent_;

  std::unordered_map<int32_t, int> pid_to_command_id_;
  int next_command_id_;
};

#endif  // STEXECUTOR_EXECUTING_ENGINE_H_
