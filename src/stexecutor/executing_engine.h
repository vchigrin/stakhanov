// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTING_ENGINE_H_
#define STEXECUTOR_EXECUTING_ENGINE_H_

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include "base/scoped_handle.h"
#include "boost/filesystem.hpp"
#include "stexecutor/executed_command_info.h"

class BuildDirectoryState;
class ProcessCreationRequest;
class ProcessCreationResponse;
class FilesStorage;

namespace rules_mappers {
class RulesMapper;
}

// Thread-safe class, incapsulating main decision-making
// logic about executing child commands.
class ExecutingEngine {
 public:
  ExecutingEngine(
      std::unique_ptr<FilesStorage> files_storage,
      std::unique_ptr<rules_mappers::RulesMapper> rules_mapper,
      std::unique_ptr<BuildDirectoryState> build_dir_state);
  ~ExecutingEngine();

  ProcessCreationResponse AttemptCacheExecute(
      const ProcessCreationRequest& resuest);
  void SaveCommandResults(const ExecutedCommandInfo& command_info);
  void AssociatePIDWithCommandId(int32_t pid, int command_id);
  int TakeCommandIDForPID(int32_t pid);

 private:
  std::mutex instance_lock_;

  std::unique_ptr<FilesStorage> files_storage_;
  std::unique_ptr<rules_mappers::RulesMapper> rules_mapper_;
  std::unique_ptr<BuildDirectoryState> build_dir_state_;
  std::unordered_map<
      int, std::unique_ptr<ProcessCreationRequest>> running_commands_;
  std::unordered_map<int32_t, int> pid_to_command_id_;
  int next_command_id_;
};

#endif  // STEXECUTOR_EXECUTING_ENGINE_H_
