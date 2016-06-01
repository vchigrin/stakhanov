// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTOR_IMPL_H_
#define STEXECUTOR_EXECUTOR_IMPL_H_

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "base/scoped_handle.h"
#include "gen-cpp/Executor.h"
#include "stexecutor/executed_command_info.h"

class DllInjector;
class ExecutingEngine;
class ExecutorFactory;
class FilesFilter;

class ExecutorImpl : public ExecutorIf {
 public:
  ExecutorImpl(
      DllInjector* dll_injector,
      ExecutingEngine* executing_engine,
      ExecutorFactory* executor_factory,
      FilesFilter* outputs_filter);
  int32_t InitializeMainExecutor(
      const int32_t current_pid, const bool is_root_process) override;
  void InitializeHelperExecutor(
      const int32_t main_executor_command_id) override;
  void GetProcessConfig(ProcessConfigInfo& result) override;
  bool HookedCreateFile(
      const std::string& abs_path, const bool for_writing) override;
  void HookedRenameFile(
      const std::string& old_name_str,
      const std::string& new_name_str) override;
  void PushStdOutput(
      const StdHandles::type handle, const std::string& data) override;
  void OnBeforeProcessCreate(
      CacheHitInfo& result,
      const std::string& exe_path,
      const std::vector<std::string>& arguments,
      const std::string& startup_dir,
      const std::string& environment_hash) override;
  void OnSuspendedProcessCreated(
      const int32_t child_pid,
      const int32_t child_main_thread_id,
      const int32_t executor_command_id,
      const bool append_std_streams,
      const bool leave_suspended) override;
  void OnFileDeleted(const std::string& abs_path) override;
  void OnBeforeExitProcess() override;
  void FillExitCode();
  const ExecutedCommandInfo& command_info() const {
    return command_info_;
  }
  int command_id() const {
    return command_info_.command_id;
  }
  void set_dump_env_dir(const boost::filesystem::path& dump_env_dir) {
    dump_env_dir_ = dump_env_dir;
  }

 private:
  void FillFileInfos();
  void DumpEnvIfNeed(
      const std::string& env_hash,
      const std::vector<std::string>& sorted_env);

  DllInjector* dll_injector_;
  ExecutingEngine* executing_engine_;
  ExecutorFactory* executor_factory_;
  FilesFilter* files_filter_;
  ExecutedCommandInfo command_info_;
  using FilePathSet = std::unordered_set<
      boost::filesystem::path, base::FilePathHash>;
  using FilePathMap = std::unordered_map<
      boost::filesystem::path, rules_mappers::FileInfo, base::FilePathHash>;

  FilePathMap input_files_;
  FilePathSet output_files_;
  FilePathSet removed_files_;
  base::ScopedHandle process_handle_;
  // List of Executors, related to parent processes, that share same
  // stdout and stderr handles.
  std::vector<std::shared_ptr<ExecutorImpl>>
      executors_should_append_std_streams_;
  // PushStdOutput can be called from alien thread because of
  // Child-Parent std streams sharing. So we use mutex to protect it.
  std::mutex std_handles_lock_;
  boost::filesystem::path dump_env_dir_;
  bool files_infos_filled_;
  ProcessConfigInfo process_config_info_;
  bool is_helper_executor_;
};

#endif  // STEXECUTOR_EXECUTOR_IMPL_H_
