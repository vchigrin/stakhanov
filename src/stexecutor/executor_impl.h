// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTOR_IMPL_H_
#define STEXECUTOR_EXECUTOR_IMPL_H_

#include <memory>
#include <string>

#include "base/scoped_handle.h"
#include "gen-cpp/Executor.h"
#include "stexecutor/command_info.h"

class DllInjector;

class ExecutorImpl : public ExecutorIf {
 public:
  explicit ExecutorImpl(DllInjector* dll_injector);
  bool HookedCreateFile(
      const std::string& abs_path, const bool for_writing) override;
  void HookedCloseFile(const std::string& abs_path) override;
  void Initialize(
      const int32_t current_pid,
      const std::string& command_line,
      const std::string& startup_directory) override;
  void OnSuspendedProcessCreated(const int32_t child_pid) override;
  void FillExitCode();
  const CommandInfo& command_info() const {
    return command_info_;
  }

 private:
  DllInjector* dll_injector_;
  CommandInfo command_info_;
  base::ScopedHandle process_handle_;
};

#endif  // STEXECUTOR_EXECUTOR_IMPL_H_
