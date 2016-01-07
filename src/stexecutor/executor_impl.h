// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTOR_IMPL_H_
#define STEXECUTOR_EXECUTOR_IMPL_H_

#include <memory>
#include <string>

#include "gen-cpp/Executor.h"

class DllInjector;

class ExecutorImpl : public ExecutorIf {
 public:
  explicit ExecutorImpl(std::unique_ptr<DllInjector> dll_injector);
  bool HookedCreateFile(
      const std::string& abs_path, const bool for_writing) override;
  void HookedCloseFile(const std::string& abs_path) override;
  void OnSuspendedProcessCreated(
      const int32_t current_pid, const int32_t child_pid) override;

 private:
  std::unique_ptr<DllInjector> dll_injector_;
};

#endif  // STEXECUTOR_EXECUTOR_IMPL_H_
