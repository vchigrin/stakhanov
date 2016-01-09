// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTOR_FACTORY_H_
#define STEXECUTOR_EXECUTOR_FACTORY_H_

#include <condition_variable>
#include <memory>
#include <mutex>
#include <vector>

#include "gen-cpp/Executor.h"
#include "stexecutor/command_info.h"

class DllInjector;

class ExecutorFactory : public ExecutorIfFactory {
 public:
  explicit ExecutorFactory(std::unique_ptr<DllInjector> dll_injector);
  ExecutorIf* getHandler(
      const ::apache::thrift::TConnectionInfo& connInfo) override;
  void releaseHandler(ExecutorIf* handler) override;

  const std::vector<CommandInfo>& FinishAndGetCommandsInfo();

 private:
  std::unique_ptr<DllInjector> dll_injector_;
  std::vector<CommandInfo> commands_info_;
  int active_handlers_count_;
  std::condition_variable handler_released_;
  std::mutex instance_lock_;
};

#endif  // STEXECUTOR_EXECUTOR_FACTORY_H_
