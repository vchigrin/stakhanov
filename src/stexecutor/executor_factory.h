// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_EXECUTOR_FACTORY_H_
#define STEXECUTOR_EXECUTOR_FACTORY_H_

#include <condition_variable>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "gen-cpp/Executor.h"

class DllInjector;
class ExecutingEngine;
class ExecutorImpl;

class ExecutorFactory : public ExecutorIfFactory {
 public:
  ExecutorFactory(
      std::unique_ptr<DllInjector> dll_injector,
      ExecutingEngine* executing_engine);
  ExecutorIf* getHandler(
      const ::apache::thrift::TConnectionInfo& connInfo) override;
  void releaseHandler(ExecutorIf* handler) override;
  void Finish();
  void RegisterExecutor(int command_id, ExecutorImpl* instance);
  std::vector<std::shared_ptr<ExecutorImpl>> GetExecutors(
      const std::vector<int>& command_ids);

 private:
  std::unique_ptr<DllInjector> dll_injector_;
  ExecutingEngine* executing_engine_;
  int active_handlers_count_;
  std::condition_variable handler_released_;
  std::mutex instance_lock_;
  std::unordered_map<int, std::shared_ptr<ExecutorImpl>> active_executors_;
};

#endif  // STEXECUTOR_EXECUTOR_FACTORY_H_
