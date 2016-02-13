// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_factory.h"

#include "stexecutor/dll_injector.h"
#include "stexecutor/executor_impl.h"

ExecutorFactory::ExecutorFactory(
    std::unique_ptr<DllInjector> dll_injector,
    ExecutingEngine* executing_engine)
    : dll_injector_(std::move(dll_injector)),
      executing_engine_(executing_engine),
      active_handlers_count_(0) {
}

ExecutorIf* ExecutorFactory::getHandler(
    const ::apache::thrift::TConnectionInfo& connInfo) {
  {
    std::unique_lock<std::mutex> lock(instance_lock_);
    ++active_handlers_count_;
  }
  return new ExecutorImpl(dll_injector_.get(), executing_engine_);
}

void ExecutorFactory::releaseHandler(ExecutorIf* handler) {
  ExecutorImpl* executor = static_cast<ExecutorImpl*>(handler);
  executor->FillExitCode();
  {
    delete executor;
    --active_handlers_count_;
    handler_released_.notify_all();
  }
}

void ExecutorFactory::Finish() {
  while (true) {
    std::unique_lock<std::mutex> lock(instance_lock_);
    if (active_handlers_count_ == 0)
      break;
    handler_released_.wait(lock);
  }
}
