// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_factory.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executor_impl.h"
#include "stexecutor/files_filter.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutorFactory");

}  // namespace

ExecutorFactory::ExecutorFactory(
    std::unique_ptr<DllInjector> dll_injector,
    ExecutingEngine* executing_engine,
    std::unique_ptr<FilesFilter> files_filter)
    : dll_injector_(std::move(dll_injector)),
      executing_engine_(executing_engine),
      active_handlers_count_(0),
      files_filter_(std::move(files_filter)) {
}

ExecutorIf* ExecutorFactory::getHandler(
    const ::apache::thrift::TConnectionInfo& connInfo) {
  {
    std::lock_guard<std::mutex> lock(instance_lock_);
    ++active_handlers_count_;
  }
  ExecutorImpl* result = new ExecutorImpl(
      dll_injector_.get(), executing_engine_, this, files_filter_.get());
  result->set_dump_env_dir(dump_env_dir_);
  return result;
}

void ExecutorFactory::releaseHandler(ExecutorIf* handler) {
  ExecutorImpl* executor = static_cast<ExecutorImpl*>(handler);
  executor->FillExitCode();
  {
    std::lock_guard<std::mutex> lock(instance_lock_);
    auto it = active_executors_.find(executor->command_id());
    if (it != active_executors_.end() &&
       // Now it is OK to have multiple executors with same command id,
       // but only main executor registered in active_executors_.
       it->second.get() == executor) {
      active_executors_.erase(it);
    } else {
      // This executor is not "registered" so
      // it was not shared with anybody.
      delete executor;
    }
    --active_handlers_count_;
    handler_released_.notify_all();
  }
}

void ExecutorFactory::RegisterExecutor(int command_id, ExecutorImpl* instance) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  LOG4CPLUS_ASSERT(
      logger_, active_executors_.find(command_id) == active_executors_.end());
  active_executors_.insert(std::make_pair(
      command_id, std::shared_ptr<ExecutorImpl>(instance)));
}

std::vector<std::shared_ptr<ExecutorImpl>> ExecutorFactory::GetExecutors(
    const std::vector<int>& command_ids) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  std::vector<std::shared_ptr<ExecutorImpl>> result;
  result.reserve(command_ids.size());
  for (int command_id : command_ids) {
    auto it = active_executors_.find(command_id);
    if (it != active_executors_.end()) {
      result.push_back(it->second);
    } else {
      LOG4CPLUS_WARN(
          logger_, "Failed find executor for command " << command_id);
    }
  }
  return result;
}

void ExecutorFactory::Finish() {
  while (true) {
    std::unique_lock<std::mutex> lock(instance_lock_);
    if (active_handlers_count_ == 0)
      break;
    handler_released_.wait(lock);
  }
}
