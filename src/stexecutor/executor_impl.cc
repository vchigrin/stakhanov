// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/executor_impl.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/dll_injector.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ExecutorImpl");

}  // namespace

ExecutorImpl::ExecutorImpl(std::unique_ptr<DllInjector> dll_injector)
    : dll_injector_(std::move(dll_injector))  {
}

bool ExecutorImpl::HookedCreateFile(
    const std::string& abs_path, const bool for_writing) {
  LOG4CPLUS_INFO(logger_, "Created file " << abs_path.c_str());
  return true;
}

void ExecutorImpl::HookedCloseFile(const std::string& abs_path) {
  LOG4CPLUS_INFO(logger_, "Closed file " << abs_path.c_str());
}

void ExecutorImpl::OnSuspendedProcessCreated(
    const int32_t current_pid, const int32_t child_pid) {
  LOG4CPLUS_INFO(
      logger_, "Created process " << child_pid << " from " << current_pid);
  if (!dll_injector_->InjectInto(child_pid)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed inject dll into process " << child_pid);
  }
}
