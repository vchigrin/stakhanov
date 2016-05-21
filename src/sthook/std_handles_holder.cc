// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/std_handles_holder.h"

#include <unordered_set>

StdHandlesHolder* StdHandlesHolder::instance_;

class StdHandlesHolder::HolderImpl {
 public:
  explicit HolderImpl(StdHandles::type holder_type)
    : holder_type_(holder_type) { }

  bool IsStdHandle(HANDLE handle, StdHandles::type* handle_type) {
    if (handles_.count(handle) != 0) {
      *handle_type = holder_type_;
      return true;
    }
    return false;
  }

  void SetStdHandle(StdHandles::type handle_type, HANDLE handle) {
    // All members of the set contain handles for the same kernel object.
    // So replacing std output / error output with different kernel object
    // should causereplacing the whole set.
    if (handle_type == holder_type_) {
      if (handles_.count(handle) == 0) {
        handles_.clear();
        handles_.insert(handle);
      }
    }
  }

  void MarkDuplicatedHandle(HANDLE existed_handle, HANDLE new_handle) {
    if (handles_.count(existed_handle))
      handles_.insert(new_handle);
  }

  void MarkHandleClosed(HANDLE handle) {
    auto it = handles_.find(handle);
    if (it != handles_.end())
      handles_.erase(it);
  }

 private:
  const StdHandles::type holder_type_;
  std::unordered_set<HANDLE> handles_;
};

// static
void StdHandlesHolder::Initialize() {
  instance_ = new StdHandlesHolder();
  instance_->Initialize(
      GetStdHandle(STD_OUTPUT_HANDLE),
      GetStdHandle(STD_ERROR_HANDLE));
}

void StdHandlesHolder::Initialize(
    HANDLE original_output_handle, HANDLE original_error_handle) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  std_output_holder_->SetStdHandle(
      StdHandles::StdOutput, original_output_handle);
  std_error_holder_->SetStdHandle(
      StdHandles::StdError, original_error_handle);
}

StdHandlesHolder::StdHandlesHolder()
  : std_output_holder_(new HolderImpl(StdHandles::StdOutput)),
    std_error_holder_(new HolderImpl(StdHandles::StdError)) {
}

StdHandlesHolder::~StdHandlesHolder() {}

bool StdHandlesHolder::IsStdHandle(
    HANDLE handle, StdHandles::type* handle_type) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  return std_output_holder_->IsStdHandle(handle, handle_type) ||
      std_error_holder_->IsStdHandle(handle, handle_type);
}

void StdHandlesHolder::MarkDuplicatedHandle(
    HANDLE existed_handle, HANDLE new_handle) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  std_output_holder_->MarkDuplicatedHandle(existed_handle, new_handle);
  std_error_holder_->MarkDuplicatedHandle(existed_handle, new_handle);
}

void StdHandlesHolder::MarkHandleClosed(HANDLE handle) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  std_output_holder_->MarkHandleClosed(handle);
  std_error_holder_->MarkHandleClosed(handle);
}
