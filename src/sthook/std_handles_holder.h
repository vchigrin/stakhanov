// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STHOOK_STD_HANDLES_HOLDER_H_
#define STHOOK_STD_HANDLES_HOLDER_H_

#include <windows.h>

#include <mutex>

#include "gen-cpp/Executor.h"

class StdHandlesHolder {
 public:
  static StdHandlesHolder* GetInstance() {
    return instance_;
  }
  static void Initialize();
  bool IsStdHandle(HANDLE handle, StdHandles::type* handle_type);
  void SetStdHandle(StdHandles::type handle_type, HANDLE handle);
  void MarkDuplicatedHandle(HANDLE existed_handle, HANDLE new_handle);
  void MarkHandleClosed(HANDLE handle);
  // Returns true if handles, that were active at process creation
  // (stdout and stderr) are still present in set of handles representing
  // std streams. Need for tracking "append std streams" flag.
  bool AreOriginalHandlesActive();

 private:
  StdHandlesHolder();
  ~StdHandlesHolder();
  void Initialize(HANDLE original_output_handle, HANDLE original_error_handle);

  static StdHandlesHolder* instance_;
  class HolderImpl;

  std::mutex instance_lock_;
  std::unique_ptr<HolderImpl> std_output_holder_;
  std::unique_ptr<HolderImpl> std_error_holder_;
  HANDLE original_output_handle_;
  HANDLE original_error_handle_;
};

#endif  // STHOOK_STD_HANDLES_HOLDER_H_

