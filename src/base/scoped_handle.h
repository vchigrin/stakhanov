// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_SCOPED_HANDLE_H_
#define BASE_SCOPED_HANDLE_H_

#include <windows.h>

namespace base {

class ScopedHandle {
 public:
  ScopedHandle()
    : value_(NULL) {
  }

  explicit ScopedHandle(HANDLE value)
    : value_(value) {
  }

  ScopedHandle(ScopedHandle&& second)
    : value_(second.Release()) {
  }

  ScopedHandle(const ScopedHandle&) = delete;

  ~ScopedHandle() {
    Close();
  }

  ScopedHandle& operator=(ScopedHandle&& second) {
    Close();
    value_ = second.Release();
    return *this;
  }

  ScopedHandle& operator=(const ScopedHandle&) = delete;

  HANDLE Get() const {
    return value_;
  }

  HANDLE Release() {
    HANDLE result = value_;
    value_ = NULL;
    return result;
  }

  bool IsValid() const {
    return value_ != NULL && value_ != INVALID_HANDLE_VALUE;
  }

  void Close() {
    if (IsValid())
      ::CloseHandle(value_);
    value_ = NULL;
  }

  HANDLE* Receive() {
    Close();
    return &value_;
  }

 private:
  HANDLE value_;
};

}  // namespace base

#endif  // BASE_SCOPED_HANDLE_H_

