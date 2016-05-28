// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_TIMED_BLOCK_H_
#define BASE_TIMED_BLOCK_H_

#include <windows.h>

#include <chrono>
#include <sstream>
#include <string>

namespace base {

class TimedBlock {
 public:
  explicit TimedBlock(const std::string& description)
      : description_(description),
        start_(std::chrono::high_resolution_clock::now()) {
  }

  ~TimedBlock() {
    auto end = std::chrono::high_resolution_clock::now();
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(
        end - start_);
    std::stringstream msg;
    msg << description_ << " took " << microseconds.count() << " mcs.";
    OutputDebugStringA(msg.str().c_str());
  }

 private:
  std::string description_;
  std::chrono::high_resolution_clock::time_point start_;
};

}  // namespace base

#endif  // BASE_TIMED_BLOCK_H_
