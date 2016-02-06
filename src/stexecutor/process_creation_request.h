// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_PROCESS_CREATION_REQUEST_H_
#define STEXECUTOR_PROCESS_CREATION_REQUEST_H_

#include <string>
#include <vector>

// NOTE: all passed in paths must already be normalized,
// and have already stripped build_root directory.
class ProcessCreationRequest {
 public:
  ProcessCreationRequest(
      const std::string& exe_path,
      const std::string& startup_directory,
      const std::vector<std::string>& command_line,
      const std::vector<std::string>& environment_strings);

  const std::string& exe_path() const {
    return exe_path_;
  }

  const std::string& startup_directory() const {
    return startup_directory_;
  }

  const std::vector<std::string>& command_line() const {
    return command_line_;
  }

  const std::vector<std::string>& sorted_environment_strings() const {
    return sorted_environment_strings_;
  }

  size_t ComputeHashCode() const;

 private:
  std::string exe_path_;
  std::string startup_directory_;
  std::vector<std::string> command_line_;
  std::vector<std::string> sorted_environment_strings_;
};

#endif  // STEXECUTOR_PROCESS_CREATION_REQUEST_H_

