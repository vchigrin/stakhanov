// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_creation_request.h"

ProcessCreationRequest::ProcessCreationRequest(
    const std::string& exe_path,
    const std::string& startup_directory,
    const std::vector<std::string>& command_line,
    const std::unordered_set<std::string>& environment_strings)
    : exe_path_(exe_path),
      startup_directory_(startup_directory),
      command_line_(command_line),
      environment_strings_(environment_strings) {
}

size_t ProcessCreationRequest::ComputeHashCode() const {
  size_t result = std::hash(exe_path_);
  result ^= std::hash(startup_directory_);
  for (const std::string& command_argument : command_line_) {
    result ^= std::hash(command_argument);
  }
  for (const std::sttring& env_string : environment_strings_) {
    result ^= std::hash(env_string);
  }
  return result;
}
