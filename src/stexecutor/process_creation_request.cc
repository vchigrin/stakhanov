// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_creation_request.h"

ProcessCreationRequest::ProcessCreationRequest(
    const boost::filesystem::path& exe_path,
    const boost::filesystem::path& startup_directory,
    const std::vector<std::string>& command_line,
    const std::vector<std::string>& environment_strings)
    : exe_path_(exe_path),
      startup_directory_(startup_directory),
      command_line_(command_line),
      sorted_environment_strings_(environment_strings) {
  std::sort(
      sorted_environment_strings_.begin(), sorted_environment_strings_.end());
}
