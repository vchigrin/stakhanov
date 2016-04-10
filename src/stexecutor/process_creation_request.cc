// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_creation_request.h"
#include "base/string_utils.h"

ProcessCreationRequest::ProcessCreationRequest(
    const boost::filesystem::path& exe_path,
    const boost::filesystem::path& startup_directory,
    const std::vector<std::string>& command_line,
    const std::string& environment_hash)
    : exe_path_(exe_path),
      startup_directory_(startup_directory),
      command_line_(command_line),
      environment_hash_(environment_hash) {
}


std::wostream& operator << (
    std::wostream& stream, const ProcessCreationRequest& request) {
  for (const std::string& str : request.command_line()) {
    stream << base::ToWideFromUTF8(str) << L" ";
  }
  return stream;
}
