// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_COMMAND_INFO_H_
#define STEXECUTOR_COMMAND_INFO_H_

#include <string>
#include <vector>

struct CommandInfo {
  int exit_code;
  int id;
  std::string startup_directory;
  std::string command_line;
  std::vector<std::string> input_files;
  std::vector<std::string> output_files;
  std::vector<int> child_command_ids;
  std::string result_stdout;
  std::string result_stderr;
};

#endif  // STEXECUTOR_COMMAND_INFO_H_

