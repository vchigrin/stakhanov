// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_COMMAND_INFO_H_
#define STEXECUTOR_COMMAND_INFO_H_

#include <string>
#include <vector>
#include <unordered_set>

struct ExecutedCommandInfo {
  int exit_code;
  int command_id;
  std::unordered_set<boost::filesystem::path> input_files;
  std::unordered_set<boost::filesystem::path> output_files;
  std::vector<int> child_command_ids;
  std::string result_stdout;
  std::string result_stderr;
};

#endif  // STEXECUTOR_COMMAND_INFO_H_

