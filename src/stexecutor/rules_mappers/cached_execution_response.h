// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_CACHED_EXECUTION_RESPONSE_H_
#define STEXECUTOR_RULES_MAPPERS_CACHED_EXECUTION_RESPONSE_H_

#include <string>
#include <vector>

#include "stexecutor/rules_mappers/file_info.h"

namespace rules_mappers {

struct CachedExecutionResponse {
  CachedExecutionResponse(
      const std::vector<FileInfo>& output_files,
      int exit_code,
      const std::string& result_stdout,
      const std::string& result_stderr)
      : output_files(output_files),
        exit_code(exit_code),
        result_stdout(result_stdout),
        result_stderr(result_stderr) {}

  std::vector<FileInfo> output_files;
  int exit_code;
  std::string result_stdout;
  std::string result_stderr;
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_CACHED_EXECUTION_RESPONSE_H_
