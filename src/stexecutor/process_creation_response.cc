// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_creation_response.h"

// static
ProcessCreationResponse ProcessCreationResponse::BuildCacheMissResponse(
    int command_id) {
  return ProcessCreationResponse(
      command_id,
      false,
      0,
      std::string(),
      std::string());
}

// static
ProcessCreationResponse ProcessCreationResponse::BuildCacheHitResponse(
    int command_id,
    int exit_code,
    const std::string& result_stdout,
    const std::string& result_stderr) {
  return ProcessCreationResponse(
      command_id,
      true,
      exit_code,
      result_stdout,
      result_stderr);
}

ProcessCreationResponse::ProcessCreationResponse(
    int real_command_id,
    bool is_cache_hit,
    int exit_code,
    const std::string& result_stdout,
    const std::string& result_stderr)
    : real_command_id_(real_command_id),
      is_cache_hit_(is_cache_hit),
      exit_code_(exit_code),
      result_stdout_(result_stdout),
      result_stderr_(result_stderr) {
}
