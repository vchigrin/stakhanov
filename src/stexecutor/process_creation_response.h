// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_PROCESS_CREATION_RESPONSE_H_
#define STEXECUTOR_PROCESS_CREATION_RESPONSE_H_

#include <string>

class ProcessCreationResponse {
 public:

  bool is_cache_hit() const {
    return is_cache_hit_;
  }

  // Id of the command, that should be used later to report
  // results of this command to executing engine.
  int real_command_id() const {
    return real_command_id_;
  }

  int exit_code() const {
    return exit_code_;
  }

  std::string result_stdout() const {
    return result_stdout_;
  }

  std::string result_stderr() const {
    return result_stderr_;
  }

  static ProcessCreationResponse BuildCacheMissResponse(int command_id);
  static ProcessCreationResponse BuildCacheHitResponse(
      int command_id,
      int exit_code,
      const std::string& result_stdout,
      const std::string& result_stderr);

 private:
  ProcessCreationResponse(
      int real_command_id,
      bool is_cache_hit,
      int exit_code,
      const std::string& result_stdout,
      const std::string& result_stderr);

  int real_command_id_;
  bool is_cache_hit_;
  // All further fields are valid only in case cache hit.
  int exit_code_;
  std::string result_stdout_;
  std::string result_stderr_;
};

#endif  // STEXECUTOR_PROCESS_CREATION_RESPONSE_H_
