// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPER_H_
#define STEXECUTOR_RULES_MAPPER_H_

#include <vector>
#include "boost/filesystem.hpp"

struct FileInfo {
  FileInfo(const boost::filesystem::path& rel_file_path,
           const std::string& storage_content_id)
      : rel_file_path(rel_file_path),
        storage_content_id(storage_content_id) {}

  boost::filesystem::path rel_file_path;
  std::string storage_content_id;
};

struct CachedExecutionResponse {
  CachedExecutionResponse(
      const std::vector<fileinfo>& output_files,
      int exit_code,
      const std::string& result_stdout,
      const std::string& result_stderr)
      : output_files(output_files),
        exit_code(exit_code),
        result_stdout(result_stdout),
        result_stderr(result_stderr) {}

  std::vector<fileinfo> output_files;
  int exit_code;
  std::string result_stdout;
  std::string result_stderr;
};

class RulesMapper {
 public:
  virtual ~RulesMapper() {}
  virtual std::unique_ptr<CachedExecutionResponse> FindCachedResults(
      const ProcessCreationRequest& process_creation_request,
      const BuildDirectoryState& build_dir_state) = 0;
  virtual void AddRule(
      const ProcessCreationRequest& process_creation_request,
      const std::vector<FileInfo>& input_files,
      std::unique_ptr<CachedExecutionResponse> response) = 0;
};

#endif  // STEXECUTOR_RULES_MAPPER_H_
