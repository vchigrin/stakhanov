// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_REQUEST_RESULTS_BASE_H_
#define STEXECUTOR_RULES_MAPPERS_REQUEST_RESULTS_BASE_H_

#include <memory>
#include <vector>

class BuildDirectoryState;

namespace rules_mappers {

struct CachedExecutionResponse;
struct FileInfo;
class FileSet;

class RequestResultsBase {
 public:
  virtual ~RequestResultsBase();
  virtual void AddRule(
      const std::vector<FileInfo>& input_files,
      std::unique_ptr<CachedExecutionResponse> response) = 0;
  virtual std::unique_ptr<CachedExecutionResponse> FindCachedResults(
      const BuildDirectoryState& build_dir_state,
      std::vector<FileInfo>* input_files) = 0;

 protected:
  bool FileSetMatchesBuildState(
      const FileSet& file_set,
      const BuildDirectoryState& build_dir_state);
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_REQUEST_RESULTS_BASE_H_

