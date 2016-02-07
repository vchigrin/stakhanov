// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_IN_MEMORY_REQUEST_RESULTS_H_
#define STEXECUTOR_RULES_MAPPERS_IN_MEMORY_REQUEST_RESULTS_H_

#include "stexecutor/rules_mappers/file_info.h"
#include "stexecutor/rules_mappers/file_set.h"
#include "stexecutor/rules_mappers/rules_hashing.h"

#include <memory>
#include <unordered_map>

class BuildDirectoryState;

namespace rules_mappers {

struct CachedExecutionResponse;

class InMemoryRequestResults {
 public:
  void AddRule(
      std::vector<FileInfo> input_files,
      std::unique_ptr<CachedExecutionResponse> response);
  const CachedExecutionResponse* FindCachedResults(
      const BuildDirectoryState& build_dir_state);

 private:
  using FileSetHashToResponse = std::unordered_map<
      HashValue,
      std::unique_ptr<CachedExecutionResponse>,
      HashValueHasher>;

  std::unordered_map<FileSet, FileSetHashToResponse, FileSetHash> responses_;
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_IN_MEMORY_REQUEST_RESULTS_H_
