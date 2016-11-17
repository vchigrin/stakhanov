// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_RULES_MAPPER_H_
#define STEXECUTOR_RULES_MAPPERS_RULES_MAPPER_H_

#include <memory>
#include <vector>

class BuildDirectoryState;
class ProcessCreationRequest;

namespace rules_mappers {

struct FileInfo;
struct CachedExecutionResponse;

// It is assumed that this class is thread-safe.
class RulesMapper {
 public:
  virtual ~RulesMapper() {}
  virtual std::unique_ptr<CachedExecutionResponse> FindCachedResults(
      const ProcessCreationRequest& process_creation_request,
      const BuildDirectoryState& build_dir_state,
      std::vector<FileInfo>* input_files) = 0;
  virtual void AddRule(
      const ProcessCreationRequest& process_creation_request,
      std::vector<FileInfo>&& input_files,
      std::unique_ptr<CachedExecutionResponse> response) = 0;
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_RULES_MAPPER_H_
