// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_IN_MEMORY_RULES_MAPPER_H_
#define STEXECUTOR_IN_MEMORY_RULES_MAPPER_H_

#include "stexecutor/rules_mapper.h"

class InMemoryRulesMapper : public RulesMapper {
 public:
  InMemoryRulesMapper();
  ~InMemoryRulesMapper();

  std::unique_ptr<CachedExecutionResponse> FindCachedResults(
      const ProcessCreationRequest& process_creation_request,
      const BuildDirectoryState& build_dir_state) override;
  void AddRule(
      const ProcessCreationRequest& process_creation_request,
      const std::vector<FileInfo>& input_files,
      std::unique_ptr<CachedExecutionResponse> response) override;

 private:
  class ProcessCreationRequestResults;
  using HashValue = uint8_t[16];
  static HashValue ComputeProcessCreationHash(
      const ProcessCreationRequest& process_creation_request);
  std::unordered_map<
      HashValue, std::unique_ptr<ProcessCreationRequestResults>> rules_;
};

#endif  // STEXECUTOR_IN_MEMORY_RULES_MAPPER_H_
