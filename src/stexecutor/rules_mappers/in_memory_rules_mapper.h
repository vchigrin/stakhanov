// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_IN_MEMORY_RULES_MAPPER_H_
#define STEXECUTOR_RULES_MAPPERS_IN_MEMORY_RULES_MAPPER_H_

#include <mutex>
#include <unordered_map>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/serialization/serialization.hpp"
#include "stexecutor/rules_mappers/rules_mapper_base.h"
#include "stexecutor/rules_mappers/rules_hashing.h"

namespace rules_mappers {

class InMemoryRequestResults;

class InMemoryRulesMapper : public RulesMapperBase {
 public:
  InMemoryRulesMapper();
  ~InMemoryRulesMapper();

  std::unique_ptr<CachedExecutionResponse> FindCachedResults(
      const ProcessCreationRequest& process_creation_request,
      const BuildDirectoryState& build_dir_state,
      std::vector<FileInfo>* input_files) override;
  void AddRule(
      const ProcessCreationRequest& process_creation_request,
      const std::vector<FileInfo>& input_files,
      std::unique_ptr<CachedExecutionResponse> response) override;
  void set_dbg_dump_rules_dir(
      const boost::filesystem::path& dbg_dump_rules_dir) {
    dbg_dump_rules_dir_ = dbg_dump_rules_dir;
  }

 private:
  std::mutex instance_lock_;
  void DumpRequestResults(
      InMemoryRequestResults* results,
      const ProcessCreationRequest& process_creation_request,
      const HashValue& hash_value);

  std::unordered_map<
      HashValue,
      std::unique_ptr<InMemoryRequestResults>,
      HashValueHasher> rules_;
  boost::filesystem::path dbg_dump_rules_dir_;
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_IN_MEMORY_RULES_MAPPER_H_
