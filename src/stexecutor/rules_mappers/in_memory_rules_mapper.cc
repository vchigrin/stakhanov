// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/in_memory_rules_mapper.h"

#include <vector>
#include <string>

#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/in_memory_request_results.h"
#include "stexecutor/process_creation_request.h"

namespace rules_mappers {

InMemoryRulesMapper::InMemoryRulesMapper() {
}

InMemoryRulesMapper::~InMemoryRulesMapper() {
}

const CachedExecutionResponse* InMemoryRulesMapper::FindCachedResults(
    const ProcessCreationRequest& process_creation_request,
    const BuildDirectoryState& build_dir_state) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  auto it = rules_.find(request_hash);
  if (it == rules_.end())
    return nullptr;
  return it->second->FindCachedResults(build_dir_state);
}


// static
HashValue InMemoryRulesMapper::ComputeProcessCreationHash(
    const ProcessCreationRequest& process_creation_request) {
  CryptoPP::Weak::MD5 hasher;
  HashString(&hasher,
      process_creation_request.exe_path().generic_string());
  HashString(&hasher,
      process_creation_request.startup_directory().generic_string());
  for (const std::string& argument : process_creation_request.command_line()) {
    HashString(&hasher, argument);
  }
  for (const std::string& env_string :
      process_creation_request.sorted_environment_strings()) {
    HashString(&hasher, env_string);
  }
  HashValue request_hash;
  hasher.Final(request_hash.data());
  return request_hash;
}

void InMemoryRulesMapper::AddRule(
    const ProcessCreationRequest& process_creation_request,
    std::vector<FileInfo> input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  auto it = rules_.find(request_hash);
  InMemoryRequestResults* results = nullptr;
  if (it != rules_.end()) {
    results = it->second.get();
  } else {
    std::unique_ptr<InMemoryRequestResults> new_results(
        new InMemoryRequestResults());
    results = new_results.get();
    rules_.insert(std::make_pair(request_hash, std::move(new_results)));
  }
  results->AddRule(std::move(input_files), std::move(response));
}

}  // namespace rules_mappers
