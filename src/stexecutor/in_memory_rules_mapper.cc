// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/in_memory_rules_mapper.h"

#include "third_party/cryptopp/md5.h"

namespace {

inline void HashString(
    CryptoPP::Weak::MD5* hasher, const std::string& str) {
  hasher->Update(str.c_str(), str.length());
}
}  // namespace

class InMemoryRulesMapper::ProcessCreationRequestResults {
 public:
 private:
   std::unordered_map<
       InMemoryRulesMapper::HashValue,
       std::unique_ptr<ProcessCreationResponse>> responses_;
};

InMemoryRulesMapper::InMemoryRulesMapper() {
}

InMemoryRulesMapper::~InMemoryRulesMapper() {
}

std::unique_ptr<CachedExecutionResponse> InMemoryRulesMapper::FindCachedResults(
    const ProcessCreationRequest& process_creation_request,
    const BuildDirectoryState& build_dir_state) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
}


// static
InMemoryRulesMapper::HashValue InMemoryRulesMapper::ComputeProcessCreationHash(
    const ProcessCreationRequest& process_creation_request) {
  CryptoPP::Weak::MD5 hasher;
  HashString(&hasher, process_creation_request.exe_path());
  HashString(&hasher, process_creation_request.startup_directory());
  for (const std::string& argument : process_creation_request.command_line()) {
    HashString(&hasher, argument);
  }
  for (const std::string& env_string :
      process_creation_request.sorted_environment_strings()) {
    HashString(&hasher, env_string);
  }
  LOG4CPLUS_ASSERT(hasher.DigestSize() == sizeof(HashValue));
  HashValue request_hash;
  hasher.Final(&request_hash[0]);
  return request_hash;
}

void InMemoryRulesMapper::AddRule(
    const ProcessCreationRequest& process_creation_request,
    std::vector<FileInfo> input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  std::sort(
      input_files.begin(), input_files.end(),
      [](const FileInfo& first, const FileInfo& second) {
        return first.rel_file_path < second.rel_file_path;
      });
  CryptoPP::Weak::MD5 hasher;
  for (const FileInfo& info : input_files) {
    HashString(&hasher, info.rel_file_path.generic_string());
    HashString(&hasher, info.storage_content_id);
  }
  HashValue input_files_hash;
  hasher.Final(&input_files_hash[0]);
  auto it = rules_.find(request_hash);
  ProcessCreationRequestResults* results = nullptr;
  if (it != rules_.end()) {
    results = it->second.get();
  } else {
    std::unique_ptr<ProcessCreationRequestResults> new_results(
        new ProcessCreationRequestResults());
    results = new_results.get();
    rules_.insert(std::make_pair(request_hash, std::move(new_results));
  }
  results->AddRule(
      input_files,
      std::move(response));
}
