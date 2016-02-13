// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/in_memory_request_results.h"

#include <string>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/file_set.h"

namespace rules_mappers {

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"InMemoryRequestResults");

bool ComputeHashForFileSet(
    const FileSet& file_set,
    const BuildDirectoryState& build_dir_state,
    HashValue* result) {
  HashAlgorithm content_ids_hasher;
  for (const auto& rel_path : file_set.sorted_rel_file_paths()) {
    std::string content_id = build_dir_state.GetFileContentId(rel_path);
    if (content_id.empty()) {
      LOG4CPLUS_INFO(
          logger_, "No content id for " << rel_path.generic_string().c_str());
      return false;
    }
    HashString(&content_ids_hasher, content_id);
  }
  content_ids_hasher.Final(result->data());
  return true;
}

}  // namespace


void InMemoryRequestResults::AddRule(
    std::vector<FileInfo> input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  std::sort(
      input_files.begin(),
      input_files.end(),
      [](const FileInfo& first, const FileInfo& second) {
        return first.rel_file_path < second.rel_file_path;
      });
  HashAlgorithm content_ids_hasher;
  for (const FileInfo& file_info : input_files) {
    HashString(&content_ids_hasher, file_info.storage_content_id);
  }
  HashValue input_content_hash;
  content_ids_hasher.Final(input_content_hash.data());
  FileSet file_set(std::move(input_files));
  FileSetHashToResponse& file_set_hash_to_response = responses_[file_set];
  file_set_hash_to_response[input_content_hash] = std::move(response);
}

const CachedExecutionResponse*
InMemoryRequestResults::FindCachedResults(
    const BuildDirectoryState& build_dir_state) {
  for (const auto& file_set_and_hashes : responses_) {
    HashValue input_content_hash;
    if (!ComputeHashForFileSet(
        file_set_and_hashes.first, build_dir_state, &input_content_hash)) {
      continue;  // May be not all files present in current build dir state.
    }
    const FileSetHashToResponse& file_set_hash_to_response =
        file_set_and_hashes.second;
    auto it = file_set_hash_to_response.find(input_content_hash);
    if (it != file_set_hash_to_response.end())
      return it->second.get();
  }
  return nullptr;
}

}  // namespace rules_mappers
