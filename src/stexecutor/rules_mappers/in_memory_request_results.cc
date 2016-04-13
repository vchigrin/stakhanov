// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/in_memory_request_results.h"

#include <algorithm>
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

bool FileSetMatchesBuildState(
    const FileSet& file_set,
    const BuildDirectoryState& build_dir_state) {
  const auto& file_infos = file_set.file_infos();
  for (const FileInfo& file_info : file_infos) {
    std::string actual_content_id = build_dir_state.GetFileContentId(
        file_info.rel_file_path);
    if (actual_content_id.empty()) {
      LOG4CPLUS_INFO(
          logger_,
          "No content id for "
              << file_info.rel_file_path.generic_string().c_str());
      return false;
    }
    if (actual_content_id != file_info.storage_content_id)
      return false;
  }
  return true;
}

}  // namespace


void InMemoryRequestResults::AddRule(
    const std::vector<FileInfo>& input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  FileSet file_set(input_files);
  responses_[file_set] = std::move(response);
}

const CachedExecutionResponse*
InMemoryRequestResults::FindCachedResults(
    const BuildDirectoryState& build_dir_state,
    std::vector<FileInfo>* input_files) {
  for (const auto& file_set_and_response : responses_) {
    if (FileSetMatchesBuildState(
        file_set_and_response.first,
        build_dir_state)) {
      *input_files = file_set_and_response.first.file_infos();
      return file_set_and_response.second.get();
    }
  }
  input_files->clear();
  return nullptr;
}

}  // namespace rules_mappers
