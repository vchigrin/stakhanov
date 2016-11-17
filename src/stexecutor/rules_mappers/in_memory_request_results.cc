// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/in_memory_request_results.h"

#include <algorithm>
#include <string>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/file_set.h"

namespace rules_mappers {

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"InMemoryRequestResults");

}  // namespace

void InMemoryRequestResults::AddRule(
    std::vector<FileInfo>&& input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  FileSet file_set(std::move(input_files));
  responses_.emplace(std::move(file_set), std::move(response));
}

std::unique_ptr<CachedExecutionResponse>
InMemoryRequestResults::FindCachedResults(
    const BuildDirectoryState& build_dir_state,
    std::vector<FileInfo>* input_files) {
  for (const auto& file_set_and_response : responses_) {
    if (FileSetMatchesBuildState(
        file_set_and_response.first,
        build_dir_state)) {
      *input_files = file_set_and_response.first.file_infos();
      return std::make_unique<CachedExecutionResponse>(*file_set_and_response.second);
    }
  }
  input_files->clear();
  return nullptr;
}

}  // namespace rules_mappers
