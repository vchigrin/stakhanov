// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/request_results_base.h"

#include <string>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/rules_mappers/file_set.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"RequestResultsBase");

}  // namespace

namespace rules_mappers {

RequestResultsBase::~RequestResultsBase() {}

bool RequestResultsBase::FileSetMatchesBuildState(
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

}  // namespace rules_mappers

