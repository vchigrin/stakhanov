// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
#define STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_

#include <string>

#include "boost/filesystem.hpp"

namespace rules_mappers {

struct FileInfo {
  FileInfo(const boost::filesystem::path& rel_file_path,
           const std::string& storage_content_id)
      : rel_file_path(rel_file_path),
        storage_content_id(storage_content_id) {}

  boost::filesystem::path rel_file_path;
  std::string storage_content_id;
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
