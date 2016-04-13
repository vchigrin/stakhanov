// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
#define STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_

#include <string>

#include "boost/filesystem.hpp"

namespace rules_mappers {

// Represents unique state on one file in build dir.
// That is, it relative path and hash of it content.
struct FileInfo {
  FileInfo(const boost::filesystem::path& rel_file_path,
           const std::string& storage_content_id)
      : rel_file_path(rel_file_path),
        storage_content_id(storage_content_id) {}

  bool operator == (const FileInfo& second) const {
    return rel_file_path == second.rel_file_path &&
        storage_content_id == second.storage_content_id;
  }

  bool operator < (const FileInfo& second) const {
    auto cmp_result = rel_file_path.compare(second.rel_file_path);
    if (cmp_result == 0) {
      // Path are equal - compare storage ids.
      return storage_content_id < second.storage_content_id;
    }
    return cmp_result < 0;
  }

  boost::filesystem::path rel_file_path;
  std::string storage_content_id;
};

struct FileInfoHasher {
  size_t operator()(const FileInfo& val) const {
    std::hash<std::string> hasher;
    size_t path_hash = hasher(val.rel_file_path.generic_string());
    size_t content_hash = hasher(val.storage_content_id);
    return path_hash ^ content_hash;
  }
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
