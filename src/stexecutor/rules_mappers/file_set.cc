// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/file_set.h"

#include <algorithm>
#include <string>

namespace rules_mappers {

FileSet::FileSet(const std::vector<FileInfo>& file_infos)
    : hash_value_(0),
      sorted_file_infos_(file_infos) {
  std::sort(sorted_file_infos_.begin(), sorted_file_infos_.end());
  std::hash<std::string> string_hasher;
  for (const FileInfo& file_info : sorted_file_infos_) {
    hash_value_ ^= string_hasher(file_info.rel_file_path.generic_string());
    hash_value_ ^= string_hasher(file_info.storage_content_id);
  }
}

bool FileSet::operator==(const FileSet& second) const {
  if (hash_value_ != second.hash_value_)
    return false;
  if (sorted_file_infos_.size() != second.sorted_file_infos_.size())
    return false;
  return std::equal(
      sorted_file_infos_.begin(),
      sorted_file_infos_.end(),
      second.sorted_file_infos_.begin());
}

}  // namespace rules_mappers

