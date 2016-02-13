// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/file_set.h"

#include <algorithm>
#include <string>

namespace rules_mappers {

FileSet::FileSet(const std::vector<FileInfo>& sorted_input_files)
    : hash_value_(0) {
  sorted_rel_file_paths_.reserve(sorted_input_files.size());
  std::transform(
      sorted_input_files.begin(),
      sorted_input_files.end(),
      std::back_inserter(sorted_rel_file_paths_),
      [](const FileInfo& file_info) { return file_info.rel_file_path; });
  std::hash<std::string> string_hasher;
  for (const boost::filesystem::path& rel_file_path : sorted_rel_file_paths_) {
    hash_value_ ^= string_hasher(rel_file_path.generic_string());
  }
}

bool FileSet::operator==(const FileSet& second) const {
  if (hash_value_ != second.hash_value_)
    return false;
  if (sorted_rel_file_paths_.size() != second.sorted_rel_file_paths_.size())
    return false;
  for (size_t i = 0; i < sorted_rel_file_paths_.size(); ++i) {
    if (sorted_rel_file_paths_[i] != second.sorted_rel_file_paths_[i])
      return false;
  }
  return true;
}

}  // namespace rules_mappers

