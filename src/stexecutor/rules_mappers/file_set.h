// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_FILE_SET_H_
#define STEXECUTOR_RULES_MAPPERS_FILE_SET_H_

#include <vector>

#include "boost/filesystem.hpp"
#include "stexecutor/rules_mappers/file_info.h"

namespace rules_mappers {

class FileSet {
 public:
  FileSet(const std::vector<FileInfo>& sorted_input_files);

  const std::vector<boost::filesystem::path>& sorted_rel_file_paths() const {
    return sorted_rel_file_paths_;
  }

  size_t hash_value() const {
    return hash_value_;
  }

  bool operator==(const FileSet& second) const;

 private:
  std::vector<boost::filesystem::path> sorted_rel_file_paths_;
  size_t hash_value_;
};

struct FileSetHash {
  size_t operator()(const FileSet& file_set) const {
    return file_set.hash_value();
  }
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_FILE_SET_H_
