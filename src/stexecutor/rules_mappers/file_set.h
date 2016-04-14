// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_FILE_SET_H_
#define STEXECUTOR_RULES_MAPPERS_FILE_SET_H_

#include <vector>

#include "boost/filesystem.hpp"
#include "boost/serialization/serialization.hpp"
#include "boost/serialization/vector.hpp"
#include "stexecutor/rules_mappers/file_info.h"

namespace rules_mappers {

// Represents unique set of files in build dir - that is
// path to these files and hashes of content of each of them.
class FileSet {
 public:
  explicit FileSet(const std::vector<FileInfo>& file_infos);

  FileSet();

  size_t hash_value() const {
    return hash_value_;
  }

  bool operator==(const FileSet& second) const;

  const std::vector<FileInfo> file_infos() const {
    return sorted_file_infos_;
  }

 private:
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version) {  // NOLINT
    ar & BOOST_SERIALIZATION_NVP(sorted_file_infos_);
  }

  std::vector<FileInfo> sorted_file_infos_;
  size_t hash_value_;
};

struct FileSetHash {
  size_t operator()(const FileSet& file_set) const {
    return file_set.hash_value();
  }
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_FILE_SET_H_
