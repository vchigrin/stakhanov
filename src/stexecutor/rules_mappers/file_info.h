// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
#define STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_

#include <string>

#include "boost/filesystem.hpp"
#include "boost/serialization/split_free.hpp"

namespace rules_mappers {

// Represents unique state on one file in build dir.
// That is, it relative path and hash of it content.
struct FileInfo {
  FileInfo(const boost::filesystem::path& rel_file_path,
           const std::string& storage_content_id)
      : rel_file_path(rel_file_path),
        storage_content_id(storage_content_id) {}

  FileInfo() {}

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

  template<typename Archive>
  void serialize(
      Archive& ar,  // NOLINT
      const unsigned int) {
    ar & boost::serialization::make_nvp(
        "rel_file_path", rel_file_path);
    ar & boost::serialization::make_nvp(
        "storage_content_id", storage_content_id);
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

BOOST_SERIALIZATION_SPLIT_FREE(boost::filesystem::path)

namespace boost {
namespace serialization {

template<typename Archive>
void save(
    Archive& ar,  // NOLINT
    const boost::filesystem::path& path,
    const unsigned int) {
  ar << boost::serialization::make_nvp("path", path.generic_string());
}

template<typename Archive>
void load(
    Archive& ar, boost::filesystem::path& path,  // NOLINT
    const unsigned int) {
  std::string generic_path;
  ar >> generic_path;
  path = boost::filesystem::path(generic_path);
}

}  // namespace serialization
}  // namespace boost

#endif  // STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
