// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_
#define STEXECUTOR_RULES_MAPPERS_FILE_INFO_H_

#include <chrono>
#include <string>

#include "boost/filesystem.hpp"
#include "boost/serialization/split_free.hpp"

namespace rules_mappers {

// Represents unique state on one file in build dir.
// That is, it relative path and hash of it content.
struct FileInfo {
  using TimePoint = std::chrono::steady_clock::time_point;
  FileInfo(const boost::filesystem::path& rel_file_path,
           const std::string& storage_content_id,
           const TimePoint& construction_time)
      : rel_file_path(rel_file_path),
        storage_content_id(storage_content_id),
        construction_time(construction_time) {}

  FileInfo() {}

  bool operator == (const FileInfo& second) const {
    return rel_file_path == second.rel_file_path &&
        storage_content_id == second.storage_content_id &&
        construction_time == second.construction_time;
  }

  bool operator < (const FileInfo& second) const {
    auto cmp_result = rel_file_path.compare(second.rel_file_path);
    if (cmp_result < 0)
      return true;
    if (cmp_result > 0)
      return false;
    // Path are equal - compare storage ids.
    cmp_result = storage_content_id.compare(second.storage_content_id);
    if (cmp_result < 0)
      return true;
    if (cmp_result > 0)
      return false;
    return construction_time < second.construction_time;
  }

  template<typename Archive>
  void serialize(
      Archive& ar,  // NOLINT
      const unsigned int) {
    ar & boost::serialization::make_nvp(
        "rel_file_path", rel_file_path);
    ar & boost::serialization::make_nvp(
        "storage_content_id", storage_content_id);
    // NOTE: construction_time intentionally not serialized.
    // There is no point in wasting precise memory in Redis for it.
  }

  boost::filesystem::path rel_file_path;
  std::string storage_content_id;
  // Preserve time of file construction to properly determine
  // result outputs in case when parent command overwrites some of child
  // command outputs. We can not just rely on the fact that parent
  // command info is filled after children. Due to race conditions in
  // executor process child command info may be added after parent command
  // info applied.
  TimePoint construction_time;
};

struct FileInfoHasher {
  size_t operator()(const FileInfo& val) const {
    std::hash<std::string> string_hasher;
    std::hash<std::chrono::steady_clock::duration::rep> time_hasher;
    size_t path_hash = string_hasher(val.rel_file_path.generic_string());
    size_t content_hash = string_hasher(val.storage_content_id);
    size_t time_hash = time_hasher(
        val.construction_time.time_since_epoch().count());
    return path_hash ^ content_hash ^ time_hash;
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
