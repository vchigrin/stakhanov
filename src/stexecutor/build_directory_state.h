// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_BUILD_DIRECTORY_STATE_H_
#define STEXECUTOR_BUILD_DIRECTORY_STATE_H_

#include <mutex>
#include <string>
#include <unordered_map>

#include "base/filesystem_utils.h"
#include "boost/filesystem.hpp"

class FilesStorage;

class BuildDirectoryState {
 public:
  explicit BuildDirectoryState(const boost::filesystem::path& dir_path);
  std::string GetFileContentId(const boost::filesystem::path& rel_path) const;
  bool TakeFileFromStorage(
      FilesStorage* files_storage,
      const std::string& storage_id,
      const boost::filesystem::path& rel_path);
  boost::filesystem::path MakeRelativePath(
      const boost::filesystem::path& abs_path) const;
  bool RemoveFile(const boost::filesystem::path& rel_path);
  void NotifyFileChanged(const boost::filesystem::path& rel_path);

 private:
  mutable std::mutex instance_lock_;
  mutable std::unordered_map<
      boost::filesystem::path,
      std::string,
      base::FilePathHash> content_id_cache_;
  const boost::filesystem::path build_dir_path_;
};

#endif  // STEXECUTOR_BUILD_DIRECTORY_STATE_H_
