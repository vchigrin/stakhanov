// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_FILESYSTEM_FILES_STORAGE_H_
#define STEXECUTOR_FILESYSTEM_FILES_STORAGE_H_

#include <mutex>
#include <string>
#include <unordered_set>

#include "boost/property_tree/ptree_fwd.hpp"
#include "stexecutor/files_storage.h"

class FilesystemFilesStorage : public FilesStorage {
 public:
  explicit FilesystemFilesStorage(
      const boost::property_tree::ptree& config);
  std::string StoreFile(
      const boost::filesystem::path& abs_file_path) override;
  bool GetFileFromStorage(
      const std::string& storage_id,
      const boost::filesystem::path& dest_path) override;
  std::string StoreContent(const std::string& data) override;
  std::string RetrieveContent(const std::string& storage_id) override;

 private:
  std::mutex instance_lock_;
  void LoadConfig(const boost::property_tree::ptree& config);
  std::string GetFileHash(const boost::filesystem::path& file_path);
  boost::filesystem::path PreparePlace(const std::string& storage_id);
  boost::filesystem::path FilePathFromId(const std::string& storage_id);
  bool IsSafeToLink(const boost::filesystem::path& file_path);

  boost::filesystem::path storage_dir_;
  // Zero means no limit.
  uint32_t max_file_size_;
  // Set of file extensions  (with dot, like ".obj"), that are safe to hardlink
  // from build dir to cache and vise versa.
  std::unordered_set<std::string> safe_to_link_extensions_;
};

#endif  // STEXECUTOR_FILESYSTEM_FILES_STORAGE_H_
