// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_FILESYSTEM_FILES_STORAGE_H_
#define STEXECUTOR_FILESYSTEM_FILES_STORAGE_H_

#include <string>

#include "stexecutor/files_storage.h"

class FilesystemFilesStorage : public FilesStorage {
 public:
  explicit FilesystemFilesStorage(const boost::filesystem::path& storage_dir);
  std::string StoreFile(
      const boost::filesystem::path& abs_file_path) override;
  bool GetFileFromStorage(
      const std::string& storage_id,
      const boost::filesystem::path& dest_path) override;
  std::string StoreContent(const std::string& data) override;
  std::string RetrieveContent(const std::string& storage_id) override;

 private:
  std::string GetFileHash(const boost::filesystem::path& file_path);
  boost::filesystem::path PreparePlace(const std::string& storage_id);
  boost::filesystem::path FilePathFromId(const std::string& storage_id);
  const boost::filesystem::path storage_dir_;
};

#endif  // STEXECUTOR_FILESYSTEM_FILES_STORAGE_H_
