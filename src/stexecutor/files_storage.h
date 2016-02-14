// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_FILES_STORAGE_H_
#define STEXECUTOR_FILES_STORAGE_H_

#include <string>

#include "boost/filesystem.hpp"

class FilesStorage {
 public:
  // Empty string is invalid id. Used to indicate errors.
  virtual std::string StoreFile(
      const boost::filesystem::path& abs_file_path) = 0;
  virtual bool GetFileFromStorage(
      const std::string& storage_id,
      const boost::filesystem::path& dest_path) = 0;
};

#endif  // STEXECUTOR_FILES_STORAGE_H_