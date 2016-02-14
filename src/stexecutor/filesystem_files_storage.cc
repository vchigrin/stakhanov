// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/filesystem_files_storage.h"

#include <vector>

#include "base/string_utils.h"
#include "stexecutor/file_hash.h"
#include "third_party/cryptopp/md5.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"FilesystemFilesStorage");

const int kTopDirCharacters = 2;

}  // namespace

FilesystemFilesStorage::FilesystemFilesStorage(
    const boost::filesystem::path& storage_dir)
    : storage_dir_(storage_dir) {
}

std::string FilesystemFilesStorage::StoreFile(
    const boost::filesystem::path& abs_file_path) {
  std::string file_id = GetFileHash(abs_file_path);
  if (file_id.empty())
    return file_id;
  std::string top_dir_name = file_id.substr(0, kTopDirCharacters);
  std::string object_name = file_id.substr(kTopDirCharacters);
  boost::filesystem::path dest_path = storage_dir_ / top_dir_name;
  if (!boost::filesystem::exists(dest_path)) {
    if (!boost::filesystem::create_directory(dest_path)) {
      LOG4CPLUS_ERROR(
          logger_, "Failed create directory " << dest_path.c_str());
      return std::string();
    }
  }
  dest_path /= object_name;
  // TODO(vchigrin): Consider usage of hard links.
  try {
    boost::filesystem::copy_file(abs_file_path, dest_path);
  } catch (const std::exception& ex) {
    LOG4CPLUS_ERROR(
        logger_, "Failed copy file " << abs_file_path.c_str()
            << " Error message " << ex.what());
    return std::string();
  }
  return file_id;
}

bool FilesystemFilesStorage::GetFileFromStorage(
    const std::string& storage_id,
    const boost::filesystem::path& dest_path) {
  if (storage_id.length() <= kTopDirCharacters) {
    LOG4CPLUS_ERROR(logger_, "Invalid storage id " << storage_id.c_str());
    return false;
  }
  std::string top_dir_name = storage_id.substr(0, kTopDirCharacters);
  std::string object_name = storage_id.substr(kTopDirCharacters);
  boost::filesystem::path src_path =
      storage_dir_ / top_dir_name / object_name;
  if (!boost::filesystem::exists(src_path)) {
    LOG4CPLUS_ERROR(
        logger_, "Object doesn't exist " << src_path.c_str());
    return false;
  }
  // TODO(vchigrin): Consider usage of hard links.
  try {
    boost::filesystem::copy_file(src_path, dest_path);
  } catch (const std::exception& ex) {
    LOG4CPLUS_ERROR(
        logger_, "Failed copy file " << src_path.c_str()
            << " Error message " << ex.what());
    return false;
  }
  return true;
}

std::string FilesystemFilesStorage::GetFileHash(
    const boost::filesystem::path& file_path) {
  CryptoPP::Weak::MD5 hasher;
  if (!HashFileContent(file_path, &hasher)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed hash file " << file_path.generic_string().c_str());
    return std::string();
  }
  std::vector<uint8_t> digest(hasher.DigestSize());
  hasher.Final(&digest[0]);
  return base::BytesToHexString(digest);
}
