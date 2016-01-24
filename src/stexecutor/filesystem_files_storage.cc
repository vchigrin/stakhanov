// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/filesystem_files_storage.h"

#include <vector>

#include "base/string_utils.h"
#include "third_party/cryptopp/md5.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"FilesystemFilesStorage");

const int kTopDirCharacters = 2;
const int kInputBufferSize = 1024 * 1024;

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
  boost::filesystem::copy_file(abs_file_path, dest_path);
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
  boost::filesystem::copy(src_path, dest_path);
  return true;
}

std::string FilesystemFilesStorage::GetFileHash(
    const boost::filesystem::path& file_path) {
  CryptoPP::Weak::MD5 hasher;
  boost::filesystem::filebuf input_filebuf;
  if (!input_filebuf.open(file_path, std::ios::in)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed open file " << file_path.c_str());
    return std::string();
  }
  std::vector<uint8_t> buffer(kInputBufferSize);
  while (true) {
    auto read = input_filebuf.sgetn(
        reinterpret_cast<char*>(&buffer[0]), kInputBufferSize);
    if (read < 0) {
      LOG4CPLUS_ERROR(
          logger_, "Unexpected sgetn result " << read);
      return std::string();
    }
    hasher.Update(&buffer[0], static_cast<size_t>(read));
    if (read < kInputBufferSize)
      break;
  }
  std::vector<uint8_t> digest(hasher.DigestSize());
  hasher.Final(&digest[0]);
  return base::BytesToHexString(digest);
}
