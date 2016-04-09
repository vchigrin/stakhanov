// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/filesystem_files_storage.h"

#include <windows.h>

#include <vector>

#include "base/scoped_handle.h"
#include "base/string_utils.h"
#include "stexecutor/file_hash.h"
#include "third_party/cryptopp/md5.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"FilesystemFilesStorage");

const int kTopDirCharacters = 2;

std::string StorageIdFromHasher(CryptoPP::Weak::MD5* hasher) {
  std::vector<uint8_t> digest(hasher->DigestSize());
  hasher->Final(&digest[0]);
  return base::BytesToHexString(digest);
}

}  // namespace

FilesystemFilesStorage::FilesystemFilesStorage(
    const boost::filesystem::path& storage_dir)
    : storage_dir_(storage_dir) {
}

boost::filesystem::path FilesystemFilesStorage::PreparePlace(
    const std::string& storage_id) {
  std::string top_dir_name = storage_id.substr(0, kTopDirCharacters);
  std::string object_name = storage_id.substr(kTopDirCharacters);
  boost::filesystem::path dest_path = storage_dir_ / top_dir_name;
  if (!boost::filesystem::exists(dest_path)) {
    if (!boost::filesystem::create_directory(dest_path)) {
      LOG4CPLUS_ERROR(
          logger_, "Failed create directory " << dest_path.c_str());
      return boost::filesystem::path();
    }
  }
  dest_path /= object_name;
  return dest_path;
}

boost::filesystem::path FilesystemFilesStorage::FilePathFromId(
    const std::string& storage_id) {
  if (storage_id.length() <= kTopDirCharacters) {
    LOG4CPLUS_ERROR(logger_, "Invalid storage id " << storage_id.c_str());
    return boost::filesystem::path();
  }
  std::string top_dir_name = storage_id.substr(0, kTopDirCharacters);
  std::string object_name = storage_id.substr(kTopDirCharacters);
  return storage_dir_ / top_dir_name / object_name;
}

std::string FilesystemFilesStorage::StoreFile(
    const boost::filesystem::path& abs_file_path) {
  std::string file_id = GetFileHash(abs_file_path);
  LOG4CPLUS_DEBUG(logger_, "Storing file " << abs_file_path.string().c_str()
                        << " file_id " << file_id.c_str());
  if (file_id.empty())
    return file_id;
  boost::filesystem::path dest_path = PreparePlace(file_id);
  if (dest_path.empty())
    return std::string();

  // TODO(vchigrin): Consider usage of hard links.
  boost::system::error_code error_code;
  boost::filesystem::copy_file(
      abs_file_path, dest_path,
      boost::filesystem::copy_option::overwrite_if_exists,
      error_code);
  if (error_code) {
    LOG4CPLUS_ERROR(
        logger_, "Failed copy file " << abs_file_path.c_str()
            << " Error code " << error_code);
    return std::string();
  }
  return file_id;
}

bool FilesystemFilesStorage::GetFileFromStorage(
    const std::string& storage_id,
    const boost::filesystem::path& dest_path) {
  LOG4CPLUS_DEBUG(logger_, "Retrieving file to " << dest_path.string().c_str()
                        << " file_id " << storage_id.c_str());
  boost::filesystem::path src_path = FilePathFromId(storage_id);
  if (!boost::filesystem::exists(src_path)) {
    LOG4CPLUS_ERROR(logger_, "Object doesn't exist " << src_path.c_str());
    return false;
  }
  // TODO(vchigrin): Consider usage of hard links.
  boost::system::error_code error_code;
  boost::filesystem::create_directories(dest_path.parent_path());
  boost::filesystem::copy_file(
      src_path,
      dest_path,
      boost::filesystem::copy_option::overwrite_if_exists,
      error_code);
  if (error_code) {
    LOG4CPLUS_ERROR(
        logger_, "Failed copy file " << src_path.c_str()
              << " Error code " << error_code);
    return false;
  }
  return true;
}

std::string FilesystemFilesStorage::StoreContent(const std::string& data) {
  CryptoPP::Weak::MD5 hasher;
  if (!data.empty()) {
    hasher.Update(
        reinterpret_cast<const uint8_t*>(data.data()), data.length());
  }
  std::string storage_id = StorageIdFromHasher(&hasher);
  boost::filesystem::path dest_path = PreparePlace(storage_id);
  if (dest_path.empty())
    return std::string();
  boost::filesystem::filebuf filebuf;
  if (!filebuf.open(dest_path, std::ios::out | std::ios::binary)) {
    LOG4CPLUS_ERROR(logger_, "Failed open file " << dest_path.c_str());
    return std::string();
  }
  if (!data.empty()) {
    filebuf.sputn(data.c_str(), data.length());
  }
  return storage_id;
}

std::string FilesystemFilesStorage::RetrieveContent(
    const std::string& storage_id) {
  boost::filesystem::path file_path = FilePathFromId(storage_id);
  if (!boost::filesystem::exists(file_path)) {
    LOG4CPLUS_ERROR(logger_, "Object doesn't exist " << file_path.c_str());
    return std::string();
  }
  base::ScopedHandle input_file(
      CreateFileW(
          file_path.native().c_str(),
          GENERIC_READ,
          FILE_SHARE_READ,
          NULL,
          OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL,
          NULL));
  if (!input_file.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_,
        "Failed open file " << file_path.c_str() << " Error " << error);
    return false;
  }
  auto file_size = GetFileSize(input_file.Get(), NULL);
  if (file_size == INVALID_FILE_SIZE) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed get file size, error " << error);
    return std::string();
  }
  if (file_size == 0)
    return std::string();
  std::vector<char> data(file_size);
  DWORD bytes_read = 0;
  BOOL ok = ReadFile(
      input_file.Get(),
      &data[0],
      file_size,
      &bytes_read,
      NULL);
  if (!ok) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "ReadFile failed Error " << error);
    return std::string();
  }
  return std::string(&data[0], file_size);
}

std::string FilesystemFilesStorage::GetFileHash(
    const boost::filesystem::path& file_path) {
  CryptoPP::Weak::MD5 hasher;
  if (!HashFileContent(file_path, &hasher)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed hash file " << file_path.generic_string().c_str());
    return std::string();
  }
  return StorageIdFromHasher(&hasher);
}
