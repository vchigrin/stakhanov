// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/build_directory_state.h"

#include <ctime>
#include <vector>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "base/filesystem_utils.h"
#include "base/scoped_handle.h"
#include "base/string_utils.h"
#include "stexecutor/file_hash.h"
#include "stexecutor/files_storage.h"
#include "third_party/cryptopp/md5.h"

using HashAlgorithm = CryptoPP::Weak::MD5;

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"BuildDirectoryState");

bool UpdateModificationTime(const boost::filesystem::path& abs_path) {
  // boost::filesystem::last_write_time uses std::time_t, that is measured in
  // seconds. Such granularity is not always enough
  base::ScopedHandle file_handle(
      CreateFileW(
          abs_path.native().c_str(),
          GENERIC_WRITE,
          FILE_SHARE_READ | FILE_SHARE_WRITE,
          NULL,
          OPEN_EXISTING,
          FILE_ATTRIBUTE_NORMAL,
          NULL));
  if (!file_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_,
        "Failed open file " << abs_path.c_str() << " Error " << error);
    return false;
  }
  FILETIME last_write_time = {0};
  SYSTEMTIME system_time = {0};
  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &last_write_time);
  if (!SetFileTime(
      file_handle.Get(),
      NULL,  // Creation time
      NULL,  // Last access time
      &last_write_time)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_,
        "Failed SetFileTime " << abs_path.c_str() << " Error " << error);
    return false;
  }
  return true;
}

}  // namespace

BuildDirectoryState::BuildDirectoryState(
    const boost::filesystem::path& dir_path)
    : build_dir_path_(base::WideToLower(dir_path.string<std::wstring>())) {
}

std::string BuildDirectoryState::GetFileContentId(
    const boost::filesystem::path& rel_path) const {
  std::lock_guard<std::mutex> lock(instance_lock_);
  auto it_cache = content_id_cache_.find(rel_path);
  if (it_cache != content_id_cache_.end()) {
    return it_cache->second;
  }
  boost::filesystem::path abs_path = build_dir_path_ / rel_path;
  CryptoPP::Weak::MD5 hasher;
  if (!HashFileContent(abs_path, &hasher)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed hash file " << abs_path.generic_string().c_str());
    return std::string();
  }
  std::vector<uint8_t> digest(hasher.DigestSize());
  hasher.Final(&digest[0]);
  std::string result = base::BytesToHexString(digest);
  content_id_cache_.insert(std::make_pair(rel_path, result));
  return result;
}

bool BuildDirectoryState::TakeFileFromStorage(
    FilesStorage* files_storage,
    const std::string& storage_id,
    const boost::filesystem::path& rel_path) {
  boost::filesystem::path abs_path = build_dir_path_ / rel_path;
  bool is_ok = files_storage->GetFileFromStorage(storage_id, abs_path);
  if (is_ok) {
    // We must update modification time of file (files storage may not do this
    // if it uses hard links). Without it some commands,
    // like used by NaCL toolcain in chromium build, will fail.
    is_ok &= UpdateModificationTime(abs_path);
  }

  std::lock_guard<std::mutex> lock(instance_lock_);
  content_id_cache_.erase(rel_path);
  if (!is_ok)
    return false;
  // Take advantage of the fact that FilesystmFilesStorage uses
  // same hash algorithm as we do.
  // TODO(vchigrin): Make thie assumption clearer.
  content_id_cache_.insert(std::make_pair(rel_path, storage_id));
  return true;
}

void BuildDirectoryState::RemoveFile(const boost::filesystem::path& rel_path) {
  {
    std::lock_guard<std::mutex> lock(instance_lock_);
    content_id_cache_.erase(rel_path);
  }
  boost::filesystem::path abs_path = build_dir_path_ / rel_path;
  boost::system::error_code remove_error;
  // Delete old file, if any.
  boost::filesystem::remove(abs_path, remove_error);
}

void BuildDirectoryState::NotifyFileChanged(
    const boost::filesystem::path& rel_path) {
  std::lock_guard<std::mutex> lock(instance_lock_);
  content_id_cache_.erase(rel_path);
}

boost::filesystem::path BuildDirectoryState::MakeRelativePath(
    const boost::filesystem::path& abs_path) const {
  if (!base::IsAncestorOfFile(build_dir_path_, abs_path))
    return boost::filesystem::path();
  return abs_path.lexically_relative(build_dir_path_);
}


