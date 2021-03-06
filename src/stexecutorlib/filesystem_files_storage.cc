// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutorlib/filesystem_files_storage.h"

#include <windows.h>

#include <vector>

#include "base/scoped_handle.h"
#include "base/string_utils.h"
#include "boost/property_tree/ptree.hpp"
#include "stexecutorlib/file_hash.h"
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

bool LinkOrCopyFile(
    const boost::filesystem::path& src_path,
    const boost::filesystem::path& dst_path,
    bool is_safe_to_link) {
  boost::system::error_code error;
  bool tried_remove = false;
  while (true) {
    // It is not always safe to link files, since build process
    // may change outputs of previous commands.
    if (is_safe_to_link) {
      boost::filesystem::create_hard_link(
          src_path, dst_path,
          error);
      if (!error)
        return true;
    }
    boost::filesystem::copy_file(
        src_path, dst_path,
        boost::filesystem::copy_option::overwrite_if_exists,
        error);
    if (!error)
      return true;

    if (tried_remove) {
      LOG4CPLUS_ERROR(
          logger_, "Both copy and hard_link failed for " << src_path.c_str()
              << " Error code " << error);
      return false;
    }
    // Delete file and try again.
    boost::system::error_code remove_error;
    tried_remove = true;
    boost::filesystem::remove(dst_path, error);
#ifdef _WINDOWS
    // Strange, but Windows will disallow remove ANY hardlink to file if it
    // open through ANY OTHER hardlink. Just report true, since in other case
    // we'll have problems with storing same file content when some process
    // in build system did not released file handle yet.
    if (error.value() == ERROR_SHARING_VIOLATION) {
      return true;
    }
#endif
  }
  return true;
}

}  // namespace

FilesystemFilesStorage::FilesystemFilesStorage(
      const boost::property_tree::ptree& config)
    : max_file_size_(0) {
  try {
    LoadConfig(config);
  } catch(const std::exception& ex) {
    LOG4CPLUS_FATAL(logger_, "Error during config parsing " << ex.what());
  }
  CryptoPP::Weak::MD5 hasher;
  empty_content_id_ = StorageIdFromHasher(&hasher);
}

void FilesystemFilesStorage::LoadConfig(
    const boost::property_tree::ptree& config) {
  const boost::property_tree::ptree files_storage_node = config.get_child(
      "files_storage");
  storage_dir_ = files_storage_node.get<boost::filesystem::path>(
      "storage_dir");
  max_file_size_ = files_storage_node.get<uint32_t>("max_file_size_bytes");
  boost::property_tree::ptree safe_to_link_extensions =
      files_storage_node.get_child("safe_to_link_extensions");
  for (const auto& ext : safe_to_link_extensions) {
    safe_to_link_extensions_.insert(ext.second.data());
  }
}

std::string FilesystemFilesStorage::StoreFile(
    const boost::filesystem::path& abs_file_path) {
  if (max_file_size_) {
    boost::system::error_code ec;
    auto file_size = boost::filesystem::file_size(abs_file_path, ec);
    if (ec) {
      LOG4CPLUS_WARN(
          logger_, "Failed get file size " << abs_file_path.string().c_str());
    } else {
      if (file_size > max_file_size_) {
        LOG4CPLUS_INFO(
            logger_,
            "Do not store too big file " << abs_file_path.string().c_str());
        return std::string();
      }
    }
  }
  std::string file_id = GetFileHash(abs_file_path);
  if (file_id.empty())
    return file_id;

  boost::filesystem::path dest_path = PreparePlace(file_id);
  if (dest_path.empty())
    return std::string();
  boost::filesystem::path temp_path = PrepareTempPath();
  if (!LinkOrCopyFile(abs_file_path, temp_path, IsSafeToLink(abs_file_path)))
    return std::string();
  if (!MoveTempFile(temp_path, dest_path))
    return std::string();
  OnStorageIdFilled(file_id);
  return file_id;
}

bool FilesystemFilesStorage::GetFileFromStorage(
    const std::string& storage_id,
    const boost::filesystem::path& dest_path) {
  boost::filesystem::path src_path = FilePathFromId(storage_id);
  if (!boost::filesystem::exists(src_path)) {
    if (!OnRequestedMissedStorageId(storage_id)) {
      LOG4CPLUS_ERROR(logger_, "Object doesn't exist " << src_path.c_str());
      return false;
    }
  }
  boost::filesystem::create_directories(dest_path.parent_path());
  return LinkOrCopyFile(src_path, dest_path, IsSafeToLink(dest_path));
}

std::string FilesystemFilesStorage::StoreContent(const std::string& data) {
  if (data.empty())
    return empty_content_id_;
  if (max_file_size_) {
    if (data.length() > max_file_size_) {
      LOG4CPLUS_INFO(
          logger_, "Do not store too big content of length " << data.length());
      return std::string();
    }
  }
  CryptoPP::Weak::MD5 hasher;
  if (!data.empty()) {
    hasher.Update(
        reinterpret_cast<const uint8_t*>(data.data()), data.length());
  }
  std::string storage_id = StorageIdFromHasher(&hasher);
  boost::filesystem::path dest_path = PreparePlace(storage_id);
  if (dest_path.empty())
    return std::string();
  boost::filesystem::path temp_path = PrepareTempPath();
  {
    boost::filesystem::filebuf filebuf;
    if (!filebuf.open(temp_path, std::ios::out | std::ios::binary)) {
      LOG4CPLUS_ERROR(logger_, "Failed open file " << dest_path.c_str());
      return std::string();
    }
    if (!data.empty())
      filebuf.sputn(data.c_str(), data.length());
  }
  if (!MoveTempFile(temp_path, dest_path))
    return std::string();
  OnStorageIdFilled(storage_id);
  return storage_id;
}

bool FilesystemFilesStorage::RetrieveContent(
    const std::string& storage_id,
    std::string* result) {
  if (storage_id == empty_content_id_) {
    *result = std::string();
    return true;
  }
  boost::filesystem::path file_path = FilePathFromId(storage_id);
  if (!boost::filesystem::exists(file_path)) {
    if (!OnRequestedMissedStorageId(storage_id)) {
      LOG4CPLUS_ERROR(logger_, "Object doesn't exist " << file_path.c_str());
      return false;
    }
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
    return false;
  }
  if (file_size == 0)
    return false;
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
    return false;
  }
  *result = std::string(&data[0], file_size);
  return true;
}

void FilesystemFilesStorage::OnStorageIdFilled(
    const std::string& storage_id) {
}

bool FilesystemFilesStorage::OnRequestedMissedStorageId(
    const std::string& storage_id) {
  return false;
}

// static
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
  std::string rel_path = RelFilePathFromId(storage_id);
  if (rel_path.empty())
    return boost::filesystem::path();
  return storage_dir_ / rel_path;
}

// static
std::string FilesystemFilesStorage::RelFilePathFromId(
    const std::string& storage_id) {
  if (storage_id.length() <= kTopDirCharacters) {
    LOG4CPLUS_ERROR(logger_, "Invalid storage id " << storage_id.c_str());
    return std::string();
  }
  std::string top_dir_name = storage_id.substr(0, kTopDirCharacters);
  std::string object_name = storage_id.substr(kTopDirCharacters);
  return top_dir_name + "/" + object_name;
}

std::string FilesystemFilesStorage::IdFromFilePath(
    const boost::filesystem::path& file_path) {
  auto rel_path = boost::filesystem::relative(file_path, storage_dir_);
  std::vector<std::string> components;
  for (auto it = rel_path.begin(); it != rel_path.end(); ++it)
    components.push_back(it->generic_string());
  if (components.size() != 2 || components[0].length() != kTopDirCharacters) {
    LOG4CPLUS_ERROR(
        logger_, "Invalid entry path " << file_path.generic_string().c_str());
    return std::string();
  }
  return components[0] + components[1];
}

bool FilesystemFilesStorage::IsSafeToLink(
    const boost::filesystem::path& file_path) {
  std::string ext = file_path.extension().generic_string();
  if (ext.empty())
    return false;
  return safe_to_link_extensions_.count(ext) != 0;
}

boost::filesystem::path FilesystemFilesStorage::PrepareTempPath() const {
  // It is important that temp files will live in same place as
  // all storage, to ensure rename operation will be atomic.
  boost::filesystem::path temp_name = boost::filesystem::unique_path();
  return storage_dir_ / temp_name;
}

// static
bool FilesystemFilesStorage::MoveTempFile(
    const boost::filesystem::path& temp_path,
    const boost::filesystem::path& dest_path) {
  // Hope rename operation is atomic, so other thread will not see
  // half-written file.
  boost::system::error_code error;
  boost::filesystem::rename(temp_path, dest_path, error);
  if (error) {
    boost::filesystem::remove(temp_path, error);
    if (boost::filesystem::exists(dest_path)) {
      // May be other thread renamed to the same file.
      // since destination path depends on the file content, the file must be
      // identical to the one we're renaming, and we should not consider this
      // as error.
      return true;
    }
    LOG4CPLUS_ERROR(logger_, "Rename failed, error " << error);
    return false;
  }
  return true;
}
