// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/build_directory_state.h"

#include <vector>

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "base/filesystem_utils.h"
#include "base/string_utils.h"
#include "stexecutor/file_hash.h"
#include "stexecutor/files_storage.h"
#include "third_party/cryptopp/md5.h"

using HashAlgorithm = CryptoPP::Weak::MD5;

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"BuildDirectoryState");

}  // namespace

BuildDirectoryState::BuildDirectoryState(
    const boost::filesystem::path& dir_path)
    : build_dir_path_(base::WideToLower(dir_path.string<std::wstring>())) {
}

std::string BuildDirectoryState::GetFileContentId(
    const boost::filesystem::path& rel_path) const {
  boost::filesystem::path abs_path = build_dir_path_ / rel_path;
  CryptoPP::Weak::MD5 hasher;
  if (!HashFileContent(abs_path, &hasher)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed hash file " << abs_path.generic_string().c_str());
    return std::string();
  }
  std::vector<uint8_t> digest(hasher.DigestSize());
  hasher.Final(&digest[0]);
  return base::BytesToHexString(digest);
}

bool BuildDirectoryState::TakeFileFromStorage(
    FilesStorage* files_storage,
    const std::string& storage_id,
    const boost::filesystem::path& rel_path) {
  boost::filesystem::path abs_path = build_dir_path_ / rel_path;
  return files_storage->GetFileFromStorage(storage_id, abs_path);
}

boost::filesystem::path BuildDirectoryState::MakeRelativePath(
    const boost::filesystem::path& abs_path) const {
  if (!base::IsAncestorOfFile(build_dir_path_, abs_path))
    return boost::filesystem::path();
  return abs_path.lexically_relative(build_dir_path_);
}
