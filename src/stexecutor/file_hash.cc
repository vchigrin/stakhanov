// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/file_hash.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"HashFileContent");
const int kInputBufferSize = 1024 * 1024;

}  // namespace

bool HashFileContent(
    const boost::filesystem::path& file_path,
    CryptoPP::HashTransformation* hasher) {
  boost::filesystem::filebuf input_filebuf;
  if (!input_filebuf.open(file_path, std::ios::in)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed open file " << file_path.c_str());
    return false;
  }
  std::vector<uint8_t> buffer(kInputBufferSize);
  while (true) {
    auto read = input_filebuf.sgetn(
        reinterpret_cast<char*>(&buffer[0]), kInputBufferSize);
    if (read < 0) {
      LOG4CPLUS_ERROR(
          logger_, "Unexpected sgetn result " << read);
      return false;
    }
    hasher.Update(&buffer[0], static_cast<size_t>(read));
    if (read < kInputBufferSize)
      break;
  }
  return true;
}
