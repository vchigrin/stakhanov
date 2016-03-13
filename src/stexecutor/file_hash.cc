// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/file_hash.h"

#include <windows.h>
#include <vector>

#include "base/scoped_handle.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"HashFileContent");
const int kInputBufferSize = 1024 * 1024;

}  // namespace

bool HashFileContent(
    const boost::filesystem::path& file_path,
    CryptoPP::HashTransformation* hasher) {
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

  std::vector<uint8_t> buffer(kInputBufferSize);
  while (true) {
    DWORD bytes_read = 0;
    BOOL ok = ReadFile(
        input_file.Get(),
        &buffer[0],
        kInputBufferSize,
        &bytes_read,
        NULL);
    if (!ok) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "ReadFile failed Error " << error);
      return false;
    }
    hasher->Update(&buffer[0], bytes_read);
    if (bytes_read < kInputBufferSize)
      break;
  }
  return true;
}
