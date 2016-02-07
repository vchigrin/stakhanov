// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_FILE_HASH_H_
#define STEXECUTOR_FILE_HASH_H_

#include "boost/filesystem.hpp"
#include "third_party/cryptopp/cryptlib.h"

bool HashFileContent(
    const boost::filesystem::path& file_path,
    CryptoPP::HashTransformation* hasher);

#endif  // STEXECUTOR_FILE_HASH_H_
