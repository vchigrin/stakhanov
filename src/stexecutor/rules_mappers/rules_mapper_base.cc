// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/rules_mapper_base.h"

#include <string>

#include "stexecutor/process_creation_request.h"

namespace rules_mappers {

RulesMapperBase::RulesMapperBase() {}

RulesMapperBase::~RulesMapperBase() {}

// static
HashValue RulesMapperBase::ComputeProcessCreationHash(
    const ProcessCreationRequest& process_creation_request) {
  CryptoPP::Weak::MD5 hasher;
  HashString(&hasher,
      process_creation_request.exe_path().generic_string());
  HashString(&hasher,
      process_creation_request.startup_directory().generic_string());
  for (const std::string& argument : process_creation_request.command_line()) {
    HashString(&hasher, argument);
  }
  HashString(&hasher, process_creation_request.environment_hash());
  HashValue request_hash;
  hasher.Final(request_hash.data());
  return request_hash;
}

}  // namespace rules_mappers

