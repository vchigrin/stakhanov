// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_creation_request.h"
#include "base/string_utils.h"

ProcessCreationRequest::ProcessCreationRequest(
    const boost::filesystem::path& exe_path,
    const boost::filesystem::path& startup_directory,
    const std::vector<std::string>& command_line,
    const std::string& environment_hash)
    : exe_path_(exe_path),
      startup_directory_(startup_directory),
      command_line_(command_line),
      environment_hash_(environment_hash),
      hash_value_computed_(false) {
}


std::wostream& operator << (
    std::wostream& stream, const ProcessCreationRequest& request) {
  for (const std::string& str : request.command_line()) {
    stream << base::ToWideFromUTF8(str) << L" ";
  }
  return stream;
}

const rules_mappers::HashValue& ProcessCreationRequest::GetHash() const {
  if (hash_value_computed_)
    return hash_value_;
  CryptoPP::Weak::MD5 hasher;
  rules_mappers::HashString(&hasher, exe_path_.generic_string());
  rules_mappers::HashString(&hasher, startup_directory_.generic_string());
  for (const std::string& argument : command_line_) {
    rules_mappers::HashString(&hasher, argument);
  }
  rules_mappers::HashString(&hasher, environment_hash_);
  hasher.Final(hash_value_.data());
  hash_value_computed_ = true;
  return hash_value_;
}
