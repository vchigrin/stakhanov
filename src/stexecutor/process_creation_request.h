// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_PROCESS_CREATION_REQUEST_H_
#define STEXECUTOR_PROCESS_CREATION_REQUEST_H_

#include <string>
#include <vector>
#include "boost/filesystem.hpp"
#include "boost/serialization/nvp.hpp"
#include "boost/serialization/serialization.hpp"
#include "boost/serialization/vector.hpp"
#include "stexecutor/rules_mappers/rules_hashing.h"

// NOTE: all passed in paths must already be normalized,
// and have already stripped build_root directory.
class ProcessCreationRequest {
 public:
  ProcessCreationRequest(
      const boost::filesystem::path& exe_path,
      const boost::filesystem::path& startup_directory,
      const std::vector<std::string>& command_line,
      const std::string& environment_hash);
  ProcessCreationRequest() {}

  const boost::filesystem::path& exe_path() const {
    return exe_path_;
  }

  const boost::filesystem::path& startup_directory() const {
    return startup_directory_;
  }

  const std::vector<std::string>& command_line() const {
    return command_line_;
  }

  const std::string& environment_hash() const {
    return environment_hash_;
  }

  // TODO(vchigrin): Move out from rules_mappers namespace.
  const rules_mappers::HashValue& GetHash() const;

 private:
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version) {  // NOLINT
    ar & BOOST_SERIALIZATION_NVP(exe_path_);
    ar & BOOST_SERIALIZATION_NVP(startup_directory_);
    ar & BOOST_SERIALIZATION_NVP(command_line_);
    ar & BOOST_SERIALIZATION_NVP(environment_hash_);
  }

  boost::filesystem::path exe_path_;
  boost::filesystem::path startup_directory_;
  std::vector<std::string> command_line_;
  std::string environment_hash_;
  mutable rules_mappers::HashValue hash_value_;
  mutable bool hash_value_computed_;
};

// For ease of logging.
std::wostream& operator << (
    std::wostream& stream, const ProcessCreationRequest& request);

#endif  // STEXECUTOR_PROCESS_CREATION_REQUEST_H_

