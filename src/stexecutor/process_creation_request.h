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

// NOTE: all passed in paths must already be normalized,
// and have already stripped build_root directory.
class ProcessCreationRequest {
 public:
  ProcessCreationRequest(
      const boost::filesystem::path& exe_path,
      const boost::filesystem::path& startup_directory,
      const std::vector<std::string>& command_line,
      const std::vector<std::string>& environment_strings);

  const boost::filesystem::path& exe_path() const {
    return exe_path_;
  }

  const boost::filesystem::path& startup_directory() const {
    return startup_directory_;
  }

  const std::vector<std::string>& command_line() const {
    return command_line_;
  }

  const std::vector<std::string>& sorted_environment_strings() const {
    return sorted_environment_strings_;
  }

 private:
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version) {  // NOLINT
    ar & BOOST_SERIALIZATION_NVP(exe_path_);
    ar & BOOST_SERIALIZATION_NVP(startup_directory_);
    ar & BOOST_SERIALIZATION_NVP(command_line_);
    ar & BOOST_SERIALIZATION_NVP(sorted_environment_strings_);
  }

  boost::filesystem::path exe_path_;
  boost::filesystem::path startup_directory_;
  std::vector<std::string> command_line_;
  std::vector<std::string> sorted_environment_strings_;
};

// For ease of logging.
std::wostream& operator << (
    std::wostream& stream, const ProcessCreationRequest& request);

#endif  // STEXECUTOR_PROCESS_CREATION_REQUEST_H_

