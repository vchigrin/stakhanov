// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_CACHED_EXECUTION_RESPONSE_H_
#define STEXECUTOR_RULES_MAPPERS_CACHED_EXECUTION_RESPONSE_H_

#include <string>
#include <vector>

#include "boost/serialization/nvp.hpp"
#include "boost/serialization/serialization.hpp"
#include "stexecutor/rules_mappers/file_info.h"

namespace rules_mappers {

struct CachedExecutionResponse {
  CachedExecutionResponse(
      const std::vector<FileInfo>& output_files,
      int exit_code,
      const std::string& stdout_content_id,
      const std::string& stderr_content_id)
      : output_files(output_files),
        exit_code(exit_code),
        stdout_content_id(stdout_content_id),
        stderr_content_id(stderr_content_id) {}

  std::vector<FileInfo> output_files;
  int exit_code;
  std::string stdout_content_id;
  std::string stderr_content_id;

  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version) {  // NOLINT
    ar & BOOST_SERIALIZATION_NVP(output_files);
    ar & BOOST_SERIALIZATION_NVP(exit_code);
    ar & BOOST_SERIALIZATION_NVP(stdout_content_id);
    ar & BOOST_SERIALIZATION_NVP(stderr_content_id);
  }
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_CACHED_EXECUTION_RESPONSE_H_
