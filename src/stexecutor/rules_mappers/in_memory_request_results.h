// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_IN_MEMORY_REQUEST_RESULTS_H_
#define STEXECUTOR_RULES_MAPPERS_IN_MEMORY_REQUEST_RESULTS_H_

#include <memory>
#include <unordered_map>
#include <vector>

#include "boost/serialization/shared_ptr.hpp"
#include "boost/serialization/unordered_map.hpp"
#include "stexecutor/rules_mappers/file_set.h"
#include "stexecutor/rules_mappers/request_results_base.h"
#include "stexecutor/rules_mappers/rules_hashing.h"

class BuildDirectoryState;

namespace rules_mappers {

struct CachedExecutionResponse;

class InMemoryRequestResults : public RequestResultsBase {
 public:
  void AddRule(
      std::vector<FileInfo>&& input_files,
      std::unique_ptr<CachedExecutionResponse> response) override;
  std::unique_ptr<CachedExecutionResponse> FindCachedResults(
      const BuildDirectoryState& build_dir_state,
      std::vector<FileInfo>* input_files) override;

 private:
  friend class boost::serialization::access;
  template<class Archive>
  void serialize(Archive & ar, const unsigned int version) {  // NOLINT
    ar & BOOST_SERIALIZATION_NVP(responses_);
  }

  std::unordered_map<
      FileSet,
      std::shared_ptr<CachedExecutionResponse>,
      FileSetHash> responses_;
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_IN_MEMORY_REQUEST_RESULTS_H_
