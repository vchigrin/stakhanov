// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_OUTPUTS_FILTER_H_
#define STEXECUTOR_OUTPUTS_FILTER_H_

#include <mutex>
#include <string>
#include <unordered_set>

#include "boost/filesystem.hpp"
#include "boost/property_tree/ptree_fwd.hpp"

// Manages, what outputs is safe to "drop". E.g. *.ilk files
// is not needed if we want build only once for running tests.
class OutputsFilter {
 public:
  explicit OutputsFilter(const boost::property_tree::ptree& config);
  bool CanDropOutput(const boost::filesystem::path& path) const;

 private:
  void LoadConfig(const boost::property_tree::ptree& config);

  mutable std::mutex instance_lock_;
  std::unordered_set<std::string> safe_to_drop_output_extensions_;
};

#endif  // STEXECUTOR_OUTPUTS_FILTER_H_

