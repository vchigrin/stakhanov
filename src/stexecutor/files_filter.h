// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_FILES_FILTER_H_
#define STEXECUTOR_FILES_FILTER_H_

#include <mutex>
#include <string>
#include <unordered_set>

#include "boost/filesystem.hpp"
#include "boost/property_tree/ptree_fwd.hpp"

// Manages, what outputs is safe to "drop". E.g. *.ilk files
// is not needed if we want build only once for running tests.
// Some inputs we also can ignore, e.g. *.pyc files.
class FilesFilter {
 public:
  explicit FilesFilter(const boost::property_tree::ptree& config);
  bool CanDropOutput(const boost::filesystem::path& path) const;
  bool CanDropInput(const boost::filesystem::path& path) const;

 private:
  void LoadConfig(const boost::property_tree::ptree& config);
  static void LoadSet(
      const boost::property_tree::ptree& config,
      const std::string& node_path,
      std::unordered_set<std::string>* string_set);

  mutable std::mutex instance_lock_;
  std::unordered_set<std::string> safe_to_drop_output_extensions_;
  std::unordered_set<std::string> safe_to_drop_input_extensions_;
};

#endif  // STEXECUTOR_FILES_FILTER_H_

