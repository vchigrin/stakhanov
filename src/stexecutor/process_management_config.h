// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_PROCESS_MANAGEMENT_CONFIG_H_
#define STEXECUTOR_PROCESS_MANAGEMENT_CONFIG_H_

#include <vector>

#include "boost/regex.hpp"
#include "boost/property_tree/ptree_fwd.hpp"

class ProcessCreationRequest;

// Manages, what process results should be
// "stick to parent", in future may also provide different other decisions.
class ProcessManagementConfig {
 public:
  explicit ProcessManagementConfig(const boost::property_tree::ptree& config);
  bool ShouldStickToParent(const ProcessCreationRequest& request) const;

 private:
  struct ProcessMatchPattern {
    // Pattern matches request if all command_line_patterns match
    // some item in command line.
    std::vector<boost::regex> command_line_patterns;

    bool is_valid() const {
      return !command_line_patterns.empty();
    }
  };
  void ProcessManagementConfig::LoadStickToParentPatterns(
      const boost::property_tree::ptree& config);
  static bool RequestMatchesPattern(
      const ProcessMatchPattern& pattern,
      const ProcessCreationRequest& request);
  static ProcessMatchPattern LoadProcessMatchPattern(
      const boost::property_tree::ptree& module_node);

  std::vector<ProcessMatchPattern> stick_to_parent_patterns_;
};

#endif  // STEXECUTOR_PROCESS_MANAGEMENT_CONFIG_H_
