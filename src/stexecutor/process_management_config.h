// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_PROCESS_MANAGEMENT_CONFIG_H_
#define STEXECUTOR_PROCESS_MANAGEMENT_CONFIG_H_

#include <string>
#include <vector>

#include "boost/regex.hpp"
#include "boost/property_tree/ptree_fwd.hpp"

class ProcessCreationRequest;

// Manages, what process results should be
// "stick to parent", to which processes we should avoid injecting and
// instead of it always execute them, etc.
class ProcessManagementConfig {
 public:
  explicit ProcessManagementConfig(const boost::property_tree::ptree& config);
  bool ShouldStickToParent(
      const ProcessCreationRequest& request,
      const ProcessCreationRequest& parent_request) const;
  bool ShouldDoNotTrack(const ProcessCreationRequest& request) const;
  bool ShouldUseHoaxProxy(const ProcessCreationRequest& request) const;

 private:
  struct ProcessMatchPattern {
    // Pattern matches request if all command_line_patterns match
    // some item in command line.
    std::vector<boost::regex> command_line_patterns;

    bool is_valid() const {
      return !command_line_patterns.empty();
    }
  };
  void LoadConfig(const boost::property_tree::ptree& config);
  static void LoadPatternsByPath(
      const boost::property_tree::ptree& config,
      const std::string& path,
      std::vector<ProcessMatchPattern>* patterns);
  static bool RequestMatchesPattern(
      const ProcessMatchPattern& pattern,
      const ProcessCreationRequest& request);
  static bool MatchesAnyPattern(
      const ProcessCreationRequest& request,
      const std::vector<ProcessMatchPattern>& patterns);
  static ProcessMatchPattern LoadProcessMatchPattern(
      const boost::property_tree::ptree& module_node);

  std::vector<ProcessMatchPattern> stick_to_parent_patterns_;
  std::vector<ProcessMatchPattern> do_not_track_patterns_;
  std::vector<ProcessMatchPattern> use_hoax_proxy_patterns_;
};

#endif  // STEXECUTOR_PROCESS_MANAGEMENT_CONFIG_H_
