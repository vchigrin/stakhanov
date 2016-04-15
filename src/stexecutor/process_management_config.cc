// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_management_config.h"

#include <string>

#include "boost/property_tree/ptree.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/process_creation_request.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"ProcessManagementConfig");

}  // namespace

ProcessManagementConfig::ProcessManagementConfig(
    const boost::property_tree::ptree& config) {
  try {
    LoadStickToParentPatterns(config);
  } catch(const std::exception& ex) {
    LOG4CPLUS_FATAL(logger_, "Error during config parsing " << ex.what());
  }
}

bool ProcessManagementConfig::ShouldStickToParent(
    const ProcessCreationRequest& request) const {
  for (const ProcessMatchPattern& stick_pattern : stick_to_parent_patterns_) {
    if (RequestMatchesPattern(stick_pattern, request))
      return true;
  }
  return false;
}

void ProcessManagementConfig::LoadStickToParentPatterns(
    const boost::property_tree::ptree& config) {
  boost::property_tree::ptree stick_to_parent = config.get_child(
      "process_rules.stick_to_parent",
      boost::property_tree::ptree());
  if (stick_to_parent.empty())
    return;
  stick_to_parent_patterns_.reserve(stick_to_parent.size());
  for (const auto& process_item : stick_to_parent) {
    ProcessMatchPattern pattern = LoadProcessMatchPattern(process_item.second);
    if (!pattern.is_valid()) {
      LOG4CPLUS_ERROR(logger_, "Invalid process match pattern in config");
      continue;
    }
    stick_to_parent_patterns_.emplace_back(std::move(pattern));
  }
}

// static
bool ProcessManagementConfig::RequestMatchesPattern(
    const ProcessMatchPattern& pattern,
    const ProcessCreationRequest& request) {
  const std::vector<std::string>& command_line = request.command_line();
  for (const boost::regex& re : pattern.command_line_patterns) {
    bool matched_any = false;
    for (const std::string& arg : command_line) {
      if (boost::regex_match(arg, re)) {
        matched_any = true;
        break;
      }
    }
    if (!matched_any)
      return false;
  }
  return true;
}

// static
ProcessManagementConfig::ProcessMatchPattern
ProcessManagementConfig::LoadProcessMatchPattern(
    const boost::property_tree::ptree& module_node) {
  ProcessMatchPattern result;
  const auto& cmd_line_patterns = module_node.get_child(
      "command_line_patterns");
  result.command_line_patterns.reserve(cmd_line_patterns.size());
  for (const auto& pattern : cmd_line_patterns) {
    result.command_line_patterns.push_back(
        boost::regex(pattern.second.data()));
  }
  return result;
}
