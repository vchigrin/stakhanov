// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/process_management_config.h"

#include <string>

#include "base/string_utils.h"
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
    LoadConfig(config);
  } catch(const std::exception& ex) {
    LOG4CPLUS_FATAL(logger_, "Error during config parsing " << ex.what());
  }
}

bool ProcessManagementConfig::ShouldStickToParent(
    const ProcessCreationRequest& request,
    const ProcessCreationRequest& parent_request) const {
  // HACK: Cygwin executables respawns themselves with exactly same
  // command line to emulate "fork" call on Windows.
  // They distinguish child copy by using undocumented STARTUPINFO structure
  // fields.
  // We should always treate such commands as "stick to parent"
  // to avoid weird problems - since behavior of these strange "childs"
  // is not same as parent.
  if (request.GetHash() == parent_request.GetHash())
    return true;
  // TODO(vchigrin): Allow JSON config add rules based on exe path.
  auto file_name = request.exe_path().filename();
  if (file_name == L"cc1plus.exe" ||
      file_name == "cc1.exe" ||
      file_name == "collect2.exe" ||
      // Can not use "stick to parent" rules for parent protoc.exe,
      // since we must stick exactly these command invokations.
      file_name == "json_values_converter.bat" ||
      file_name == "proto_zero_plugin.exe") {
    return true;
  }
  return MatchesAnyPattern(request, stick_to_parent_patterns_);
}

// static
bool ProcessManagementConfig::MatchesAnyPattern(
    const ProcessCreationRequest& request,
    const std::vector<ProcessMatchPattern>& patterns) {
  for (const ProcessMatchPattern& stick_pattern : patterns) {
    if (RequestMatchesPattern(stick_pattern, request))
      return true;
  }
  return false;
}

bool ProcessManagementConfig::ShouldDoNotTrack(
    const ProcessCreationRequest& request) const {
  // TODO(vchigrin): Allow JSON config add riles based on exe path.
  // unfortunatelly, vctip.exe has empty command line.
  std::wstring filename = base::WideToLower(
      request.exe_path().filename().native());
  if (filename == L"vctip.exe")
    return true;
  return MatchesAnyPattern(request, do_not_track_patterns_);
}

bool ProcessManagementConfig::ShouldUseHoaxProxy(
    const ProcessCreationRequest& request) const {
  return MatchesAnyPattern(request, use_hoax_proxy_patterns_);
}

bool ProcessManagementConfig::ShouldIgnoreStdStreamsFromChildren(
    const ProcessCreationRequest& request) const {
  return MatchesAnyPattern(
      request, ignore_std_streams_from_children_patterns_);
}

bool ProcessManagementConfig::ShouldBufferStdStreams(
    const ProcessCreationRequest& request) const {
  return MatchesAnyPattern(request, buffer_std_streams_patterns_);
}

bool ProcessManagementConfig::ShouldIgnoreOutputFiles(
    const ProcessCreationRequest& request) const {
  return MatchesAnyPattern(request, ignore_output_files_patterns_);
}

void ProcessManagementConfig::LoadConfig(
    const boost::property_tree::ptree& config) {
  LoadPatternsByPath(
      config, "process_rules.stick_to_parent", &stick_to_parent_patterns_);
  LoadPatternsByPath(
      config, "process_rules.do_not_track", &do_not_track_patterns_);
  LoadPatternsByPath(
      config, "process_rules.use_hoax_proxy", &use_hoax_proxy_patterns_);
  LoadPatternsByPath(
      config, "process_rules.ignore_std_streams_from_children",
      &ignore_std_streams_from_children_patterns_);
  LoadPatternsByPath(
      config, "process_rules.buffer_std_streams",
      &buffer_std_streams_patterns_);
  LoadPatternsByPath(
      config, "process_rules.ignore_output_files",
      &ignore_output_files_patterns_);
}

void ProcessManagementConfig::LoadPatternsByPath(
    const boost::property_tree::ptree& config,
    const std::string& path,
    std::vector<ProcessMatchPattern>* patterns) {
  boost::property_tree::ptree parent_node = config.get_child(
      path,
      boost::property_tree::ptree());
  if (parent_node.empty())
    return;
  patterns->reserve(parent_node.size());
  for (const auto& process_item : parent_node) {
    ProcessMatchPattern pattern = LoadProcessMatchPattern(process_item.second);
    if (!pattern.is_valid()) {
      LOG4CPLUS_ERROR(logger_, "Invalid process match pattern in config");
      continue;
    }
    patterns->emplace_back(std::move(pattern));
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
