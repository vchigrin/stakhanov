// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/files_filter.h"

#include "boost/property_tree/ptree.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"FilesFilter");

}  // namespace

FilesFilter::FilesFilter(const boost::property_tree::ptree& config) {
  try {
    LoadConfig(config);
  } catch(const std::exception& ex) {
    LOG4CPLUS_FATAL(logger_, "Error during config parsing " << ex.what());
  }
}

bool FilesFilter::CanDropOutput(const boost::filesystem::path& path) const {
  std::lock_guard<std::mutex> lock(instance_lock_);
  return safe_to_drop_output_extensions_.count(
      path.extension().generic_string()) != 0;
}

bool FilesFilter::CanDropInput(const boost::filesystem::path& path) const {
  std::lock_guard<std::mutex> lock(instance_lock_);
  return safe_to_drop_input_extensions_.count(
      path.extension().generic_string()) != 0;
}

void FilesFilter::LoadConfig(const boost::property_tree::ptree& config) {
  LoadSet(
      config,
      "files_filtering.safe_to_drop_output_extensions",
      &safe_to_drop_output_extensions_);
  LoadSet(
      config,
      "files_filtering.safe_to_drop_input_extensions",
      &safe_to_drop_input_extensions_);
}

// static
void FilesFilter::LoadSet(
    const boost::property_tree::ptree& config,
    const std::string& node_path,
    std::unordered_set<std::string>* string_set) {
  auto extensions_node = config.get_child(node_path);
  for (const auto& name_and_node : extensions_node) {
    string_set->insert(name_and_node.second.data());
  }
}
