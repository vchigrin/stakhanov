// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/outputs_filter.h"

#include "boost/property_tree/ptree.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"OutputsFilter");

}  // namespace

OutputsFilter::OutputsFilter(const boost::property_tree::ptree& config) {
  try {
    LoadConfig(config);
  } catch(const std::exception& ex) {
    LOG4CPLUS_FATAL(logger_, "Error during config parsing " << ex.what());
  }
}

bool OutputsFilter::CanDropOutput(const boost::filesystem::path& path) const {
  std::lock_guard<std::mutex> lock(instance_lock_);
  return safe_to_drop_output_extensions_.count(
      path.extension().generic_string()) != 0;
}

void OutputsFilter::LoadConfig(const boost::property_tree::ptree& config) {
  auto extensions_node = config.get_child(
      "output_filtering.safe_to_drop_output_extensions");
  for (const auto& name_and_node : extensions_node) {
    safe_to_drop_output_extensions_.insert(name_and_node.second.data());
  }
}
