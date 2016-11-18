// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_INTERFACE_H_
#define BASE_INTERFACE_H_

#include <memory>
#include <string>

#include "boost/filesystem.hpp"
#include "boost/program_options.hpp"
#include "boost/property_tree/ptree.hpp"

class RedisClientPool;

namespace interface {

extern const char kHelpOption[];
extern const char kSilentLogOption[];
extern const char kBuildDirOption[];
extern const char kRulesMapperTypeOption[];
extern const char kDumpEnvDirOption[];
extern const char kConfigFileOption[];
extern const char kDumpRulesDirOption[];

enum class RulesMapperType {
  InMemory,
  Redis
};

boost::property_tree::ptree LoadConfig(const boost::filesystem::path& path);

bool ProcessOptions(
    int argc, const char* argv[],
    boost::program_options::variables_map* variables,
    const std::string& help_message);

std::shared_ptr<RedisClientPool> BuildRedisClientPoolFromConfig(
    const boost::property_tree::ptree& config);

}  // namespace interface

#endif  // BASE_INTERFACE_H_
