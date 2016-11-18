// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/interface.h"

#include <iostream>
#include <string>

#include "base/redis_client_pool.h"
#include "boost/property_tree/json_parser.hpp"

namespace interface {

namespace {

boost::program_options::options_description BuildProgramOptions() {
  namespace po = boost::program_options;

  boost::program_options::options_description general_desc("General");
  general_desc.add_options()
      (interface::kHelpOption, "Print help message")
      (interface::kSilentLogOption, "Do not print log messages to stdout")
      (interface::kBuildDirOption,
       po::value<boost::filesystem::path>()->required(),
        "Directory where build will run")
      (interface::kRulesMapperTypeOption,
       po::value<RulesMapperType>()->required(),
      "Rules mapper to use. Either \"in-memory\" or \"redis\"")
      (interface::kDumpEnvDirOption,
       po::value<boost::filesystem::path>(),
        "Directory to dump env blocks for debugging purposes")
      (interface::kConfigFileOption,
       po::value<boost::filesystem::path>()->required(),
        "Path to config JSON file with additional options");

  po::options_description in_memory_desc("InMemory rules mapper options");
  in_memory_desc.add_options()
      (interface::kDumpRulesDirOption,
       po::value<boost::filesystem::path>(),
        "Directory to dump observed rules for debugging purposes");

  po::options_description desc;
  desc.add(general_desc).add(in_memory_desc);
  return desc;
}

}  // namespace

const char kHelpOption[] = "help";
const char kSilentLogOption[] = "silent";
const char kBuildDirOption[] = "build_dir";
const char kRulesMapperTypeOption[] = "rules_mapper_type";
const char kDumpEnvDirOption[] = "dump_env_dir";
const char kConfigFileOption[] = "config_file";
const char kDumpRulesDirOption[] = "dump_rules_dir";

std::istream& operator >> (
    std::istream &in, RulesMapperType& rules_mapper_type) {  // NOLINT
  std::string token;
  in >> token;
  if (token == "in-memory")
    rules_mapper_type = RulesMapperType::InMemory;
  else if (token == "redis")
    rules_mapper_type = RulesMapperType::Redis;
  else
    throw boost::program_options::validation_error(
        boost::program_options::validation_error::invalid_option_value,
        "Invalid Rules mapper type");
  return in;
}

boost::property_tree::ptree LoadConfig(const boost::filesystem::path& path) {
  boost::filesystem::ifstream config_stream(path);
  boost::property_tree::ptree config;
  boost::property_tree::read_json(config_stream, config);
  return config;
}

bool ProcessOptions(
    int argc, const char* argv[],
    boost::program_options::variables_map* variables,
    const std::string& help_message) {
  const auto& desc = BuildProgramOptions();
  try {
    boost::program_options::store(
        boost::program_options::parse_command_line(argc, argv, desc),
        *variables);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return false;
  }
  if (variables->count(kHelpOption)) {
    if (!help_message.empty())
      std::cout << help_message << std::endl;
    std::cout << desc;
    return false;
  }
  try {
    boost::program_options::notify(*variables);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return false;
  }
  return true;
}

std::shared_ptr<RedisClientPool> BuildRedisClientPoolFromConfig(
    const boost::property_tree::ptree& config) {
  boost::property_tree::ptree redis_node = config.get_child("redis");

  std::string redis_sentinel_ip = redis_node.get<std::string>("sentinel_ip");
  std::string redis_slave_ip = redis_node.get<std::string>("slave_ip");
  int redis_sentinel_port = redis_node.get<int>("sentinel_port");
  int redis_slave_port = redis_node.get<int>("slave_port");
  std::string sentinel_master_name = redis_node.get<std::string>(
      "sentinel_master_name");

  return std::make_shared<RedisClientPool>(
          redis_sentinel_ip,
          redis_sentinel_port,
          redis_slave_ip,
          redis_slave_port,
          sentinel_master_name);
}

}  // namespace interface

