// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/interface.h"

#include <iostream>
#include <string>

#include "base/redis_client_pool.h"
#include "boost/property_tree/json_parser.hpp"

namespace interface {

boost::property_tree::ptree LoadConfig(const boost::filesystem::path& path) {
  boost::filesystem::ifstream config_stream(path);
  boost::property_tree::ptree config;
  boost::property_tree::read_json(config_stream, config);
  return config;
}

bool ProcessOptions(
    const boost::program_options::options_description& desc,
    int argc, const char* argv[],
    boost::program_options::variables_map* variables,
    const std::string& help_message) {
  try {
    boost::program_options::store(
        boost::program_options::parse_command_line(argc, argv, desc),
        *variables);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return false;
  }
  if (variables->count("help")) {
    if (!help_message.empty())
      std::cout << help_message << std::endl;
    std::cout << desc;
    return false;
  }

#if defined(STAKHANOV_LASTCHANGE)
  if (variables->count("version")) {
    std::cout << STAKHANOV_LASTCHANGE << std::endl;
    return false;
  }
#endif

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

