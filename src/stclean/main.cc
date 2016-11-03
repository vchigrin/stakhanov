// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <iostream>
#include <regex>

#include "base/init_logging.h"
#include "base/interface.h"
#include "base/redis_client_pool.h"
#include "base/redis_key_prefixes.h"
#include "boost/algorithm/string.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

static const int kKeysInBatch = 1000;
log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

void RemoveRule(RedisSyncClient* client, const std::string& key) {
  // TODO(vchigrin): Implement this.
  std::cout << "Removing rule " << key << std::endl;
}

void RemoveFileSet(RedisSyncClient* client, const std::string& key) {
  // TODO(vchigrin): Implement this.
  std::cout << "Removing file set " << key << std::endl;
}

std::multimap<time_t, std::string> LoadKeyAccessTimes(
    RedisSyncClient* client) {
  // TODO(vchigrin): Implement this.
  return std::multimap<time_t, std::string>();
}

void RemoveKey(RedisSyncClient* client, const std::string& key) {
  if (boost::algorithm::starts_with(
        key, std::string(redis_key_prefixes::kRules))) {
    RemoveRule(client, key);
  } else if (boost::algorithm::starts_with(
      key, std::string(redis_key_prefixes::kFileSets))) {
    RemoveFileSet(client, key);
  } else {
    LOG4CPLUS_ERROR(logger_, "Unknown key type " << key.c_str());
  }
}

int64_t GetRedisMemoryUsage(RedisSyncClient* client) {
  RedisValue reply = client->command("INFO", "MEMORY");
  std::string reply_text = reply.toString();
  std::regex re("used_memory:(\\d+)");
  std::smatch match;
  if (!std::regex_search(reply_text, match, re)) {
    LOG4CPLUS_FATAL(
        logger_, "Unexpected reply from Redis " << reply_text.c_str());
    return -1;
  }
  try {
    return boost::lexical_cast<int64_t>(match[1]);
  } catch(const boost::bad_lexical_cast&) {
    LOG4CPLUS_FATAL(
        logger_, "Unexpected reply from Redis " << reply_text.c_str());
    return -1;
  }
}

void CleanRedisToSize(
    RedisSyncClient* client, int64_t target_number_of_bytes) {
  int64_t current_size = GetRedisMemoryUsage(client);
  if (current_size < 0)
    return;
  if (current_size <= target_number_of_bytes) {
    std::cout << "Redis consumes only " << current_size
              << " bytes, no cleanup required." << std::endl;
    return;
  }
  // Kill all other clients, if any, to ensure they will not be surprised
  // by suddenly disappeared keys.
  client->command("CLIENT", "KILL", "TYPE", "normal");
  std::multimap<time_t, std::string> last_access_time_to_key =
     LoadKeyAccessTimes(client);
  int counter = 0;
  // Iterate from oldest key to newest
  for (auto it = last_access_time_to_key.begin();
      it != last_access_time_to_key.end(); ++it) {
    RemoveKey(client, it->second);
    counter++;
    if (counter % kKeysInBatch == 0) {
      current_size = GetRedisMemoryUsage(client);
      if (current_size < 0)
        return;
      std::cout << "After removing " << counter << " keys Redis consumes "
                << current_size << " bytes" << std::endl;
      if (current_size <= target_number_of_bytes)
        break;
    }
  }
}

}  // namespace

int main(int argc, const char* argv[]) {
  base::InitLogging(true);
  boost::program_options::options_description desc;
  desc.add_options()
      ("help", "Print help message")
      ("config_file",
       boost::program_options::value<boost::filesystem::path>()->required(),
        "Path to config JSON file with additional options")
      ("target_number_of_bytes",
       boost::program_options::value<int64_t>()->required(),
       "Cleanup will proceed until memory consumption of redis master will "
       "not drop below or equal to that number of bytes. \n"
       "Determined by 'used_memory' field in Redis 'INFO' command");

  boost::program_options::variables_map variables;
  if (!interface::ProcessOptions(desc, argc, argv, &variables))
    return 1;
  boost::property_tree::ptree config = interface::LoadConfig(
      variables["config_file"].as<boost::filesystem::path>());
  std::shared_ptr<RedisClientPool> redis_client_pool =
      interface::BuildRedisClientPoolFromConfig(config);
  if (!redis_client_pool->IsInitialized()) {
    std::cerr << "Failed connect to Redis instance" << std::endl;
    return 1;
  }
  int64_t target_number_of_bytes =
      variables["target_number_of_bytes"].as<int64_t>();
  auto redis_result = redis_client_pool->GetClient(
      RedisClientType::READ_WRITE);
  CleanRedisToSize(redis_result.client(), target_number_of_bytes);
  return 0;
}
