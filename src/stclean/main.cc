// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <iostream>
#include <regex>
#include <unordered_map>
#include <unordered_set>

#include "base/init_logging.h"
#include "base/interface.h"
#include "base/redis_client_pool.h"
#include "base/redis_key_prefixes.h"
#include "boost/algorithm/string.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

// TODO(vchigrin): There is a lot of common logic in this file and
// redis_request_results.cc. Refactor it to separate library.
static const char kFileInfoSeparator[] = "*";

static const int kKeysInBatch = 1000;
log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

using FileSetKeyToRuleKeys =
    std::unordered_map<std::string, std::vector<std::string>>;

// Helper class to iterate through results of SCAN command with
// MATCH restriction
class Scanner {
 public:
  Scanner(RedisSyncClient* client, const std::string& match_restriction)
      : client_(client),
        match_restriction_(match_restriction),
        current_cursor_("0") {
  }
  const std::vector<RedisValue>& current_results() const {
    return current_results_;
  }

  // Returne false if this was the last chunk of data, and
  // FetchNext should not be called any more.
  bool FetchNext();

 private:
  RedisSyncClient* client_;
  const std::string match_restriction_;
  std::string current_cursor_;
  std::vector<RedisValue> current_results_;
};

bool Scanner::FetchNext() {
  current_results_.empty();
  RedisValue scan_reply = client_->command(
      "SCAN", current_cursor_, "MATCH", match_restriction_);
  std::vector<RedisValue> reply_array = scan_reply.toArray();
  if (reply_array.size() != 2) {
    LOG4CPLUS_ERROR(logger_, "Invalid reply on SCAN command");
    return false;
  }
  current_cursor_ = reply_array[0].toString();
  if (current_cursor_.empty()) {
    LOG4CPLUS_ERROR(logger_, "Invalid reply on SCAN command");
    return false;
  }
  current_results_ = reply_array[1].toArray();
  return current_cursor_ != "0";
}

void RemoveRule(RedisSyncClient* client, const std::string& key) {
  client->command("DEL", key);
  // Delete all replies, associated with that rule.
  // We don't touch FileSets, since they may be shared. And in any case,
  // they have their own timestamps and will be deleted eventually.
  const std::string request_hash = key.substr(key.find(':') + 1);
  const std::string match_restriction =
      std::string(redis_key_prefixes::kResponse) + request_hash + "_*";
  Scanner scanner(client, match_restriction);
  bool has_more_data = false;
  do {
    has_more_data = scanner.FetchNext();
    const std::vector<RedisValue>& response_keys = scanner.current_results();
    for (const RedisValue& response_key : response_keys) {
      std::string response_key_str = response_key.toString();
      client->command("DEL", response_key_str);
    }
  } while (has_more_data);
}

std::multimap<time_t, std::string> LoadKeyAccessTimes(
    RedisSyncClient* client) {
  const size_t key_timestamp_prefix_len =
      strlen(redis_key_prefixes::kKeyTimeStamp);
  std::multimap<time_t, std::string> result;
  const std::string match_restriction =
      std::string(redis_key_prefixes::kKeyTimeStamp) + "*";
  Scanner scanner(client, match_restriction);
  bool has_more_data = false;
  do {
    has_more_data = scanner.FetchNext();
    const std::vector<RedisValue>& timestamp_keys = scanner.current_results();
    for (const RedisValue& timestamp_key : timestamp_keys) {
      std::string timestamp_key_str = timestamp_key.toString();
      std::string timestamp_str =
          client->command("GET", timestamp_key_str).toString();
      if (timestamp_str.empty()) {
        LOG4CPLUS_ERROR(
            logger_, "Corrupt timestamp key " << timestamp_key_str.c_str());
        continue;
      }
      time_t timestamp = boost::lexical_cast<time_t>(timestamp_str);
      result.insert(
          std::make_pair(timestamp,
                         timestamp_key_str.substr(key_timestamp_prefix_len)));
    }
  } while (has_more_data);
  return result;
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

FileSetKeyToRuleKeys LoadFileSetKeyToRuleKeys(RedisSyncClient* client) {
  Scanner scanner(client, std::string(redis_key_prefixes::kRules) + "*");
  bool has_more_data = false;
  std::unordered_map<std::string, std::vector<std::string>> result;
  do {
    has_more_data = scanner.FetchNext();
    const std::vector<RedisValue>& rule_keys = scanner.current_results();
    for (const RedisValue& rule_key : rule_keys) {
      std::string rule_key_str = rule_key.toString();
      RedisValue redis_val = client->command(
          "LRANGE", rule_key_str, "0", "-1");
      std::vector<RedisValue> file_set_hashes = redis_val.toArray();
      for (const RedisValue& file_set_hash : file_set_hashes) {
        const std::string file_set_hash_str = file_set_hash.toString();
        if (file_set_hash_str.empty()) {
          LOG4CPLUS_ERROR(logger_, "Empty file set hash detected");
          continue;
        }
        std::string file_set_key = std::string(redis_key_prefixes::kFileSets) +
            file_set_hash_str;
        result[file_set_key].push_back(rule_key_str);
      }
    }
  } while (has_more_data);
  return result;
}

inline std::string RuleAndFileSetKeysToResponseKey(
    const std::string& rule_key,
    const std::string& file_set_key) {
  std::stringstream redis_key_buf;
  redis_key_buf << redis_key_prefixes::kResponse;
  redis_key_buf << rule_key.substr(rule_key.find(':') + 1);
  redis_key_buf << "_";
  redis_key_buf << file_set_key.substr(file_set_key.find(':') + 1);
  return redis_key_buf.str();
}

void RemoveFileSets(
    RedisSyncClient* client,
    const std::vector<std::string>& file_set_keys,
    const FileSetKeyToRuleKeys& file_set_to_rule_keys) {
  for (const std::string& file_set_key : file_set_keys) {
    // Remove mention of that FileSet from all rules, if any.
    auto it = file_set_to_rule_keys.find(file_set_key);
    if (it != file_set_to_rule_keys.end()) {
      // There may be no rule for that FileSet in case it was deleted
      // some time before. It is OK.
      for (const std::string& rule_key : it->second) {
        client->command("LREM", rule_key, "0", file_set_key);
        // Delete corresponding response.
        const std::string response_key = RuleAndFileSetKeysToResponseKey(
            rule_key, file_set_key);
        client->command("DEL", response_key);
      }
    }
    client->command("DEL", file_set_key);
    client->command(
        "DEL", std::string(redis_key_prefixes::kKeyTimeStamp) + file_set_key);
  }
}

void RemoveKeysByAccessTime(
    RedisSyncClient* client, int64_t target_number_of_bytes) {
  std::multimap<time_t, std::string> last_access_time_to_key =
     LoadKeyAccessTimes(client);
  int counter = 0;
  // Maps fileset key to vector of rules keys, in which that fileset
  // participates.
  FileSetKeyToRuleKeys fileset_key_to_rule_keys =
      LoadFileSetKeyToRuleKeys(client);
  std::vector<std::string> removed_file_set_keys;
  // Iterate from oldest key to newest.
  for (auto it = last_access_time_to_key.begin();
      it != last_access_time_to_key.end(); ++it) {
    const std::string& key = it->second;
    if (boost::algorithm::starts_with(
          key, std::string(redis_key_prefixes::kRules))) {
      RemoveRule(client, key);
      client->command(
          "DEL", std::string(redis_key_prefixes::kKeyTimeStamp) + key);
    } else if (boost::algorithm::starts_with(
        key, std::string(redis_key_prefixes::kFileSets))) {
      removed_file_set_keys.push_back(key);
    } else {
      LOG4CPLUS_ERROR(logger_, "Unknown key type " << key.c_str());
    }
    counter++;
    if (counter % kKeysInBatch == 0) {
      RemoveFileSets(client, removed_file_set_keys, fileset_key_to_rule_keys);
      removed_file_set_keys.clear();
      auto current_size = GetRedisMemoryUsage(client);
      if (current_size < 0)
        return;
      std::cout << "After removing " << counter << " keys Redis consumes "
                << current_size << " bytes" << std::endl;
      if (current_size <= target_number_of_bytes)
        break;
    }
  }
  RemoveFileSets(client, removed_file_set_keys, fileset_key_to_rule_keys);
}

void LoadUsedContentIdAndFileInfoKeys(
    RedisSyncClient* client,
    std::unordered_set<std::string>* used_content_id_keys,
    std::unordered_set<std::string>* used_file_info_keys) {
  const std::string match_restriction =
      std::string(redis_key_prefixes::kFileSets) + "_*";
  Scanner scanner(client, match_restriction);
  bool has_more_data = false;
  do {
    has_more_data = scanner.FetchNext();
    const std::vector<RedisValue>& file_set_keys = scanner.current_results();
    for (const RedisValue& file_set_key : file_set_keys) {
      RedisValue file_set_val = client->command(
          "LRANGE", file_set_key.toString(), "0", "-1");
      std::vector<RedisValue> file_info_entries = file_set_val.toArray();
      for (const RedisValue& file_info_entry : file_info_entries) {
        const std::string file_info_key =
            std::string(redis_key_prefixes::kFileInfos) +
            file_info_entry.toString();
        used_file_info_keys->insert(file_info_key);
        RedisValue file_info_val = client->command("GET", file_info_key);
        std::string value = file_info_val.toString();
        auto separator_index = value.find(kFileInfoSeparator);
        if (separator_index == std::string::npos ||
            separator_index == (value.length() - 1)) {
          LOG4CPLUS_ERROR(
              logger_,
              "Wrong FileInfo format for key " << file_info_key.c_str());
          continue;
        }
        std::string storage_content_id = value.substr(0, separator_index);
        used_content_id_keys->insert(
            std::string(redis_key_prefixes::kStoredFileHosts) +
            storage_content_id);
      }
    }
  } while (has_more_data);
}

int64_t RemoveOrphanedKeys(
    RedisSyncClient* client,
    const std::unordered_set<std::string>& used_keys,
    const std::string& key_prefix) {
  Scanner scanner(client, key_prefix + "*");
  bool has_more_data = false;
  int64_t deleted_key_count = 0;
  do {
    has_more_data = scanner.FetchNext();
    const std::vector<RedisValue>& present_keys = scanner.current_results();
    for (const RedisValue& key : present_keys) {
      std::string key_str = key.toString();
      if (used_keys.count(key_str) == 0) {
        client->command("DEL", key_str);
        deleted_key_count++;
      }
    }
  } while (has_more_data);
  return deleted_key_count;
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
  RemoveKeysByAccessTime(client, target_number_of_bytes);
  std::cout << "Loading information about used FileInfos and content ids..."
            << std::endl;
  std::unordered_set<std::string> used_content_id_keys;
  std::unordered_set<std::string> used_file_info_keys;
  LoadUsedContentIdAndFileInfoKeys(
      client, &used_content_id_keys, &used_file_info_keys);
  std::cout << "Removing orphaned FileInfos..." << std::endl;
  auto deleted_key_count = RemoveOrphanedKeys(
      client, used_file_info_keys, redis_key_prefixes::kFileInfos);
  std::cout << deleted_key_count << " keys deleted." << std::endl;
  std::cout << "Removing orphaned content ids..." << std::endl;
  deleted_key_count = RemoveOrphanedKeys(
      client, used_content_id_keys, redis_key_prefixes::kStoredFileHosts);
  std::cout << deleted_key_count << " keys deleted." << std::endl;
  current_size = GetRedisMemoryUsage(client);
  std::cout << "Finished: after removing Redis consumes " << current_size
            << " bytes" << std::endl;
}

void CleanFileStorageFromOrphanedEntries(RedisSyncClient* redis_client) {
  // TODO(vchigrin):
}

}  // namespace

int main(int argc, const char* argv[]) {
  base::InitLogging(true);
  boost::program_options::options_description desc;
  desc.add_options()
      ("help", "Print help message")
      ("mode",
       boost::program_options::value<std::string>()->required(),
      "Mode of operation. Either clean-redis or clean-files-storage")
      ("config_file",
       boost::program_options::value<boost::filesystem::path>()->required(),
        "Path to config JSON file with additional options");

  boost::program_options::options_description redis_options(
      "Options for clean-redis mode");
  redis_options.add_options()
      ("target_redis_number_of_bytes",
       boost::program_options::value<int64_t>(),
       "Cleanup will proceed until memory consumption of redis master will "
       "not drop below or equal to that number of bytes. \n"
       "Determined by 'used_memory' field in Redis 'INFO' command");

  desc.add(redis_options);

  boost::program_options::variables_map variables;
  static const char* kHelp =
      "clean-redis mode removes old entries from redis DB.\n"
      "Please, ensure there are no any build running on that Redis DB \n"
      "while cleanup in progress.\n\n"
      "clean-files-storage mode removes entries from files storage\n"
      "that are no more referred by any key in Redis DB. It can be performed\n"
      "in parallel with building on OTHER machines connected to the same"
      "Redis DB\n";
  if (!interface::ProcessOptions(desc, argc, argv, &variables, kHelp))
    return 1;
  const std::string mode = variables["mode"].as<std::string>();
  const bool clean_redis = (mode == "clean-redis");
  const bool clean_files_storage = (mode == "clean-files-storage");
  if (!clean_redis && !clean_files_storage) {
    std::cerr
        << "Mode must be either clean-redis or clean-files-storage"
        << std::endl;
    return 1;
  }
  boost::property_tree::ptree config = interface::LoadConfig(
      variables["config_file"].as<boost::filesystem::path>());
  std::shared_ptr<RedisClientPool> redis_client_pool =
      interface::BuildRedisClientPoolFromConfig(config);
  if (!redis_client_pool->IsInitialized()) {
    std::cerr << "Failed connect to Redis instance" << std::endl;
    return 1;
  }
  if (clean_redis) {
    int64_t target_number_of_bytes = 0;
    try {
      target_number_of_bytes =
          variables["target_redis_number_of_bytes"].as<int64_t>();
    } catch (const std::exception& ex) {
      std::cerr
          << "clean-redis mode requires integer target_redis_number_of_bytes"
          << std::endl;
      return 1;
    }
    auto redis_result = redis_client_pool->GetClient(
        RedisClientType::READ_WRITE);
    CleanRedisToSize(redis_result.client(), target_number_of_bytes);
  } else if (clean_files_storage) {
    auto redis_result = redis_client_pool->GetClient(
        RedisClientType::READ_ONLY);
    CleanFileStorageFromOrphanedEntries(redis_result.client());
  }
  return 0;
}
