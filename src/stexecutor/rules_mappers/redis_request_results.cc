// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/redis_request_results.h"

#include "boost/archive/binary_iarchive.hpp"
#include "boost/archive/binary_oarchive.hpp"
#include "stexecutor/redis_key_prefixes.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/file_info.h"
#include "stexecutor/rules_mappers/file_set.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"RedisRequestResults");

inline std::string FileSetHashToKey(const std::string& file_set_hash) {
  return redis_key_prefixes::kFileSets + file_set_hash;
}

inline std::string RequestAndFileSetHashToKey(
    const rules_mappers::HashValue& request_hash,
    const rules_mappers::HashValue& file_set_hash) {
  std::stringstream redis_key_buf;
  redis_key_buf << redis_key_prefixes::kResponse;
  redis_key_buf << request_hash;
  redis_key_buf << "_";
  redis_key_buf << file_set_hash;
  return redis_key_buf.str();
}

std::string RequestHashToRedisKey(
    const rules_mappers::HashValue& request_hash) {
  std::stringstream redis_key_buf;
  redis_key_buf << redis_key_prefixes::kRules;
  redis_key_buf << request_hash;
  return redis_key_buf.str();
}

rules_mappers::HashValue HashFileSet(const rules_mappers::FileSet& file_set) {
  rules_mappers::HashAlgorithm hasher;
  for (const rules_mappers::FileInfo& file_info : file_set.file_infos()) {
    rules_mappers::HashString(
        &hasher,
        file_info.rel_file_path.generic_string());
    rules_mappers::HashString(
        &hasher,
        file_info.storage_content_id);
  }
  rules_mappers::HashValue result;
  hasher.Final(result.data());
  return result;
}

template<typename T>
bool LoadObject(const RedisValue& val, T* result) {
  std::stringbuf buffer(val.toString());
  boost::archive::binary_iarchive input(buffer);
  try {
    input >> (*result);
  } catch(const std::exception&) {
    return false;
  }
  return true;
}

template<typename T>
std::string SerializeToString(const T& value) {
  std::stringbuf buffer;
  boost::archive::binary_oarchive output(buffer);
  output << value;
  return buffer.str();
}

}  // namespace

namespace rules_mappers {

RedisRequestResults::RedisRequestResults(
    RedisSyncClient* redis_client,
    const HashValue& request_hash)
    : redis_client_(redis_client),
      request_hash_(request_hash) {
  // Get the whole list.
  RedisValue redis_val = redis_client_->command(
      "LRANGE", RequestHashToRedisKey(request_hash), "0", "-1");
  if (redis_val.isOk()) {
    std::vector<RedisValue> file_set_hashes = redis_val.toArray();
    file_sets_.reserve(file_set_hashes.size());
    for (const RedisValue& file_set_hash : file_set_hashes) {
      FileSet file_set;
      if (LoadFileSet(file_set_hash.toString(), &file_set)) {
        file_sets_.push_back(std::move(file_set));
      }
    }
  }
}

RedisRequestResults::~RedisRequestResults() {}

void RedisRequestResults::AddRule(
    const std::vector<FileInfo>& input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  FileSet file_set(input_files);
  HashValue input_files_hash = HashFileSet(file_set);
  std::string input_files_hash_string = HashValueToString(input_files_hash);
  SaveFileSet(FileSetHashToKey(input_files_hash_string), file_set);
  std::string key = RequestAndFileSetHashToKey(
      request_hash_,
      input_files_hash);
  SaveExecutionResponse(key, *response);
  redis_client_->command(
      "RPUSH",
      RequestHashToRedisKey(request_hash_),
      input_files_hash_string);
}

std::shared_ptr<const CachedExecutionResponse>
RedisRequestResults::FindCachedResults(
    const BuildDirectoryState& build_dir_state,
    std::vector<FileInfo>* input_files) {
  input_files->clear();
  for (const auto& file_set : file_sets_) {
    if (FileSetMatchesBuildState(
        file_set,
        build_dir_state)) {
      std::string key = RequestAndFileSetHashToKey(
          request_hash_,
          HashFileSet(file_set));
      std::shared_ptr<CachedExecutionResponse> result = LoadExecutionResponse(
          key);
      if (!result)
        return nullptr;
      *input_files = file_set.file_infos();
      return result;
    }
  }
  return nullptr;
}

bool RedisRequestResults::LoadFileSet(
    const std::string& file_set_hash, FileSet* file_set) {
  RedisValue file_set_val = redis_client_->command(
      "GET", FileSetHashToKey(file_set_hash));
  if (!file_set_val.isOk()) {
    LOG4CPLUS_INFO(logger_, "No file set for hash " << file_set_hash.c_str());
    return false;
  }
  if (!LoadObject(file_set_val, file_set)) {
    LOG4CPLUS_ERROR(
        logger_, "Corrupt file set for hash " << file_set_hash.c_str());
    return false;
  }
  return true;
}

std::shared_ptr<CachedExecutionResponse>
RedisRequestResults::LoadExecutionResponse(const std::string& key) {
  RedisValue response_val = redis_client_->command("GET", key);
  if (!response_val.isOk())
    return nullptr;
  std::shared_ptr<CachedExecutionResponse> result =
      std::make_shared<CachedExecutionResponse>();
  if (!LoadObject(response_val, result.get())) {
    LOG4CPLUS_ERROR(
        logger_,
        "Corrupt Redis value for execution response");
    return nullptr;
  }
  return result;
}

void RedisRequestResults::SaveFileSet(
    const std::string& key, const FileSet& file_set) {
  redis_client_->command("SET", key, SerializeToString(file_set));
}

void RedisRequestResults::SaveExecutionResponse(
    const std::string& key, const CachedExecutionResponse& response) {
  redis_client_->command("SET", key, SerializeToString(response));
}

}  // namespace rules_mappers

