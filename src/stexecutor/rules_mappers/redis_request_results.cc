// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/redis_request_results.h"

#include "base/redis_key_prefixes.h"
#include "boost/archive/binary_iarchive.hpp"
#include "boost/archive/binary_oarchive.hpp"
#include "boost/lexical_cast.hpp"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/file_info.h"
#include "stexecutor/rules_mappers/file_set.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"RedisRequestResults");

// Special character, absent both in file paths and in content_id
// hex representation.
static const char kFileInfoSeparator[] = "*";

inline std::string FileSetHashToKey(const std::string& file_set_hash) {
  return redis_key_prefixes::kFileSets + file_set_hash;
}

inline std::string FileInfoHashToKey(const std::string& file_info_hash) {
  return redis_key_prefixes::kFileInfos + file_info_hash;
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

std::string FileInfoToHashKey(const rules_mappers::FileInfo& file_info) {
  rules_mappers::HashAlgorithm hasher;
  rules_mappers::HashString(
      &hasher,
      file_info.rel_file_path.generic_string());
  rules_mappers::HashString(
      &hasher,
      file_info.storage_content_id);
  rules_mappers::HashValue result;
  hasher.Final(result.data());
  return HashValueToString(result);
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
  const std::string key = RequestHashToRedisKey(request_hash);
  RedisValue redis_val = redis_client_->command(
      "LRANGE", key, "0", "-1");
  if (redis_val.isOk()) {
    MarkKeyAccessed(key);
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
  const std::string file_set_key = FileSetHashToKey(input_files_hash_string);
  SaveFileSet(file_set_key, file_set);
  MarkKeyAccessed(file_set_key);
  const std::string execution_response_key = RequestAndFileSetHashToKey(
      request_hash_,
      input_files_hash);
  SaveExecutionResponse(execution_response_key, *response);
  const std::string request_key = RequestHashToRedisKey(request_hash_);
  redis_client_->command(
      "RPUSH",
      request_key,
      input_files_hash_string);
  MarkKeyAccessed(request_key);
}

std::unique_ptr<CachedExecutionResponse>
RedisRequestResults::FindCachedResults(
    const BuildDirectoryState& build_dir_state,
    std::vector<FileInfo>* input_files) {
  input_files->clear();
  for (const auto& file_set : file_sets_) {
    if (FileSetMatchesBuildState(
        file_set,
        build_dir_state)) {
      const rules_mappers::HashValue file_set_hash = HashFileSet(file_set);
      const std::string response_key = RequestAndFileSetHashToKey(
          request_hash_,
          file_set_hash);
      std::unique_ptr<CachedExecutionResponse> result = LoadExecutionResponse(
          response_key);
      if (!result)
        return nullptr;
      *input_files = file_set.file_infos();
      MarkKeyAccessed(FileSetHashToKey(HashValueToString(file_set_hash)));
      return result;
    }
  }
  return nullptr;
}

bool RedisRequestResults::LoadFileInfo(
    const std::string& file_info_hash, FileInfo* file_info) {
  RedisValue file_info_val = redis_client_->command(
      "GET", FileInfoHashToKey(file_info_hash));
  if (!file_info_val.isOk()) {
    LOG4CPLUS_ERROR(
        logger_, "No file info for hash " << file_info_hash.c_str());
    return false;
  }
  std::string value = file_info_val.toString();
  auto separator_index = value.find(kFileInfoSeparator);
  if (separator_index == std::string::npos ||
      separator_index == (value.length() - 1)) {
    LOG4CPLUS_ERROR(
        logger_, "Wrong FileInfo format for hash " << file_info_hash.c_str());
    return false;
  }
  file_info->storage_content_id = value.substr(0, separator_index);
  file_info->rel_file_path = value.substr(separator_index + 1);
  return true;
}

void RedisRequestResults::SaveFileInfo(
    const std::string& key, const FileInfo& file_info) {
  std::stringstream value_stream;
  value_stream << file_info.storage_content_id;
  value_stream << kFileInfoSeparator;
  value_stream << file_info.rel_file_path.generic_string();
  redis_client_->command("SET", key, value_stream.str());
}

bool RedisRequestResults::LoadFileSet(
    const std::string& file_set_hash, FileSet* file_set) {
  // NOTE: we intentially do not mark keys "accessed" here - we want
  // only matched FileSet to update it time, to ensure separate FileSets
  // will expire idependently.
  RedisValue file_set_val = redis_client_->command(
      "LRANGE", FileSetHashToKey(file_set_hash), "0", "-1");
  if (!file_set_val.isOk()) {
    LOG4CPLUS_INFO(logger_, "No file set for hash " << file_set_hash.c_str());
    return false;
  }
  if (!file_set_val.isArray()) {
    LOG4CPLUS_ERROR(
        logger_, "File set is not an array " << file_set_hash.c_str());
    return false;
  }
  std::vector<RedisValue> entries = file_set_val.toArray();
  std::vector<FileInfo> file_infos;
  file_infos.reserve(entries.size());
  for (const RedisValue& file_info_key : entries) {
    FileInfo info;
    if (!LoadFileInfo(file_info_key.toString(), &info))
      return false;
    file_infos.push_back(info);
  }
  *file_set = FileSet(file_infos);
  return true;
}

std::unique_ptr<CachedExecutionResponse>
RedisRequestResults::LoadExecutionResponse(const std::string& key) {
  RedisValue response_val = redis_client_->command("GET", key);
  if (!response_val.isOk())
    return nullptr;
  std::unique_ptr<CachedExecutionResponse> result(
      new CachedExecutionResponse());
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
  std::vector<std::string> file_info_hashes;
  file_info_hashes.reserve(file_set.file_infos().size());
  for (const FileInfo& file_info : file_set.file_infos()) {
    std::string hash = FileInfoToHashKey(file_info);
    SaveFileInfo(FileInfoHashToKey(hash), file_info);
    file_info_hashes.push_back(hash);
  }
  redis_client_->command("MULTI");
  // Ensure list absent, if any.
  redis_client_->command("DEL", key);
  for (const std::string& hash : file_info_hashes) {
    redis_client_->command("RPUSH", key, hash);
  }
  redis_client_->command("EXEC");
}

void RedisRequestResults::SaveExecutionResponse(
    const std::string& key, const CachedExecutionResponse& response) {
  redis_client_->command("SET", key, SerializeToString(response));
}

void RedisRequestResults::MarkKeyAccessed(const std::string& key) {
  const auto now = std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now());
  redis_client_->command(
      "SET",
      redis_key_prefixes::kKeyTimeStamp + key,
      boost::lexical_cast<std::string>(now));
}

}  // namespace rules_mappers

