// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/redis_rules_mapper.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/rules_mappers/cached_execution_response.h"
#include "stexecutor/rules_mappers/redis_request_results.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"
#include "third_party/redisclient/src/redisclient/redisvalue.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"RedisRulesMapper");

}  // namespace

namespace rules_mappers {

RedisRulesMapper::RedisRulesMapper(
    std::unique_ptr<RedisSyncClient> redis_client)
    : redis_client_(std::move(redis_client)) { }

RedisRulesMapper::~RedisRulesMapper() { }

std::shared_ptr<const CachedExecutionResponse>
RedisRulesMapper::FindCachedResults(
    const ProcessCreationRequest& process_creation_request,
    const BuildDirectoryState& build_dir_state,
    std::vector<FileInfo>* input_files) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  RedisRequestResults request_results(redis_client_.get(), request_hash);
  return request_results.FindCachedResults(build_dir_state, input_files);
}

void RedisRulesMapper::AddRule(
    const ProcessCreationRequest& process_creation_request,
    const std::vector<FileInfo>& input_files,
    std::unique_ptr<CachedExecutionResponse> response) {
  HashValue request_hash = ComputeProcessCreationHash(
      process_creation_request);
  std::unique_ptr<RedisRequestResults> results(
      new RedisRequestResults(redis_client_.get(), request_hash));
  results->AddRule(input_files, std::move(response));
}

}  // namespace rules_mappers

