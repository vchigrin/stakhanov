// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/redis_key_scanner.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"RedisKeyScanner");
}  // namespace

RedisKeyScanner::RedisKeyScanner(RedisSyncClient* client,
                const std::string& match_restriction)
    : client_(client),
      match_restriction_(match_restriction),
      current_cursor_("0") {
}

bool RedisKeyScanner::FetchNext() {
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
  std::vector<RedisValue> redis_keys = reply_array[1].toArray();
  for (const RedisValue& val : redis_keys) {
    std::string key = val.toString();
    if (!key.empty())
      current_results_.push_back(val.toString());
    else
      LOG4CPLUS_ERROR(logger_, "Unexpected reply from Scan command");
  }
  return current_cursor_ != "0";
}

