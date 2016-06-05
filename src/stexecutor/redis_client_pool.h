// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_REDIS_CLIENT_POOL_H_
#define STEXECUTOR_REDIS_CLIENT_POOL_H_

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "third_party/redisclient/src/redisclient/redissyncclient.h"

class RedisSyncClient;

// Manages set of Redis client, creating them as need.
// Need to parallelize RedisRulesMapper.
// This class is thread-safe.
class RedisClientPool {
 public:

  class Result {
   public:
     RedisSyncClient* client() {
       return client_.get();
     }

     ~Result() {
       pool_->ReturnClient(std::move(client_));
     }

     Result(Result&& second)
         : client_(std::move(second.client_)),
           pool_(second.pool_) { }

     Result(const Result&) = delete;
     const Result& operator = (const Result&) = delete;

   private:
     friend class RedisClientPool;
     Result(std::unique_ptr<RedisSyncClient> client, RedisClientPool* pool)
         : client_(std::move(client)),
           pool_(pool) {
     }
     std::unique_ptr<RedisSyncClient> client_;
     RedisClientPool* pool_;
  };

  RedisClientPool(const std::string& redis_ip, int redis_port);
  ~RedisClientPool();

  Result GetClient();

 private:
  void ReturnClient(std::unique_ptr<RedisSyncClient> client);
  std::unique_ptr<RedisSyncClient> ConnectNewClient();

  std::mutex instance_lock_;
  std::vector<std::unique_ptr<RedisSyncClient>> free_clients_;

  const std::string redis_ip_;
  const int redis_port_;
};

#endif  // STEXECUTOR_REDIS_CLIENT_POOL_H_
