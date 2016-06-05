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

enum class RedisClientType {
  READ_WRITE,  // Connected to Redis master.
  READ_ONLY  // May be connected to Redis slave.
};

// Manages set of Redis clients, creating them as need.
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
       pool_->ReturnClient(std::move(client_), client_type_);
     }

     Result(Result&& second)
         : client_(std::move(second.client_)),
           pool_(second.pool_),
           client_type_(second.client_type_) { }

     Result(const Result&) = delete;
     const Result& operator = (const Result&) = delete;

   private:
     friend class RedisClientPool;
     Result(
         std::unique_ptr<RedisSyncClient> client,
         RedisClientPool* pool,
         RedisClientType client_type)
         : client_(std::move(client)),
           pool_(pool),
           client_type_(client_type) {
     }
     std::unique_ptr<RedisSyncClient> client_;
     RedisClientPool* pool_;
     const RedisClientType client_type_;
  };

  RedisClientPool(
      const std::string& redis_master_ip,
      const std::string& redis_slave_ip,
      int redis_port);
  ~RedisClientPool();

  Result GetClient(RedisClientType redis_client_type);

 private:
  void ReturnClient(
      std::unique_ptr<RedisSyncClient> client, RedisClientType client_type);
  std::unique_ptr<RedisSyncClient> ConnectNewClient(
      RedisClientType client_type);

  std::mutex instance_lock_;
  std::vector<std::unique_ptr<RedisSyncClient>> free_writable_clients_;
  std::vector<std::unique_ptr<RedisSyncClient>> free_read_only_clients_;

  const std::string redis_master_ip_;
  const std::string redis_slave_ip_;
  const int redis_port_;
};

#endif  // STEXECUTOR_REDIS_CLIENT_POOL_H_
