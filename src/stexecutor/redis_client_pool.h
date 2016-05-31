// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_REDIS_CLIENT_POOL_H_
#define STEXECUTOR_REDIS_CLIENT_POOL_H_

#include <memory>
#include <mutex>
#include <string>
#include <vector>

class RedisSyncClient;

// Manages set of Redis client, creating them as need.
// Need to parallelize RedisRulesMapper.
// This class is thread-safe.
class RedisClientPool {
 public:
  RedisClientPool(const std::string& redis_ip, int redis_port);
  ~RedisClientPool();
  std::unique_ptr<RedisSyncClient> GetClient();
  void ReturnClient(std::unique_ptr<RedisSyncClient> client);

 private:
  std::unique_ptr<RedisSyncClient> ConnectNewClient();

  std::mutex instance_lock_;
  std::vector<std::unique_ptr<RedisSyncClient>> free_clients_;

  const std::string redis_ip_;
  const int redis_port_;
};

#endif  // STEXECUTOR_REDIS_CLIENT_POOL_H_
