// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_REDIS_CLIENT_POOL_H_
#define STEXECUTOR_REDIS_CLIENT_POOL_H_

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "third_party/redisclient/src/redisclient/redisasyncclient.h"
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
       pool_->ReturnClient(this);
     }

     Result(Result&& second)
         : client_(std::move(second.client_)),
           pool_(second.pool_),
           client_type_(second.client_type_),
           redis_master_ip_(second.redis_master_ip_),
           redis_master_port_(second.redis_master_port_) { }

     Result(const Result&) = delete;
     const Result& operator = (const Result&) = delete;

   private:
     friend class RedisClientPool;
     Result(
         std::unique_ptr<RedisSyncClient> client,
         RedisClientPool* pool,
         RedisClientType client_type,
         const std::string& redis_master_ip,
         int redis_master_port)
         : client_(std::move(client)),
           pool_(pool),
           client_type_(client_type),
           redis_master_ip_(redis_master_ip),
           redis_master_port_(redis_master_port) {
     }
     std::unique_ptr<RedisSyncClient> client_;
     RedisClientPool* pool_;
     const RedisClientType client_type_;
     // To avoid returning to pool clients, attached to old master
     // in case current master become inaccessible.
     const std::string redis_master_ip_;
     const int redis_master_port_;
  };

  RedisClientPool(
      const std::string& redis_sentinel_ip,
      int redis_sentinel_port,
      const std::string& redis_slave_ip,
      int redis_slave_port,
      const std::string& sentinel_master_name);
  ~RedisClientPool();

  Result GetClient(RedisClientType redis_client_type);
  bool IsInitialized() const;

 private:
  void ReturnClient(Result* result);
  std::unique_ptr<RedisSyncClient> ConnectNewClient(
      RedisClientType client_type);
  void RetrieveCurrentMasterAddress();
  void InitSentinelConnection();
  void OnMasterSwitched(const std::vector<char>& msg);
  void IOServiceThread();

  std::mutex instance_lock_;
  std::vector<std::unique_ptr<RedisSyncClient>> free_writable_clients_;
  std::vector<std::unique_ptr<RedisSyncClient>> free_read_only_clients_;
  std::unique_ptr<RedisAsyncClient> sentinel_client_;
  RedisAsyncClient::Handle sentinel_subscription_handle_;
  std::unique_ptr<boost::asio::io_service> io_service_;
  std::thread io_service_thread_;

  const std::string sentinel_ip_;
  const int sentinel_port_;
  const std::string slave_ip_;
  const int slave_port_;
  std::string current_master_ip_;
  int current_master_port_;
  const std::string sentinel_master_name_;
};

#endif  // STEXECUTOR_REDIS_CLIENT_POOL_H_
