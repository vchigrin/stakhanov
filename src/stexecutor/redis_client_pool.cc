// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/redis_client_pool.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

void OnRedisError(const std::string& error_msg) {
  LOG4CPLUS_ERROR(logger_, "REDIS ERROR " << error_msg.c_str());
}

boost::asio::io_service& GetIOService() {
  static std::unique_ptr<boost::asio::io_service> result;
  if (!result) {
    result.reset(new boost::asio::io_service());
  }
  return *result;
}

}  // namespace

RedisClientPool::RedisClientPool(
    const std::string& redis_master_ip,
    const std::string& redis_slave_ip,
    int redis_port)
    : redis_master_ip_(redis_master_ip),
      redis_slave_ip_(redis_slave_ip),
      redis_port_(redis_port) {
}

RedisClientPool::~RedisClientPool() {
}

RedisClientPool::Result RedisClientPool::GetClient(
    RedisClientType client_type) {
  std::vector<std::unique_ptr<RedisSyncClient>>* free_clients =
      client_type == RedisClientType::READ_WRITE ?
          &free_writable_clients_ : &free_read_only_clients_;
  // Quick check - may be no need to lock mutex since no clients...
  if (!free_clients->empty()) {
    std::lock_guard<std::mutex> instance_lock(instance_lock_);
    if (!free_clients->empty()) {
      std::unique_ptr<RedisSyncClient> result(
          free_clients->rbegin()->release());
      free_clients->pop_back();
      return Result(std::move(result), this, client_type);
    }
  }
  return Result(ConnectNewClient(client_type), this, client_type);
}

void RedisClientPool::ReturnClient(
    std::unique_ptr<RedisSyncClient> client, RedisClientType client_type) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  std::vector<std::unique_ptr<RedisSyncClient>>* free_clients =
      client_type == RedisClientType::READ_WRITE ?
          &free_writable_clients_ : &free_read_only_clients_;
  free_clients->push_back(std::move(client));
}

std::unique_ptr<RedisSyncClient> RedisClientPool::ConnectNewClient(
    RedisClientType client_type) {
  std::unique_ptr<RedisSyncClient> redis_client(
      new RedisSyncClient(GetIOService()));

  boost::asio::ip::address server_ip;
  if (client_type == RedisClientType::READ_WRITE)
    server_ip = boost::asio::ip::address::from_string(redis_master_ip_);
  else
    server_ip = boost::asio::ip::address::from_string(redis_slave_ip_);

  boost::asio::ip::tcp::endpoint endpoint(server_ip, redis_port_);
  std::string errmsg;
  if (!redis_client->connect(endpoint, errmsg)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed connect to the Redis server " << errmsg.c_str());
    return nullptr;
  }
  redis_client->installErrorHandler(OnRedisError);
  return redis_client;
}
