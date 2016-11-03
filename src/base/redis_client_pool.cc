// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/redis_client_pool.h"

#include <future>

#include "boost/bind.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

void OnRedisError(const std::string& error_msg) {
  // Note: It may be invoked during unsubscription from channel, e.g.
  // for Redis Sentinel clients.
  // TODO(vchigrin): Fix this (may be in thirdparty library).
  // We should cleanly separate errors from normal unsubscription.
  LOG4CPLUS_ERROR(logger_, "REDIS ERROR " << error_msg.c_str());
}

}  // namespace

RedisClientPool::RedisClientPool(
    const std::string& redis_sentinel_ip,
    int redis_sentinel_port,
    const std::string& redis_slave_ip,
    int redis_slave_port,
    const std::string& sentinel_master_name)
    : sentinel_ip_(redis_sentinel_ip),
      sentinel_port_(redis_sentinel_port),
      slave_ip_(redis_slave_ip),
      slave_port_(redis_slave_port),
      current_master_port_(0),
      sentinel_master_name_(sentinel_master_name),
      io_service_(new boost::asio::io_service()) {
  InitSentinelConnection();
  if (sentinel_client_)
    RetrieveCurrentMasterAddress();
}

RedisClientPool::~RedisClientPool() {
  if (sentinel_client_ && !sentinel_subscription_handle_.channel.empty())
    sentinel_client_->unsubscribe(sentinel_subscription_handle_);
  // Destroy all clients before IO service stopping.
  free_writable_clients_.clear();
  free_read_only_clients_.clear();
  sentinel_client_.reset(nullptr);
  io_service_->stop();
  io_service_thread_.join();
}

RedisClientPool::Result RedisClientPool::GetClient(
    RedisClientType client_type) {
  if (!IsInitialized()) {
    LOG4CPLUS_ERROR(logger_, "RedisClientPool isn't initialized successfully");
    return Result(nullptr, this, client_type,
                  current_master_ip_, current_master_port_);
  }
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
      return Result(std::move(result), this, client_type,
                    current_master_ip_, current_master_port_);
    }
  }
  if (client_type == RedisClientType::READ_WRITE) {
    return Result(ConnectNewClient(client_type),
                  this, client_type, current_master_ip_, current_master_port_);
  } else {
    return Result(ConnectNewClient(client_type),
                  this, client_type, current_master_ip_, current_master_port_);
  }
}

void RedisClientPool::ReturnClient(Result* result) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  std::vector<std::unique_ptr<RedisSyncClient>>* free_clients =
      result->client_type_ == RedisClientType::READ_WRITE ?
          &free_writable_clients_ : &free_read_only_clients_;
  if (result->client_type_ == RedisClientType::READ_WRITE &&
      (current_master_port_ != result->redis_master_port_ ||
      current_master_ip_ != result->redis_master_ip_)) {
    // This is writable client, attached to old master - just drop it.
    LOG4CPLUS_INFO(logger_, "Dropping writable client attached to old master");
    return;
  }
  free_clients->push_back(std::move(result->client_));
}

std::unique_ptr<RedisSyncClient> RedisClientPool::ConnectNewClient(
    RedisClientType client_type) {
  std::unique_ptr<RedisSyncClient> redis_client(
      new RedisSyncClient(*io_service_));

  boost::asio::ip::tcp::endpoint endpoint;
  if (client_type == RedisClientType::READ_WRITE) {
    endpoint = boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address::from_string(current_master_ip_),
        current_master_port_);
  } else {
    endpoint = boost::asio::ip::tcp::endpoint(
        boost::asio::ip::address::from_string(slave_ip_),
        slave_port_);
  }

  std::string errmsg;
  if (!redis_client->connect(endpoint, errmsg)) {
    LOG4CPLUS_ERROR(
        logger_, "Failed connect to the Redis server " << errmsg.c_str());
    return nullptr;
  }
  redis_client->installErrorHandler(OnRedisError);
  return redis_client;
}

bool RedisClientPool::IsInitialized() const {
  return (sentinel_client_ && current_master_port_ != 0 &&
      !current_master_ip_.empty());
}

void RedisClientPool::RetrieveCurrentMasterAddress() {
  std::promise<RedisValue> got_master_name;
  sentinel_client_->command(
      "SENTINEL",
      "get-master-addr-by-name",
      sentinel_master_name_,
      [&got_master_name](const RedisValue& val) {
          got_master_name.set_value(val);
  });
  RedisValue redis_val = got_master_name.get_future().get();
  if (!redis_val.isOk())
    return;
  std::vector<RedisValue> sentinel_output = redis_val.toArray();
  if (sentinel_output.size() != 2) {
    LOG4CPLUS_ERROR(logger_, "Unexpected output from Redis Sentinel");
    return;
  }
  current_master_ip_ = sentinel_output[0].toString();
  std::istringstream master_port_strm(sentinel_output[1].toString());
  master_port_strm >> current_master_port_;
  if (master_port_strm.fail()) {
    current_master_port_ = 0;
    LOG4CPLUS_ERROR(logger_, "Unexpected output from Redis Sentinel");
    return;
  }
  sentinel_subscription_handle_ = sentinel_client_->subscribe(
      "switch-master",
      boost::bind(&RedisClientPool::OnMasterSwitched, this, _1));
}

void RedisClientPool::OnMasterSwitched(const std::vector<char>& msg) {
  sentinel_client_->unsubscribe(sentinel_subscription_handle_);
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  free_writable_clients_.empty();
  current_master_ip_ = std::string();
  current_master_port_ = 0;
  RetrieveCurrentMasterAddress();
}

void OnSentinelClientConnected(
    std::promise<bool>* result,
    bool success,
    const std::string& error_message) {
  if (!success) {
    LOG4CPLUS_ERROR(
        logger_, "Sentinel connection failed " << error_message.c_str());
  }
  result->set_value(success);
}

void RedisClientPool::InitSentinelConnection() {
  boost::asio::ip::address server_ip = boost::asio::ip::address::from_string(
      sentinel_ip_);
  boost::asio::ip::tcp::endpoint endpoint(server_ip, sentinel_port_);
  sentinel_client_ = std::unique_ptr<RedisAsyncClient>(
      new RedisAsyncClient(*io_service_));
  sentinel_client_->installErrorHandler(&OnRedisError);
  std::promise<bool> connected_promise;
  std::future<bool> connected_future = connected_promise.get_future();
  sentinel_client_->connect(
      endpoint,
      boost::bind(&OnSentinelClientConnected, &connected_promise, _1, _2));
  LOG4CPLUS_ASSERT(logger_, !io_service_thread_.joinable());
  io_service_thread_ = std::thread(&RedisClientPool::IOServiceThread, this);
  if (!connected_future.get()) {
    sentinel_client_.reset();
    return;
  }
}

void RedisClientPool::IOServiceThread() {
  LOG4CPLUS_INFO(logger_, "Entering IO service thread...");
  io_service_->run();
  LOG4CPLUS_INFO(logger_, "Leaving IO service thread...");
}
