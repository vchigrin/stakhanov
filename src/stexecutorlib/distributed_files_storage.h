// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTORLIB_DISTRIBUTED_FILES_STORAGE_H_
#define STEXECUTORLIB_DISTRIBUTED_FILES_STORAGE_H_

#include <memory>
#include <mutex>
#include <string>
#include <unordered_set>

#include "boost/asio/io_service.hpp"
#include "boost/property_tree/ptree_fwd.hpp"
#include "stexecutorlib/filesystem_files_storage.h"

class RedisClientPool;

class DistributedFilesStorage : public FilesystemFilesStorage {
 public:
  struct CleanResults {
    uint64_t num_bytes_cleaned;
    uint64_t num_bytes_left_filled;
    uint64_t num_entries_cleaned;
    uint64_t num_entries_left_filled;
  };
  DistributedFilesStorage(
      const boost::property_tree::ptree& config,
      const std::shared_ptr<RedisClientPool>& redis_client_pool);
  CleanResults CleanOrphanedEntries();

 protected:
  void OnStorageIdFilled(const std::string& storage_id) override;
  // Subclasses can override this to provide storage items on-demand.
  // If returns true that means that request successfully fulfiled.
  bool OnRequestedMissedStorageId(
      const std::string& storage_id) override;

 private:
  std::unordered_set<std::string> LoadUsedStorageIds();
  void LoadConfig(const boost::property_tree::ptree& config);
  std::string GetHostNameForStorageId(const std::string& storage_id);
  bool DownloadFile(
      const std::string& host_name,
      const std::string& storage_id,
      const boost::filesystem::path& dest_path);

  int http_port_;
  std::string this_host_name_;
  std::shared_ptr<RedisClientPool> redis_client_pool_;
  boost::asio::io_service io_service_;
};

#endif  // STEXECUTORLIB_DISTRIBUTED_FILES_STORAGE_H_

