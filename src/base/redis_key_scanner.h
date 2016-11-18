// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_REDIS_KEY_SCANNER_H_
#define BASE_REDIS_KEY_SCANNER_H_

#include <string>
#include <vector>

class RedisSyncClient;

// Helper class to iterate through results of SCAN command with
// MATCH restriction
class RedisKeyScanner {
 public:
  RedisKeyScanner(RedisSyncClient* client,
                  const std::string& match_restriction);
  const std::vector<std::string>& current_results() const {
    return current_results_;
  }

  // Returne false if this was the last chunk of data, and
  // FetchNext should not be called any more.
  bool FetchNext();

 private:
  RedisSyncClient* client_;
  const std::string match_restriction_;
  std::string current_cursor_;
  std::vector<std::string> current_results_;
};


#endif  // BASE_REDIS_KEY_SCANNER_H_
