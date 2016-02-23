// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_RULES_HASHING_H_
#define STEXECUTOR_RULES_MAPPERS_RULES_HASHING_H_

#include <algorithm>
#include <string>

#include "third_party/cryptopp/md5.h"

namespace rules_mappers {

using HashAlgorithm = CryptoPP::Weak::MD5;

class HashValue {
 public:
  static const int kSize = HashAlgorithm::DIGESTSIZE;

  HashValue() {
    std::fill(value_, value_ + kSize, 0);
  }

  HashValue(const HashValue& second) {
    std::copy(second.value_, second.value_ + kSize, value_);
  }

  uint8_t* data() {
    return value_;
  }

  const uint8_t* data() const {
    return value_;
  }

  bool operator==(const HashValue& second) const {
    return std::equal(
        data(), data() + kSize,
        second.data(), second.data() + kSize);
  }

 private:
  uint8_t value_[kSize];
};

inline std::wostream& operator << (
    std::wostream& stream, const HashValue& hash_val) {
  auto flags = stream.flags();
  stream << std::hex;
  std::copy(
      hash_val.data(),
      hash_val.data() + HashValue::kSize,
      std::ostream_iterator<uint8_t, wchar_t>(stream));
  stream.flags(flags);
  return stream;
}


inline void HashString(HashAlgorithm* hasher, const std::string& str) {
  hasher->Update(reinterpret_cast<const uint8_t*>(str.c_str()), str.length());
}

struct HashValueHasher {
  size_t operator()(const HashValue& val) const {
    std::hash<std::string> hasher;
    return hasher(
        std::string(
            reinterpret_cast<const char*>(val.data()),
            HashValue::kSize));
  }
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_RULES_HASHING_H_
