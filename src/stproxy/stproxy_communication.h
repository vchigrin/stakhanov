// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STPROXY_STPROXY_COMMUNICATION_H_
#define STPROXY_STPROXY_COMMUNICATION_H_

#include <cstdint>

// After structure go stdout data, then stderr data.
struct STPROXY_SECTION_HEADER {
  uint32_t exit_code;
  uint32_t stdout_byte_size;
  uint32_t stderr_byte_size;
};

#endif  // STPROXY_STPROXY_COMMUNICATION_H_

