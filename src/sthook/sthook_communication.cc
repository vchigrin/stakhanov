// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/sthook_communication.h"

#include <stdlib.h>

namespace sthook {

static const int kDefaultExecutorPort = 9092;

int GetExecutorPort() {
  const char* port_var = getenv("ST_PORT");
  if (!port_var)
    return kDefaultExecutorPort;
  int result = atoi(port_var);
  if (result <= 0)
    result = kDefaultExecutorPort;
  return result;
}

}  // namespace sthook
