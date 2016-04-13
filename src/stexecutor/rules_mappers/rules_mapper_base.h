// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_RULES_MAPPERS_RULES_MAPPER_BASE_H_
#define STEXECUTOR_RULES_MAPPERS_RULES_MAPPER_BASE_H_

#include "stexecutor/rules_mappers/rules_mapper.h"
#include "stexecutor/rules_mappers/rules_hashing.h"

namespace rules_mappers {

class RulesMapperBase : public RulesMapper {
 public:
  RulesMapperBase();
  ~RulesMapperBase();

 protected:
  static HashValue ComputeProcessCreationHash(
      const ProcessCreationRequest& process_creation_request);
};

}  // namespace rules_mappers

#endif  // STEXECUTOR_RULES_MAPPERS_RULES_MAPPER_BASE_H_

