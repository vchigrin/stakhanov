// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/rules_mappers/rules_mapper_base.h"

#include <string>

#include "stexecutor/process_creation_request.h"

namespace rules_mappers {

RulesMapperBase::RulesMapperBase() {}

RulesMapperBase::~RulesMapperBase() {}

// static
HashValue RulesMapperBase::ComputeProcessCreationHash(
    const ProcessCreationRequest& process_creation_request) {
  // TODO(vchigrin): Remove this method.
  return process_creation_request.GetHash();
}

}  // namespace rules_mappers

