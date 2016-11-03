// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_REDIS_KEY_PREFIXES_H_
#define BASE_REDIS_KEY_PREFIXES_H_

namespace redis_key_prefixes {

extern const char kRules[];
extern const char kFileSets[];
extern const char kFileInfos[];
extern const char kResponse[];
extern const char kStoredFileHosts[];
// Contains time since epoch, in seconds, when this key was accessed last time.
// Need for proper cleanup.
// At present timestamp saved only for kRules and kFileSets key types.
extern const char kKeyTimeStamp[];

}  // namespace redis_key_prefixes

#endif  // BASE_REDIS_KEY_PREFIXES_H_
