// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef BASE_FILESYSTEM_UTILS_H_
#define BASE_FILESYSTEM_UTILS_H_

#include <boost/filesystem.hpp>

namespace base {

boost::filesystem::path GetCurrentExecutableDir();

}  // namespace base

#endif  // BASE_FILESYSTEM_UTILS_H_
