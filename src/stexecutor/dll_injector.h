// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_DLL_INJECTOR_H_
#define STEXECUTOR_DLL_INJECTOR_H_

#include <cstdint>

#include "boost/filesystem.hpp"

class DllInjector {
 public:
  DllInjector(
      const boost::filesystem::path& injected_32bit_path,
      const boost::filesystem::path& injected_64bit_path,
      uint32_t load_library_32_addr,
      uint64_t load_library_64_addr);
  bool InjectInto(int child_pid);

 private:
  const boost::filesystem::path injected_32bit_path_;
  const boost::filesystem::path injected_64bit_path_;
  const uint32_t load_library_32_addr_;
  const uint64_t load_library_64_addr_;
};

#endif  // STEXECUTOR_DLL_INJECTOR_H_
