// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STEXECUTOR_DLL_INJECTOR_H_
#define STEXECUTOR_DLL_INJECTOR_H_

#include <cstdint>

#include "boost/filesystem.hpp"

class DllInjector {
 public:
  // Pair of addresses for native x64 processes and and WOW64 (32-bit).
  struct SystemFunctionAddr {
    uint64_t addr_64;
    uint32_t addr_32;

    SystemFunctionAddr()
        : addr_64(0), addr_32(0) {}

    bool is_valid() const {
      return addr_64 != 0 && addr_32 != 0;
    }
  };

  DllInjector(
      const boost::filesystem::path& injected_32bit_path,
      const boost::filesystem::path& injected_64bit_path,
      const SystemFunctionAddr ldr_load_dll_addr,
      const SystemFunctionAddr nt_set_event_addr);
  bool InjectInto(
      int child_pid, int child_main_thread_id, bool leave_suspended);
  bool Resume(int child_pid, int child_main_thread_id);

 private:
  const boost::filesystem::path injected_32bit_path_;
  const boost::filesystem::path injected_64bit_path_;

  const SystemFunctionAddr ldr_load_dll_addr_;
  const SystemFunctionAddr nt_set_event_addr_;
};

#endif  // STEXECUTOR_DLL_INJECTOR_H_
