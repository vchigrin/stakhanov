// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STHOOK_PROCESS_PROXY_MANAGER_H_
#define STHOOK_PROCESS_PROXY_MANAGER_H_

#include <mutex>
#include <string>

#include "base/scoped_handle.h"
#include "gen-cpp/Executor.h"

class ProcessProxyManager {
 public:
  typedef BOOL (WINAPI *LPCREATE_PROCESS_W)(
      LPCWSTR application_name,
      LPWSTR command_line,
      LPSECURITY_ATTRIBUTES process_attributes,
      LPSECURITY_ATTRIBUTES thread_attributes,
      BOOL inherit_handles,
      DWORD creation_flags,
      LPVOID environment,
      LPCWSTR current_directory,
      LPSTARTUPINFOW startup_info,
      LPPROCESS_INFORMATION process_information);

  static ProcessProxyManager* GetInstance() {
    return instance_;
  }
  static void Initialize(
      HMODULE current_module,
      bool is_safe_to_use_hoax_proxy,
      LPCREATE_PROCESS_W original_create_process);

  bool CreateProxyProcess(
      const CacheHitInfo& cache_hit_info,
      DWORD creation_flags,
      HANDLE std_input_handle,
      HANDLE std_output_handle,
      HANDLE std_error_handle,
      PROCESS_INFORMATION* process_information);

 private:
  ProcessProxyManager(
      HMODULE current_module,
      bool is_safe_to_use_hoax_proxy,
      LPCREATE_PROCESS_W original_create_process);
  base::ScopedHandle PrepareFileMapping(const CacheHitInfo& cache_hit_info);
  void InitStProxyPath(HMODULE current_module);

  static ProcessProxyManager* instance_;
  const bool is_safe_to_use_hoax_proxy_;
  LPCREATE_PROCESS_W original_create_process_;
  std::wstring stproxy_path_;
};

#endif  // STHOOK_PROCESS_PROXY_MANAGER_H_

