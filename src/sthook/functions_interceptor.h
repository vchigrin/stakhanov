// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STHOOK_FUNCTIONS_INTERCEPTOR_H_
#define STHOOK_FUNCTIONS_INTERCEPTOR_H_

#include <windows.h>

#include <string>
#include <mutex>
#include <vector>
#include <unordered_map>
#include <unordered_set>

#include "log4cplus/logger.h"

namespace sthook {

// Intercepts set of function calls from all modules (except excluded) to the
// specified dll.
class FunctionsInterceptor {
 public:
  // Map from function name in intercepted_dll to new address.
  using DllInterceptedFunctions = std::unordered_map<std::string, void*>;
  using Intercepts = std::unordered_map<std::string, DllInterceptedFunctions>;
  FunctionsInterceptor();
  ~FunctionsInterceptor();
  // NOTE: dll names must be lower case.
  bool Hook(const Intercepts& intercepts, HMODULE excluded_module);
  void Unhook();
  // Called to patch IAT on newly loaded modules.
  void NewModuleLoaded(HMODULE module);
  void* GetReplacement(void* old_addr) const;

 private:
  struct PatchInformation {
    void** patched_address;
    void* old_value;
    void* new_value;
  };

  std::vector<HMODULE> GetLoadedModules();
  const IMAGE_OPTIONAL_HEADER32* GetPEOptionalHeader(const uint8_t* image_base);
  const IMAGE_DATA_DIRECTORY* GetImageDir(
      const uint8_t* image_base,
      const IMAGE_OPTIONAL_HEADER32* maybe_opt_header_32,
      int directory_entry_idx);
  template<typename ImportDescriptorType>
  std::unordered_set<HMODULE> HookImportDirectory(
      const uint8_t* base_address,
      const IMAGE_DATA_DIRECTORY& import_directory);
  void HookImportDescriptor(
      const uint8_t* base_address,
      const IMAGE_THUNK_DATA* name_table,
      const IMAGE_THUNK_DATA* address_table);
  void Patch(void** dest, void* val, bool remember);
  // Returns all modules this module references.
  std::unordered_set<HMODULE> PatchIATAndGetDeps(HMODULE module);

  Intercepts intercepts_;
  std::vector<PatchInformation> patches_;
  std::unordered_set<HMODULE> processed_modules_;
  std::unordered_map<void*, void*> functions_replacements_;
  bool hooked_;
  std::mutex instance_lock_;

  log4cplus::Logger logger_;
};

}  // namespace sthook
#endif  // STHOOK_FUNCTIONS_INTERCEPTOR_H_
