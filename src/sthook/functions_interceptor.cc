// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/functions_interceptor.h"

#include <delayimp.h>
#include <tchar.h>
#include <tlhelp32.h>

#include "base/string_utils.h"
#include "log4cplus/loggingmacros.h"

namespace {

bool IsValid(const IMAGE_IMPORT_DESCRIPTOR* descriptor) {
  return descriptor->OriginalFirstThunk != 0;
}

bool IsValid(const ImgDelayDescr* descriptor) {
  return descriptor->rvaIAT != 0;
}

int NameTableOffset(const IMAGE_IMPORT_DESCRIPTOR* descriptor) {
  return descriptor->OriginalFirstThunk;
}

int NameTableOffset(const ImgDelayDescr* descriptor) {
  return descriptor->rvaINT;
}

int AddressTableOffset(const IMAGE_IMPORT_DESCRIPTOR* descriptor) {
  return descriptor->FirstThunk;
}

int AddressTableOffset(const ImgDelayDescr* descriptor) {
  return descriptor->rvaIAT;
}

const uint8_t* EffectiveBaseAddress(
    const IMAGE_IMPORT_DESCRIPTOR* descriptor, const uint8_t* base_address) {
  return base_address;
}

const uint8_t* EffectiveBaseAddress(
    const ImgDelayDescr* descriptor, const uint8_t* base_address) {
  return (descriptor->grAttrs & dlattrRva) ? base_address : nullptr;
}

int DLLNameRVA(const IMAGE_IMPORT_DESCRIPTOR* descriptor) {
  return descriptor->Name;
}

int DLLNameRVA(const ImgDelayDescr* descriptor) {
  return descriptor->rvaDLLName;
}

}  // namespace

namespace sthook {

FunctionsInterceptor::FunctionsInterceptor()
    : hooked_(false) {
  logger_ = log4cplus::Logger::getRoot();
}

FunctionsInterceptor::~FunctionsInterceptor() {
  if (hooked_)
    Unhook();
}

void FunctionsInterceptor::NewModuleLoaded(HMODULE module) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  std::unordered_set<HMODULE> modules_to_process = PatchIATAndGetDeps(module);
  while (!modules_to_process.empty()) {
    HMODULE next_module = *modules_to_process.begin();
    modules_to_process.erase(modules_to_process.begin());
    if (processed_modules_.find(next_module) == processed_modules_.end()) {
      std::unordered_set<HMODULE> references = PatchIATAndGetDeps(next_module);
      processed_modules_.insert(next_module);
      modules_to_process.insert(references.begin(), references.end());
    }
  }
}

void* FunctionsInterceptor::GetReplacement(void* old_addr) const {
  const auto it_function = functions_replacements_.find(old_addr);
  if (it_function != functions_replacements_.end())
    return it_function->second;
  return nullptr;
}

bool FunctionsInterceptor::Hook(
    const Intercepts& intercepts,
    HMODULE excluded_module) {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  LOG4CPLUS_ASSERT(logger_, !hooked_);
  if (hooked_)
    return false;
  intercepts_ = intercepts;
  for (const auto& intercepted_module : intercepts) {
    HMODULE module_handle = GetModuleHandleA(
        intercepted_module.first.c_str());
    if (!module_handle) {
      LOG4CPLUS_ERROR(logger_, "Intercepted module not loaded ");
      return false;
    }
    for (const auto& intercepted_function : intercepted_module.second) {
      void* src_addr = GetProcAddress(
          module_handle, intercepted_function.first.c_str());
      if (src_addr) {
        functions_replacements_[src_addr] = intercepted_function.second;
      } else {
        LOG4CPLUS_ERROR(
            logger_,
            "Failed get addr. of  " << intercepted_function.first.c_str());
      }
    }
  }
  hooked_ = true;
  std::vector<HMODULE> loaded_modules = GetLoadedModules();
  for (HMODULE module : loaded_modules) {
    if (module != excluded_module) {
      PatchIATAndGetDeps(module);
      processed_modules_.insert(module);
    }
  }
  return true;
}

std::vector<HMODULE> FunctionsInterceptor::GetLoadedModules() {
  std::vector<HMODULE> result;
  HANDLE snapshot_handle = nullptr;
  do {
    snapshot_handle = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot_handle == INVALID_HANDLE_VALUE) {
      uint32_t error_code = GetLastError();
      if (error_code == ERROR_BAD_LENGTH) {
        // May be if modules list changed during the call.
        continue;
      }
      LOG4CPLUS_ERROR(
          logger_, _T("Failed create modules snapshot ")  << error_code);
      return result;
    }
  } while (snapshot_handle == INVALID_HANDLE_VALUE);
  MODULEENTRY32 me = { 0 };
  me.dwSize = sizeof(me);
  bool more_data = Module32First(snapshot_handle, &me);
  while (more_data) {
    result.push_back(me.hModule);
    more_data = Module32Next(snapshot_handle, &me);
  }
  CloseHandle(snapshot_handle);
  return result;
}

std::unordered_set<HMODULE> FunctionsInterceptor::PatchIATAndGetDeps(
    HMODULE module) {
  if (!hooked_) {
    LOG4CPLUS_ASSERT(logger_, false && "Hooks should be installed");
    return std::unordered_set<HMODULE>();
  }
  const uint8_t* base_address = reinterpret_cast<const uint8_t*>(module);
  const IMAGE_OPTIONAL_HEADER32* maybe_opt_header_32 =
      GetPEOptionalHeader(base_address);
  if (!maybe_opt_header_32) {
    LOG4CPLUS_WARN(
        logger_,
        "Failed get optional header in module " << std::hex << module);
    return std::unordered_set<HMODULE>();
  }
  const IMAGE_DATA_DIRECTORY* import_data_dir = GetImageDir(
      base_address, maybe_opt_header_32, IMAGE_DIRECTORY_ENTRY_IMPORT);
  std::unordered_set<HMODULE> result;
  if (import_data_dir) {
    result = HookImportDirectory<IMAGE_IMPORT_DESCRIPTOR>(
        base_address,
        *import_data_dir);
  }
  const IMAGE_DATA_DIRECTORY* delay_import_data_dir = GetImageDir(
      base_address, maybe_opt_header_32, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT);

  if (delay_import_data_dir) {
    std::unordered_set<HMODULE> refernces_modules =
        HookImportDirectory<ImgDelayDescr>(
            base_address, *delay_import_data_dir);
    result.insert(refernces_modules.begin(), refernces_modules.end());
  }
  hooked_ = true;
  return result;
}

void FunctionsInterceptor::Unhook() {
  std::lock_guard<std::mutex> instance_lock(instance_lock_);
  LOG4CPLUS_ASSERT(logger_, hooked_);
  if (!hooked_)
    return;
  for (const PatchInformation& info : patches_) {
    if (*info.patched_address == info.new_value) {
      Patch(info.patched_address, info.old_value, false);
    } else {
      LOG4CPLUS_WARN(
          logger_,
          _T("Somebody overwritted our patch at ") << info.patched_address);
    }
  }
  hooked_ = false;
}

const IMAGE_OPTIONAL_HEADER32* FunctionsInterceptor::GetPEOptionalHeader(
    const uint8_t* image_base) {
  const IMAGE_DOS_HEADER* dos_header =
      reinterpret_cast<const IMAGE_DOS_HEADER*>(image_base);
  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
    LOG4CPLUS_ERROR(
      logger_, _T("Invalid DOS signature ") << dos_header->e_magic);
    return nullptr;
  }
  const IMAGE_NT_HEADERS* pe_header =
      reinterpret_cast<const IMAGE_NT_HEADERS*>(
          image_base + dos_header->e_lfanew);
  if (pe_header->Signature != IMAGE_NT_SIGNATURE) {
    LOG4CPLUS_ERROR(
        logger_, _T("Invalid PE signature ") << pe_header->Signature);
    return nullptr;
  }
  if (pe_header->FileHeader.SizeOfOptionalHeader == 0) {
    LOG4CPLUS_ERROR(logger_, _T("No optional header"));
    return nullptr;
  }
  return reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(
      &pe_header->OptionalHeader);
}

const IMAGE_DATA_DIRECTORY* FunctionsInterceptor::GetImageDir(
    const uint8_t* image_base,
    const IMAGE_OPTIONAL_HEADER32* maybe_opt_header_32,
    int directory_entry_idx) {
  if (!maybe_opt_header_32)
    return nullptr;
  if (maybe_opt_header_32->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    const IMAGE_OPTIONAL_HEADER64* opt_header_64 =
        reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(maybe_opt_header_32);
    if (static_cast<int>(opt_header_64->NumberOfRvaAndSizes)
         <= directory_entry_idx) {
      return nullptr;
    }
    return &opt_header_64->DataDirectory[directory_entry_idx];
  } else if (maybe_opt_header_32->Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    if (static_cast<int>(maybe_opt_header_32->NumberOfRvaAndSizes)
         <= directory_entry_idx) {
      return nullptr;
    }
    return &maybe_opt_header_32->DataDirectory[directory_entry_idx];
  } else {
    return nullptr;
  }
}


template<typename ImportDescriptorType>
std::unordered_set<HMODULE> FunctionsInterceptor::HookImportDirectory(
    const uint8_t* base_address,
    const IMAGE_DATA_DIRECTORY& import_directory) {
  if (import_directory.VirtualAddress == 0) {
    // Seems, if module has no imports, this can be 0.
    return std::unordered_set<HMODULE>();
  }
  const ImportDescriptorType* cur_import_descriptor =
      reinterpret_cast<const ImportDescriptorType*>(
          base_address + import_directory.VirtualAddress);
  std::unordered_set<HMODULE> result;
  for (; IsValid(cur_import_descriptor); cur_import_descriptor++) {
    const uint8_t* effective_base_address =
        EffectiveBaseAddress(cur_import_descriptor, base_address);
    const char* imported_dll_name = reinterpret_cast<const char*>(
        effective_base_address + DLLNameRVA(cur_import_descriptor));
    HMODULE imported_module = GetModuleHandleA(imported_dll_name);
    // TODO(vchigrin): Check, that delay loading Dlls cause
    // LdrLoadLibrary call and patches are applied.
    // We should not call LoadLibrary call here since it causes
    // deep recursion chain since LoadLibrary calls LdrLoadLibrary that
    // we hook now.
    if (imported_module) {
      result.insert(imported_module);
    }
    HookImportDescriptor(
        base_address,
        reinterpret_cast<const IMAGE_THUNK_DATA*>(
            effective_base_address + NameTableOffset(cur_import_descriptor)),
        reinterpret_cast<const IMAGE_THUNK_DATA*>(
            effective_base_address +
                AddressTableOffset(cur_import_descriptor)));
  }
  return result;
}

void FunctionsInterceptor::HookImportDescriptor(
    const uint8_t* base_address,
    const IMAGE_THUNK_DATA* name_table,
    const IMAGE_THUNK_DATA* address_table) {
  const IMAGE_THUNK_DATA* name_entry = name_table;
  const IMAGE_THUNK_DATA* address_entry = address_table;
  for (; name_entry->u1.Ordinal != 0; name_entry++, address_entry++) {
    const auto it_function = functions_replacements_.find(
        reinterpret_cast<void*>(
            address_entry->u1.AddressOfData));
    if (it_function != functions_replacements_.end()) {
      Patch(
          reinterpret_cast<void**>(
              &const_cast<IMAGE_THUNK_DATA*>(address_entry)->u1.AddressOfData),
          it_function->second, true);
    }
  }
}

void FunctionsInterceptor::Patch(void** dest, void* val, bool remember) {
  MEMORY_BASIC_INFORMATION memory_info = { 0 };
  if (!VirtualQuery(dest, &memory_info, sizeof(memory_info))) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "VirtualQuery failed " << error_code);
    return;
  }

  bool is_executable = (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                        PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY) &
                        memory_info.Protect;
  DWORD old_protection = 0;
  if (VirtualProtect(dest,
                     sizeof(val),
                     is_executable ? PAGE_EXECUTE_READWRITE :
                                     PAGE_READWRITE,
                     &old_protection)) {
    if (remember) {
      PatchInformation patch_info;
      patch_info.patched_address = dest;
      patch_info.old_value = *dest;
      patch_info.new_value = val;
      patches_.push_back(patch_info);
    }
    *dest = val;
    VirtualProtect(dest, sizeof(val), old_protection, &old_protection);
  } else {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "VirtualProtect failed " << error_code);
  }
}

}  // namespace sthook
