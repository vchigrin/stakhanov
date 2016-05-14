// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/process_proxy_manager.h"

#include <vector>

#include "boost/filesystem.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stproxy/stproxy_communication.h"

namespace {

const wchar_t kStProxyExeName[] = L"stproxy.exe";
log4cplus::Logger logger_ = log4cplus::Logger::getInstance(
    L"ProcessProxyManager");

}  // namespace

ProcessProxyManager* ProcessProxyManager::instance_ = nullptr;

// static
void ProcessProxyManager::Initialize(
    HMODULE current_module,
    bool is_safe_to_use_hoax_proxy,
    LPCREATE_PROCESS_W original_create_process) {
  instance_ = new ProcessProxyManager(
      current_module,
      is_safe_to_use_hoax_proxy,
      original_create_process);
}

ProcessProxyManager::ProcessProxyManager(
    HMODULE current_module,
    bool is_safe_to_use_hoax_proxy,
    LPCREATE_PROCESS_W original_create_process)
    : is_safe_to_use_hoax_proxy_(is_safe_to_use_hoax_proxy),
      original_create_process_(original_create_process) {
  InitStProxyPath(current_module);
}

bool ProcessProxyManager::CreateProxyProcess(
    const CacheHitInfo& cache_hit_info,
    DWORD creation_flags,
    HANDLE std_input_handle,
    HANDLE std_output_handle,
    HANDLE std_error_handle,
    PROCESS_INFORMATION* process_information) {
  base::ScopedHandle file_mapping_handle = PrepareFileMapping(cache_hit_info);
  if (!file_mapping_handle.IsValid())
    return false;
  std::wostringstream buffer;
  buffer << std::hex << file_mapping_handle.Get();
  std::wstring handle_str = buffer.str();
  std::vector<wchar_t> command_line;
  // stproxy_path + 1 space + file_mapping_handle + zero terminator.
  command_line.reserve(stproxy_path_.length() + 1 + handle_str.length() + 1);
  std::copy(
      stproxy_path_.begin(), stproxy_path_.end(),
      std::back_inserter(command_line));
  command_line.push_back(L' ');
  std::copy(
      handle_str.begin(), handle_str.end(),
      std::back_inserter(command_line));
  command_line.push_back(L'\0');
  STARTUPINFO startup_info = {0};
  startup_info.cb = sizeof(startup_info);
  startup_info.hStdInput = std_input_handle;
  startup_info.hStdOutput = std_output_handle;
  startup_info.hStdError = std_error_handle;
  if (std_output_handle || std_error_handle || std_input_handle) {
    startup_info.dwFlags = STARTF_USESTDHANDLES;
  }
  BOOL result = original_create_process_(
        NULL,
        &command_line[0],
        NULL,
        NULL,
        TRUE,  // Inherit handles
        creation_flags & ~EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        NULL,
        &startup_info,
        process_information);
  if (!result) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed  create proxy process, error " << error);
  }
  return result;
}

base::ScopedHandle ProcessProxyManager::PrepareFileMapping(
    const CacheHitInfo& cache_hit_info) {
  DWORD required_file_mapping_size =
      sizeof(STPROXY_SECTION_HEADER) +
      static_cast<DWORD>(cache_hit_info.result_stdout.length() +
                         cache_hit_info.result_stderr.length());
  SECURITY_ATTRIBUTES security_attributes = {0};
  security_attributes.nLength = sizeof(security_attributes);
  security_attributes.lpSecurityDescriptor = NULL;
  security_attributes.bInheritHandle = TRUE;
  base::ScopedHandle file_mapping_handle(CreateFileMapping(
      INVALID_HANDLE_VALUE,
      &security_attributes,
      PAGE_READWRITE,
      0,
      required_file_mapping_size,
      NULL));
  if (!file_mapping_handle.IsValid()) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CreateFileMapping failed, error " << error_code);
    return base::ScopedHandle();
  }
  void* file_mapping_data = MapViewOfFile(
      file_mapping_handle.Get(),
      FILE_MAP_WRITE,
      0, 0,
      required_file_mapping_size);
  if (!file_mapping_data) {
    DWORD error_code = GetLastError();
    LOG4CPLUS_ERROR(logger_, "MapViewOfFile failed, error " << error_code);
    return base::ScopedHandle();
  }
  STPROXY_SECTION_HEADER* header = static_cast<STPROXY_SECTION_HEADER*>(
      file_mapping_data);
  header->exit_code = cache_hit_info.exit_code;
  header->stdout_byte_size = static_cast<DWORD>(
      cache_hit_info.result_stdout.length());
  header->stderr_byte_size = static_cast<DWORD>(
      cache_hit_info.result_stderr.length());
  uint8_t* dest_data = static_cast<uint8_t*>(file_mapping_data);
  dest_data += sizeof(STPROXY_SECTION_HEADER);
  memcpy(dest_data,
         cache_hit_info.result_stdout.c_str(),
         cache_hit_info.result_stdout.length());
  dest_data += cache_hit_info.result_stdout.length();
  memcpy(dest_data,
         cache_hit_info.result_stderr.c_str(),
         cache_hit_info.result_stderr.length());
  UnmapViewOfFile(file_mapping_data);
  return file_mapping_handle;
}


void ProcessProxyManager::InitStProxyPath(HMODULE current_module) {
  std::vector<wchar_t> buffer(MAX_PATH + 1);
  GetModuleFileName(current_module, &buffer[0], MAX_PATH);
  buffer[MAX_PATH] = L'\0';
  boost::filesystem::path cur_dll_path(&buffer[0]);
  boost::filesystem::path result =
      cur_dll_path.parent_path() / kStProxyExeName;
  stproxy_path_ = result.native();
}

