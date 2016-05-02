// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "stexecutor/dll_injector.h"

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <vector>

#include "base/scoped_handle.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"DllInjector");

bool Is64BitProcess(const base::ScopedHandle& process_handle) {
  BOOL result = FALSE;
  if (!IsWow64Process(process_handle.Get(), &result)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "IsWow64BitProcess failed, error " << error);
    return false;
  }
  return !result;
}

}  // namespace

typedef NTSTATUS (NTAPI *LdrLoadDllPtr)(
    PWCHAR path_to_file,
    ULONG* flags,
    const /* UNICODE_STRING */ void* module_file_name,
    HMODULE* module_handle);

typedef NTSTATUS (NTAPI *NtSetEventPtr)(HANDLE event, PLONG prev_state);

template<typename ptr_size_uint>
struct RemoteData {
  struct {
    USHORT length;
    USHORT max_length;
    ptr_size_uint buffer;
  } dll_name;
  ptr_size_uint ldr_load_dll;
  ptr_size_uint nt_set_event;
  ptr_size_uint event;
  ptr_size_uint completed_flag;

  static void FillBuffer(
      void* buffer_addr,
      size_t remote_string_char_len,
      void* remote_string_addr,
      HANDLE remote_event_handle,
      ptr_size_uint ldr_load_dll_addr,
      ptr_size_uint nt_set_event_addr) {
    RemoteData<ptr_size_uint>* local_data =
        reinterpret_cast<RemoteData<ptr_size_uint>*>(buffer_addr);
    local_data->dll_name.length = static_cast<USHORT>(
        remote_string_char_len * sizeof(WCHAR));
    local_data->dll_name.max_length = local_data->dll_name.length;
    local_data->dll_name.buffer = reinterpret_cast<ptr_size_uint>(
        remote_string_addr);
    local_data->ldr_load_dll = ldr_load_dll_addr;
    local_data->nt_set_event = nt_set_event_addr;
    local_data->event = reinterpret_cast<ptr_size_uint>(remote_event_handle);
    local_data->completed_flag = 0;
  }
};

using RemoteData32 = RemoteData<uint32_t>;
using RemoteData64 = RemoteData<uint64_t>;

#ifdef _M_AMD64
using RemoteDataNative = RemoteData64;
#else
using RemoteDataNative = RemoteData32;
#endif


#pragma code_seg(push, ".cave")
#pragma runtime_checks("", off)
#pragma check_stack(off)
#pragma strict_gs_check(push, off)
extern "C" static void _fastcall code_cave(RemoteDataNative* data) {
  HMODULE module;
  ULONG flags = LOAD_WITH_ALTERED_SEARCH_PATH;

  NTSTATUS error = reinterpret_cast<LdrLoadDllPtr>(data->ldr_load_dll)(
      NULL, &flags, &data->dll_name, &module);
  reinterpret_cast<NtSetEventPtr>(data->nt_set_event)(
      reinterpret_cast<HANDLE>(data->event), NULL);
  // TODO(vchigrin): May be we can do better here: do pusha
  // in the beginning of the cave, popa at the end, and then just jmp
  // to the proper address... That is a bit of extra programming,
  // but may speed up us if actual process creator did not want
  // suspended main thread (that is most probably the most popular case).
  data->completed_flag = 1;
  while (true) {}
}
extern "C" static void code_cave_end() { }
#pragma strict_gs_check(pop)
#pragma code_seg(pop)

#ifdef _M_AMD64
// For injecting code to WOW64 processes, has same logic as code_cave routine.
static const uint8_t kCodeCave32[] = {
  0x83, 0xEC, 0x08,  //        sub esp,8
  0x56,  //                    push esi
  0x8D, 0x44, 0x24, 0x08,  //  lea eax,[esp+8]
  0xC7, 0x44, 0x24, 0x04,
  0x08, 0x00, 0x00, 0x00,  //  mov dword ptr [esp+4],8
  0x50,  //                    push eax
  0x8B, 0xF1,  //              mov  esi,ecx
  0x8D, 0x44, 0x24, 0x08,  //  lea  eax,[esp+8]
  0x56,  //                    push esi
  0x50,  //                    push eax
  0x6A, 0x00,  //              push 0
  0x8B, 0x46, 0x08,  //        mov  eax,dword ptr [esi+08h]
  0xFF, 0xD0,  //              call eax
  0x8B, 0x46, 0x0C,  //        mov  eax,dword ptr [esi+0Ch]
  0x6A, 0x00,  //              push 0
  0xFF, 0x76, 0x10,  //        push dword ptr [esi+10h]
  0xFF, 0xD0,  //              call eax
  0xC7, 0x46, 0x14, 0x01, 0x00, 0x00, 0x00,  // mov dword ptr [esi+14h], 1
  0xEB, 0xFE,  //              jmp  <current_eip>
};
#endif

template<bool is_wow64>
struct ContextChangerTraits {};

template<>
struct ContextChangerTraits<false> {
  using CONTEXT_TYPE = CONTEXT;

  static bool GetContext(HANDLE thread_handle, CONTEXT_TYPE* ctx) {
    ctx->ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(thread_handle, ctx)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "GetThreadContext failed, error " << error);
      return false;
    }
    return true;
  }

  static bool SetContext(HANDLE thread_handle, const CONTEXT_TYPE& ctx) {
    if (!SetThreadContext(thread_handle, &ctx)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "SetThreadContext failed, error " << error);
      return false;
    }
    return true;
  }

  static bool SuspendThread(HANDLE thread_handle) {
    if (::SuspendThread(thread_handle) == -1) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "SuspendThread failed, error " << error);
      return false;
    }
    return true;
  }

  static void SetUpCodeCave(
      CONTEXT_TYPE* ctx,
      intptr_t code_addr,
      intptr_t param_addr) {
#ifdef _M_AMD64
    ctx->Rip = code_addr;
    ctx->Rcx = param_addr;
#else
    ctx->Eip = code_addr;
    ctx->Ecx = param_addr;
#endif
  }
};

template<>
struct ContextChangerTraits<true> {
  using CONTEXT_TYPE = WOW64_CONTEXT;
  static const int kAllFlags = WOW64_CONTEXT_ALL;

  static bool GetContext(HANDLE thread_handle, CONTEXT_TYPE* ctx) {
    ctx->ContextFlags = WOW64_CONTEXT_ALL;
    if (!Wow64GetThreadContext(thread_handle, ctx)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(
          logger_, "Wow64GetThreadContext failed, error " << error);
      return false;
    }
    return true;
  }

  static bool SetContext(HANDLE thread_handle, const CONTEXT_TYPE& ctx) {
    if (!Wow64SetThreadContext(thread_handle, &ctx)) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(
          logger_, "Wow64SetThreadContext failed, error " << error);
      return false;
    }
    return true;
  }

  static bool SuspendThread(HANDLE thread_handle) {
    if (Wow64SuspendThread(thread_handle) == -1) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "Wow64SuspendThread failed, error " << error);
      return false;
    }
    return true;
  }

  static void SetUpCodeCave(
      CONTEXT_TYPE* ctx,
      intptr_t code_addr,
      intptr_t param_addr) {
    ctx->Eip = static_cast<DWORD>(code_addr);
    ctx->Ecx = static_cast<DWORD>(param_addr);
  }
};

class ContextChangerBase {
 public:
  virtual bool GetOriginalContext() = 0;
  virtual void SetUpCodeCave(intptr_t code_addr, intptr_t param_addr) = 0;
  virtual bool SwitchCodeCaveContext() = 0;
  virtual bool SwitchToOriginalContext() = 0;
  virtual bool SuspendThread() = 0;

  static std::unique_ptr<ContextChangerBase> Create(
      bool is_wow64, HANDLE thread_handle);
};

template<bool is_wow64>
class ContextChanger : public ContextChangerBase {
 public:
  explicit ContextChanger(HANDLE thread_handle)
    : thread_handle_(thread_handle) {
    memset(&old_context_, 0, sizeof(old_context_));
    memset(&new_context_, 0, sizeof(new_context_));
  }

  bool GetOriginalContext() override {
    return ContextChangerTraits<is_wow64>::GetContext(
        thread_handle_, &old_context_);
  }

  void SetUpCodeCave(intptr_t code_addr, intptr_t param_addr) override {
    new_context_ = old_context_;
    ContextChangerTraits<is_wow64>::SetUpCodeCave(
        &new_context_,
        code_addr, param_addr);
  }

  bool SwitchCodeCaveContext() override {
    return ContextChangerTraits<is_wow64>::SetContext(
        thread_handle_, new_context_);
  }

  bool SwitchToOriginalContext() override {
    return ContextChangerTraits<is_wow64>::SetContext(
        thread_handle_, old_context_);
  }

  bool SuspendThread() override {
    return ContextChangerTraits<is_wow64>::SuspendThread(thread_handle_);
  }

 private:
  typename ContextChangerTraits<is_wow64>::CONTEXT_TYPE old_context_;
  typename ContextChangerTraits<is_wow64>::CONTEXT_TYPE new_context_;
  HANDLE thread_handle_;
};

class RemoteAddrCleaner {
 public:
  RemoteAddrCleaner(HANDLE process_handle, void* remote_addr)
      : process_handle_(process_handle),
        remote_addr_(remote_addr) { }

  ~RemoteAddrCleaner() {
    if (remote_addr_)
      VirtualFreeEx(process_handle_, remote_addr_, 0, MEM_RELEASE);
  }

 private:
  HANDLE process_handle_;
  void* remote_addr_;
};

std::unique_ptr<ContextChangerBase> ContextChangerBase::Create(
    bool is_wow64, HANDLE thread_handle) {
  if (is_wow64) {
    return std::unique_ptr<ContextChangerBase>(
        new ContextChanger<true>(thread_handle));
  } else {
    return std::unique_ptr<ContextChangerBase>(
        new ContextChanger<false>(thread_handle));
  }
}

DllInjector::DllInjector(
    const boost::filesystem::path& injected_32bit_path,
    const boost::filesystem::path& injected_64bit_path,
    const SystemFunctionAddr ldr_load_dll_addr,
    const SystemFunctionAddr nt_set_event_addr)
    : injected_32bit_path_(injected_32bit_path),
      injected_64bit_path_(injected_64bit_path),
      ldr_load_dll_addr_(ldr_load_dll_addr),
      nt_set_event_addr_(nt_set_event_addr) {
  LOG4CPLUS_ASSERT(logger_, ldr_load_dll_addr_.is_valid());
  LOG4CPLUS_ASSERT(logger_, nt_set_event_addr_.is_valid());
}

bool DllInjector::InjectInto(
    int child_pid, int child_main_thread_id, bool leave_suspended) {
  base::ScopedHandle process_handle(::OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_READ |
          PROCESS_DUP_HANDLE |PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
      FALSE, child_pid));
  if (!process_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenProcess failed. Error " << error);
    return false;
  }
  base::ScopedHandle thread_handle(OpenThread(
      THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
      FALSE,
      child_main_thread_id));
  if (!thread_handle.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "OpenThread failed, error " << error);
    return false;
  }
  base::ScopedHandle inject_ready_event(CreateEvent(
      NULL, TRUE, FALSE, NULL));
  if (!inject_ready_event.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed create event, error " << error);
    return false;
  }
  const bool is_64bit = Is64BitProcess(process_handle);
#ifndef _M_AMD64
  // WOW64 -> x64 injection not supported yet.
  LOG4CPLUS_ASSERT(logger_, !is_64bit);
#endif

  const boost::filesystem::path& path_to_inject =
      is_64bit ? injected_64bit_path_ : injected_32bit_path_;
  std::wstring path_to_inject_str = path_to_inject.native();

  const size_t code_cave_len_native =
      reinterpret_cast<const uint8_t*>(code_cave_end) -
      reinterpret_cast<const uint8_t*>(code_cave);
  const uint8_t* code_cave_data_native =
      reinterpret_cast<const uint8_t*>(code_cave);
#ifdef _M_AMD64
  const size_t code_cave_len = is_64bit ?
      code_cave_len_native : sizeof(kCodeCave32);
  const uint8_t* code_cave_data = is_64bit ?
      code_cave_data_native : kCodeCave32;
#else
  const size_t code_cave_len = code_cave_len_native;
  const uint8_t* code_cave_data = code_cave_data_native;
#endif

  size_t buffer_len = (path_to_inject_str.length() + 1) * sizeof(WCHAR);
  const size_t kRemoteDataSize =
      is_64bit ? sizeof(RemoteData64) : sizeof(RemoteData32);
  buffer_len += kRemoteDataSize;
  buffer_len += code_cave_len;
  // Buffer structure:
  // <code_cave_code>, <RemoteData struct>, <DLL path buffer>
  std::vector<uint8_t> local_buffer(buffer_len);
  std::copy(code_cave_data,
            code_cave_data + code_cave_len,
            local_buffer.begin());
  wcscpy(
      reinterpret_cast<WCHAR*>(
          local_buffer.data() + kRemoteDataSize + code_cave_len),
      path_to_inject_str.c_str());
  HANDLE remote_event_handle = NULL;
  if (!DuplicateHandle(
      GetCurrentProcess(),
      inject_ready_event.Get(),
      process_handle.Get(),
      &remote_event_handle,
      0,
      FALSE,
      DUPLICATE_SAME_ACCESS)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "Failed duplicate handle, error " << error);
    return false;
  }
  LPVOID remote_addr = VirtualAllocEx(
      process_handle.Get(),
      nullptr,
      buffer_len,
      MEM_COMMIT,
      PAGE_EXECUTE_READWRITE);
  // RemoteAddrCleaner remote_addr_cleaner(process_handle.Get(), remote_addr);
  if (!remote_addr) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_, "Failed allocate remote memory, error " << error);
    return false;
  }
  uint8_t* remote_string_addr =
      reinterpret_cast<uint8_t*>(remote_addr) +
      code_cave_len + kRemoteDataSize;
  if (is_64bit) {
    RemoteData64::FillBuffer(
        local_buffer.data() + code_cave_len,
        path_to_inject_str.length(),
        remote_string_addr,
        remote_event_handle,
        ldr_load_dll_addr_.addr_64,
        nt_set_event_addr_.addr_64);
  } else {
    RemoteData32::FillBuffer(
        local_buffer.data() + code_cave_len,
        path_to_inject_str.length(),
        remote_string_addr,
        remote_event_handle,
        ldr_load_dll_addr_.addr_32,
        nt_set_event_addr_.addr_32);
  }

  SIZE_T bytes_written = 0;
  BOOL result = WriteProcessMemory(
      process_handle.Get(),
      remote_addr,
      local_buffer.data(),
      buffer_len,
      &bytes_written);
  if (!result || bytes_written != buffer_len) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "WriteProcessMemory failed, error " << error);
    return false;
  }
#ifdef _M_AMD64
  const bool is_wow64 = !is_64bit;
#else
  const bool is_wow64 = false;
#endif

  std::unique_ptr<ContextChangerBase> context_changer =
      ContextChangerBase::Create(is_wow64, thread_handle.Get());
  if (!context_changer->GetOriginalContext())
    return false;
  context_changer->SetUpCodeCave(
      reinterpret_cast<intptr_t>(remote_addr),
      reinterpret_cast<intptr_t>(remote_addr) + code_cave_len);
  if (!context_changer->SwitchCodeCaveContext())
    return false;
  if (ResumeThread(thread_handle.Get()) == -1) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "ResumeThread failed, error " << error);
    return false;
  }
  if (WaitForSingleObject(
      inject_ready_event.Get(), INFINITE) != WAIT_OBJECT_0) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "WaitForSingleObject failed, error " << error);
    return false;
  }
  // Use busy loop to finish wait operation. Need to avoid situations:
  // 1. Thread calls NtSetEvent
  // 2. Event object becomes signaled in kernel
  // 3. We call NtSuspendThread
  // 4. OS realizes that thread in kernel mode and assumes it "suspended"
  // 5. We set context and resume thread
  // 6. OS overwrites eax value "as result of NtSetEvent" call, and then
  // returns to UM, having all fields of context proper EXCEPT eax.
  // This is problem since ndll.dll thread initialization code assumes
  // eax will hold entry point address.
  static_assert(
      sizeof(RemoteData64) >= sizeof(RemoteData32),
      "RemoteData buffer size assumption is wrong");
  std::vector<uint8_t> read_buffer(sizeof(RemoteData64), 0);
  while (true) {
    SIZE_T bytes_read = 0;
    BOOL result = ReadProcessMemory(
        process_handle.Get(),
        static_cast<uint8_t*>(remote_addr) + code_cave_len,
        read_buffer.data(),
        read_buffer.size(),
        &bytes_read);
    if (!result || bytes_read != read_buffer.size()) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "ReadProcessMemory failed, error " << error);
      return false;
    }
    if (is_64bit) {
      if (reinterpret_cast<RemoteData64*>(read_buffer.data())->completed_flag)
        break;
    } else {
      if (reinterpret_cast<RemoteData32*>(read_buffer.data())->completed_flag)
        break;
    }
  }
  // We must susped thread before context switching, since changing
  // context of running thread may have unpredictable results.
  // In particular, context may not be changed instantly, and after
  // VirtualFreeEx process will crash due to execution on invalid address.
  if (!context_changer->SuspendThread())
    return false;
  if (!context_changer->SwitchToOriginalContext())
    return false;
  if (!leave_suspended) {
    if (ResumeThread(thread_handle.Get()) == -1) {
      DWORD error = GetLastError();
      LOG4CPLUS_ERROR(logger_, "ResumeThread failed, error " << error);
      return false;
    }
  }
  return true;
}
