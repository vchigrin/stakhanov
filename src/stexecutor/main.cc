// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <cstdint>

#include "base/filesystem_utils.h"
#include "base/init_logging.h"
#include "base/sthook_constants.h"
#include "boost/smart_ptr/make_shared.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/win32debugappender.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executor_impl.h"
#include "sthook/sthook_communication.h"
#include "thrift/server/TThreadedServer.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TServerSocket.h"

namespace {

const wchar_t kGetLoadLibraryAddrExecutable[] = L"get_load_library_addr32.exe";

log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

uint32_t GetLoadLibraryAddr32(
    const boost::filesystem::path& current_executable_dir) {
  boost::filesystem::path exe_path =
      current_executable_dir / kGetLoadLibraryAddrExecutable;
  PROCESS_INFORMATION pi = { 0 };
  STARTUPINFO si = { 0 };
  if (!CreateProcessW(exe_path.c_str(), NULL, NULL, NULL, FALSE,
      0, NULL, NULL, &si, &pi)) {
    LOG4CPLUS_FATAL(logger_,
        ("Failed get LoadLibraryW 32-bit addr."
         " Process creation failed. Error ") << GetLastError());
    return 0;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD result = 0;
  if (!GetExitCodeProcess(pi.hProcess, &result)) {
    LOG4CPLUS_ERROR(
        logger_, "GetExitCodeProcess failed error " << GetLastError());
    return 0;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return result;
}

}  // namespace

int main(int argc, char* argv) {
  using apache::thrift::server::TThreadedServer;
  using apache::thrift::transport::TServerSocket;
  using apache::thrift::transport::TBufferedTransportFactory;
  using apache::thrift::protocol::TBinaryProtocolFactory;

  base::InitLogging();
  boost::filesystem::path current_executable_dir =
      base::GetCurrentExecutableDir();
  if (current_executable_dir.empty()) {
    LOG4CPLUS_FATAL(logger_, "Failed get current executable dir");
    return 1;
  }
  uint32_t load_library_addr32 = GetLoadLibraryAddr32(current_executable_dir);
  // Assumed, that in case we want Stakhanov to work on 64-bit system, that
  // we will use 64-bit executor.
  uint64_t load_library_addr64 = reinterpret_cast<uint64_t>(&LoadLibraryW);
  std::unique_ptr<DllInjector> dll_injector = std::make_unique<DllInjector>(
      current_executable_dir / base::kStHookDllName32Bit,
      current_executable_dir / base::kStHookDllName64Bit,
      load_library_addr32,
      load_library_addr64);

  boost::shared_ptr<ExecutorImpl> executor(
      new ExecutorImpl(std::move(dll_injector)));
  TThreadedServer server(
      boost::make_shared<ExecutorProcessor>(executor),
      boost::make_shared<TServerSocket>(sthook::GetExecutorPort()),
      boost::make_shared<TBufferedTransportFactory>(),
      boost::make_shared<TBinaryProtocolFactory>());
  LOG4CPLUS_INFO(logger_, "Thrift server starting...");
  server.serve();
  LOG4CPLUS_INFO(logger_, "Done. Exiting.");
  return 0;
}
