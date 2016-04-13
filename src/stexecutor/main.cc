// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <cstdint>
#include <iostream>

#include "base/filesystem_utils.h"
#include "base/init_logging.h"
#include "base/sthook_constants.h"
#include "boost/program_options.hpp"
#include "boost/smart_ptr/make_shared.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/win32debugappender.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executed_command_info.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/executor_factory.h"
#include "stexecutor/filesystem_files_storage.h"
#include "stexecutor/rules_mappers/in_memory_rules_mapper.h"
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
    DWORD error = GetLastError();
    LOG4CPLUS_FATAL(logger_,
        ("Failed get LoadLibraryW 32-bit addr."
         " Process creation failed. Error ") << error);
    return 0;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD result = 0;
  if (!GetExitCodeProcess(pi.hProcess, &result)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_, "GetExitCodeProcess failed error " << error);
    return 0;
  }
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  return result;
}

using ServerType = apache::thrift::server::TThreadedServer;

std::unique_ptr<ServerType> g_server;

BOOL WINAPI ConsoleHandler(DWORD ctrl_type) {
  if (ctrl_type == CTRL_C_EVENT) {
    g_server->stop();
    return TRUE;
  }
  return FALSE;
}

}  // namespace

int main(int argc, char* argv[]) {
  using apache::thrift::transport::TServerSocket;
  using apache::thrift::transport::TBufferedTransportFactory;
  using apache::thrift::protocol::TBinaryProtocolFactory;
  base::InitLogging();

  boost::program_options::options_description desc("Allowed options");
  desc.add_options()
      ("help", "Print help message")
      ("cache_dir",
       boost::program_options::value<boost::filesystem::path>()->required(),
       "Directory with cached build results")
      ("build_dir",
       boost::program_options::value<boost::filesystem::path>()->required(),
        "Directory where build will run")
      ("dump_rules_dir",
       boost::program_options::value<boost::filesystem::path>(),
        "Directory to dump observed rules for debugging purposes")
      ("dump_env_dir",
       boost::program_options::value<boost::filesystem::path>(),
        "Directory to dump env blocks for debugging purposes");
  boost::program_options::variables_map variables;
  boost::program_options::store(
      boost::program_options::parse_command_line(argc, argv, desc),
      variables);
  if (variables.count("help")) {
    std::cout << desc;
    return 0;
  }
  try {
    boost::program_options::notify(variables);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }
  boost::filesystem::path cache_dir_path =
      variables["cache_dir"].as<boost::filesystem::path>();
  boost::filesystem::path build_dir_path =
      variables["build_dir"].as<boost::filesystem::path>();

  boost::filesystem::path current_executable_dir =
      base::GetCurrentExecutableDir();
  if (current_executable_dir.empty()) {
    LOG4CPLUS_FATAL(logger_, "Failed get current executable dir");
    return 1;
  }
  uint32_t load_library_addr32 = GetLoadLibraryAddr32(current_executable_dir);
  if (!load_library_addr32) {
    return 1;
  }
  // Assumed, that in case we want Stakhanov to work on 64-bit system, that
  // we will use 64-bit executor.
  uint64_t load_library_addr64 = reinterpret_cast<uint64_t>(&LoadLibraryW);
  std::unique_ptr<DllInjector> dll_injector = std::make_unique<DllInjector>(
      current_executable_dir / base::kStHookDllName32Bit,
      current_executable_dir / base::kStHookDllName64Bit,
      load_library_addr32,
      load_library_addr64);
  std::unique_ptr<FilesStorage> file_storage(
      new FilesystemFilesStorage(cache_dir_path));
  std::unique_ptr<rules_mappers::InMemoryRulesMapper> rules_mapper(
      new rules_mappers::InMemoryRulesMapper());
  auto it = variables.find("dump_rules_dir");
  if (it != variables.end()) {
    rules_mapper->set_dbg_dump_rules_dir(
        it->second.as<boost::filesystem::path>());
  }
  std::unique_ptr<BuildDirectoryState> build_dir_state(
      new BuildDirectoryState(build_dir_path));
  std::unique_ptr<ExecutingEngine> executing_engine(new ExecutingEngine(
      std::move(file_storage),
      std::move(rules_mapper),
      std::move(build_dir_state)));
  boost::shared_ptr<ExecutorFactory> executor_factory =
      boost::make_shared<ExecutorFactory>(
          std::move(dll_injector),
          executing_engine.get());
  it = variables.find("dump_env_dir");
  if (it != variables.end()) {
    executor_factory->set_dump_env_dir(
        it->second.as<boost::filesystem::path>());
  }
  g_server = std::make_unique<ServerType>(
      boost::make_shared<ExecutorProcessorFactory>(executor_factory),
      boost::make_shared<TServerSocket>(sthook::GetExecutorPort()),
      boost::make_shared<TBufferedTransportFactory>(),
      boost::make_shared<TBinaryProtocolFactory>());
  std::cout << "Start serving requests. Use Ctrl+C to stop server."
            << std::endl;
  SetConsoleCtrlHandler(&ConsoleHandler, TRUE);
  g_server->serve();
  SetConsoleCtrlHandler(&ConsoleHandler, FALSE);
  g_server.reset();
  executor_factory->Finish();
  return 0;
}
