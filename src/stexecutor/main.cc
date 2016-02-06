// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <cstdint>

#include "base/filesystem_utils.h"
#include "base/init_logging.h"
#include "base/sthook_constants.h"
#include "boost/smart_ptr/make_shared.hpp"
#include "boost/archive/xml_oarchive.hpp"
#include "boost/serialization/vector.hpp"
#include "boost/serialization/unordered_set.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/win32debugappender.h"
#include "stexecutor/executed_command_info.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executor_factory.h"
#include "stexecutor/filesystem_files_storage.h"
#include "sthook/sthook_communication.h"
#include "thrift/server/TThreadedServer.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TServerSocket.h"
/*
namespace boost {
namespace serialization {

template<typename Archive>
void serialize(
    Archive& ar, CommandInfo& command, const unsigned int version) { // NOLINT
  ar & BOOST_SERIALIZATION_NVP(command.exit_code);
  ar & BOOST_SERIALIZATION_NVP(command.id);
  ar & BOOST_SERIALIZATION_NVP(command.startup_directory);
  ar & BOOST_SERIALIZATION_NVP(command.command_line);
  ar & BOOST_SERIALIZATION_NVP(command.input_files);
  ar & BOOST_SERIALIZATION_NVP(command.output_files);
  ar & BOOST_SERIALIZATION_NVP(command.child_command_ids);
  ar & BOOST_SERIALIZATION_NVP(command.result_stdout);
  ar & BOOST_SERIALIZATION_NVP(command.result_stderr);
}

}  // namespace serialization
}  // namespace boost
*/
namespace {

const wchar_t kGetLoadLibraryAddrExecutable[] = L"get_load_library_addr32.exe";
const wchar_t kDumpFileName[] = L"build_commands.xml";

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

boost::filesystem::path GetDumpFileName() {
  boost::filesystem::path executable_dir = base::GetCurrentExecutableDir();
  return executable_dir / kDumpFileName;
}
/*
void GenerateCommandsDump(
    const std::vector<CommandInfo>& commands,
    const boost::filesystem::path& dump_path) {
  std::ofstream stream(dump_path.string());
  boost::archive::xml_oarchive archive(stream);
  archive & BOOST_SERIALIZATION_NVP(commands);
}
*/
}  // namespace

int main(int argc, char* argv) {
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
     ///j
       boost::filesystem::path build_dir_path
       std::unique_ptr<CachedFilesStorage> file_storage(new FilesystemFilesStorage(cache_dir_path));
       std::unique_ptr<RulesMapper> rules_mapper(new RulesMapper());
./..
  std::unique_ptr<ExecutingEngine> executing_engine(new ExecutingEngine(
      build_dir_path,
      std::move(file_storage),
      std::move(rules_mapper)
  ));
  boost::shared_ptr<ExecutorFactory> executor_factory =
      boost::make_shared<ExecutorFactory>(
          std::move(dll_injector),
          executing_engine.get());
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
  boost::filesystem::path dump_path = GetDumpFileName();
  std::cout << "Done. Writing commands dump into " << dump_path.string()
            << std::endl;
            /*
  GenerateCommandsDump(
      executor_factory->FinishAndGetCommandsInfo(), dump_path);
  */
  return 0;
}
