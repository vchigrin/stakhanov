// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <iostream>

#include "base/filesystem_utils.h"
#include "base/init_logging.h"
#include "base/interface.h"
#include "base/redis_client_pool.h"
#include "base/sthook_constants.h"
#include "base/string_utils.h"
#include "boost/program_options.hpp"
#include "boost/property_tree/ptree.hpp"
#include "boost/smart_ptr/make_shared.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executed_command_info.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/executor_factory.h"
#include "stexecutor/files_filter.h"
#include "stexecutor/process_management_config.h"
#include "stexecutor/rules_mappers/in_memory_rules_mapper.h"
#include "stexecutor/rules_mappers/redis_rules_mapper.h"
#include "stexecutorlib/distributed_files_storage.h"
#include "sthook/sthook_communication.h"
#include "thrift/server/TThreadedServer.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TPipeServer.h"

namespace {

const wchar_t kGetNtDllProcExecutable[] = L"get_ntdll_proc32.exe";

log4cplus::Logger logger_ = log4cplus::Logger::getRoot();

DllInjector::SystemFunctionAddr GetAddr(
    const boost::filesystem::path& current_executable_dir,
    const std::string& function_name) {
  boost::filesystem::path exe_path =
      current_executable_dir / kGetNtDllProcExecutable;

  // TODO: Check for spaces in exe path to wrap in quotes.
  std::wstring mutable_command_line(exe_path.native());
  mutable_command_line += L' ';
  mutable_command_line += base::ToWideFromANSI(function_name);

  PROCESS_INFORMATION pi = { 0 };
  STARTUPINFO si = { 0 };
  DllInjector::SystemFunctionAddr result;
  if (!CreateProcessW(NULL, &mutable_command_line[0], NULL, NULL, FALSE,
      0, NULL, NULL, &si, &pi)) {
    DWORD error = GetLastError();
    LOG4CPLUS_FATAL(logger_,
        "Failed get 32-bit addr. Process creation failed. Error " << error);
    return result;
  }
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exit_code = 0;
  if (!GetExitCodeProcess(pi.hProcess, &exit_code)) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(
        logger_, "GetExitCodeProcess failed error " << error);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
  }
  result.addr_32 = exit_code;
  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  // Assumed, that in case we want Stakhanov to work on 64-bit system, that
  // we will use 64-bit executor.
  result.addr_64 = reinterpret_cast<uint64_t>(
      GetProcAddress(GetModuleHandleW(L"ntdll.dll"), function_name.c_str()));
  return result;
}

using ServerType = apache::thrift::server::TThreadedServer;

std::unique_ptr<ServerType> g_server;

BOOL WINAPI ConsoleHandler(DWORD ctrl_type) {
  if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
    g_server->stop();
    return TRUE;
  }
  return FALSE;
}

std::tuple<std::unique_ptr<rules_mappers::RulesMapper>,
           std::unique_ptr<FilesStorage>>
CreateRulesMapperAndStorage(
    const boost::program_options::variables_map& option_variables) {
  using namespace interface;

  const RulesMapperType rules_mapper_type =
      option_variables[kRulesMapperTypeOption].as<interface::RulesMapperType>();
  const auto& config = LoadConfig(
      option_variables[kConfigFileOption].as<boost::filesystem::path>());

  // We don't need a Redis stuff in case of in-memory type.
  if (rules_mapper_type == RulesMapperType::InMemory) {
    std::unique_ptr<rules_mappers::InMemoryRulesMapper> rules_mapper(
        new rules_mappers::InMemoryRulesMapper());
    auto it = option_variables.find(kDumpRulesDirOption);
    if (it != option_variables.end()) {
      rules_mapper->set_dbg_dump_rules_dir(
          it->second.as<boost::filesystem::path>());
    }
    return std::make_tuple(std::move(rules_mapper),
                           std::make_unique<FilesystemFilesStorage>(config));
  } else if (rules_mapper_type == RulesMapperType::Redis) {
    std::shared_ptr<RedisClientPool> redis_pool =
        BuildRedisClientPoolFromConfig(config);
    std::unique_ptr<FilesStorage> file_storage(
        new DistributedFilesStorage(config, redis_pool));
    return std::make_tuple(
        std::make_unique<rules_mappers::RedisRulesMapper>(redis_pool),
        std::move(file_storage));
  } else {
    LOG4CPLUS_ASSERT(logger_, false);
    return { nullptr, nullptr };
  }
}

std::unique_ptr<DllInjector> CreateInjector() {
  const boost::filesystem::path current_executable_dir =
      base::GetCurrentExecutableDir();
  if (current_executable_dir.empty()) {
    LOG4CPLUS_FATAL(logger_, "Failed get current executable dir");
    return nullptr;
  }

  DllInjector::SystemFunctionAddr ldr_load_dll_addr = GetAddr(
      current_executable_dir, "LdrLoadDll");
  DllInjector::SystemFunctionAddr nt_set_event_addr = GetAddr(
      current_executable_dir, "NtSetEvent");
  if (!ldr_load_dll_addr.is_valid() || !nt_set_event_addr.is_valid()) {
    LOG4CPLUS_FATAL(logger_, "Failed get ntdll function addresses at path: "
                                 << current_executable_dir);
    return nullptr;
  }

  return std::make_unique<DllInjector>(
      current_executable_dir / base::kStHookDllName32Bit,
      current_executable_dir / base::kStHookDllName64Bit,
      ldr_load_dll_addr,
      nt_set_event_addr);
}

class CustomEventHandler : public apache::thrift::TProcessorEventHandler {
 public:
  virtual void handlerError(void* ctx, const char* fn_name) {
    LOG4CPLUS_FATAL(logger_, "Exception in function " << fn_name);
    // We do not expect any exceptions - assume it fatal and crash process.
    std::abort();
  }
};

class CustomExecutorProcessorFactory : public ExecutorProcessorFactory {
 public:
  CustomExecutorProcessorFactory(
      const boost::shared_ptr<ExecutorIfFactory>& handler_factory)
      : ExecutorProcessorFactory(handler_factory),
        event_handler_(new CustomEventHandler()) { }

  boost::shared_ptr<apache::thrift::TProcessor> getProcessor(
      const apache::thrift::TConnectionInfo& conn_info) override {
    boost::shared_ptr<apache::thrift::TProcessor> result =
        ExecutorProcessorFactory::getProcessor(conn_info);
    if (result)
      result->setEventHandler(event_handler_);
    return result;
  }

 private:
  boost::shared_ptr<apache::thrift::TProcessorEventHandler> event_handler_;
};

}  // namespace

int main(int argc, const char* argv[]) {
  using namespace interface;
  using apache::thrift::transport::TPipeServer;
  using apache::thrift::transport::TBufferedTransportFactory;
  using apache::thrift::protocol::TBinaryProtocolFactory;
  namespace fs = boost::filesystem;

  boost::program_options::variables_map variables;
  if (!interface::ProcessOptions(argc, argv, &variables, std::string()))
    return 1;

  base::InitLogging(!variables.count(kSilentLogOption));

  std::unique_ptr<DllInjector> dll_injector = CreateInjector();
  if (!dll_injector) {
    LOG4CPLUS_FATAL(logger_, "Failed to create DLL injector");
    return 1;
  }

  std::unique_ptr<rules_mappers::RulesMapper> rules_mapper;
  std::unique_ptr<FilesStorage> file_storage;
  std::tie(rules_mapper, file_storage) = CreateRulesMapperAndStorage(variables);
  if (!rules_mapper || !file_storage) {
    LOG4CPLUS_FATAL(logger_, "Failed to create rules mapper or storage");
    return 1;
  }

  const fs::path build_dir_path = variables[kBuildDirOption].as<fs::path>();
  boost::property_tree::ptree config =
      LoadConfig(variables[kConfigFileOption].as<boost::filesystem::path>());
  std::unique_ptr<BuildDirectoryState> build_dir_state(
      new BuildDirectoryState(build_dir_path));
  std::unique_ptr<ExecutingEngine> executing_engine(new ExecutingEngine(
      std::move(file_storage),
      std::move(rules_mapper),
      std::move(build_dir_state),
      std::make_unique<ProcessManagementConfig>(config)));

  boost::shared_ptr<ExecutorFactory> executor_factory =
      boost::make_shared<ExecutorFactory>(
          std::move(dll_injector),
          executing_engine.get(),
          std::make_unique<FilesFilter>(config));
  auto it = variables.find(kDumpEnvDirOption);
  if (it != variables.end()) {
    executor_factory->set_dump_env_dir(
        it->second.as<boost::filesystem::path>());
  }
  g_server = std::make_unique<ServerType>(
      boost::make_shared<CustomExecutorProcessorFactory>(executor_factory),
      boost::make_shared<TPipeServer>(sthook::kExecutorPipeName),
      boost::make_shared<TBufferedTransportFactory>(),
      boost::make_shared<TBinaryProtocolFactory>());
  std::cout
     << "Start serving requests. Use Ctrl+C or Ctrl+Break to stop server."
     << std::endl;
  SetConsoleCtrlHandler(&ConsoleHandler, TRUE);
  g_server->serve();
  std::cout << "Server stopped." << std::endl;
  SetConsoleCtrlHandler(&ConsoleHandler, FALSE);
  g_server.reset();
  executor_factory->Finish();
  return 0;
}
