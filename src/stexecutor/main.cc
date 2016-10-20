// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <iostream>

#include "base/filesystem_utils.h"
#include "base/init_logging.h"
#include "base/sthook_constants.h"
#include "base/string_utils.h"
#include "boost/program_options.hpp"
#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"
#include "boost/smart_ptr/make_shared.hpp"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "stexecutor/build_directory_state.h"
#include "stexecutor/dll_injector.h"
#include "stexecutor/executed_command_info.h"
#include "stexecutor/executing_engine.h"
#include "stexecutor/executor_factory.h"
#include "stexecutor/distributed_files_storage.h"
#include "stexecutor/files_filter.h"
#include "stexecutor/process_management_config.h"
#include "stexecutor/redis_client_pool.h"
#include "stexecutor/rules_mappers/in_memory_rules_mapper.h"
#include "stexecutor/rules_mappers/redis_rules_mapper.h"
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

  std::vector<wchar_t> mutabble_command_line;
  auto exe_path_str = exe_path.native();
  std::copy(
      exe_path_str.begin(),
      exe_path_str.end(),
      std::back_inserter(mutabble_command_line));
  mutabble_command_line.push_back(L' ');
  auto function_name_wide = base::ToWideFromANSI(function_name);
  std::copy(
      function_name_wide.begin(),
      function_name_wide.end(),
      std::back_inserter(mutabble_command_line));
  mutabble_command_line.push_back(L'\0');

  PROCESS_INFORMATION pi = { 0 };
  STARTUPINFO si = { 0 };
  DllInjector::SystemFunctionAddr result;
  if (!CreateProcessW(NULL, mutabble_command_line.data(), NULL, NULL, FALSE,
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

enum class RulesMapperType {
  InMemory,
  Redis
};

std::istream& operator >> (
    std::istream &in, RulesMapperType& rules_mapper_type) {  // NOLINT
  std::string token;
  in >> token;
  if (token == "in-memory")
    rules_mapper_type = RulesMapperType::InMemory;
  else if (token == "redis")
    rules_mapper_type = RulesMapperType::Redis;
  else
    throw boost::program_options::validation_error(
        boost::program_options::validation_error::invalid_option_value,
        "Invalid Rules mapper type");
  return in;
}

std::unique_ptr<rules_mappers::RulesMapper> CreateRulesMapper(
    const boost::program_options::variables_map& option_variables,
    const std::shared_ptr<RedisClientPool>& redis_client_pool) {
  RulesMapperType rules_mapper_type =
      option_variables["rules_mapper_type"].as<RulesMapperType>();
  if (rules_mapper_type == RulesMapperType::InMemory) {
    std::unique_ptr<rules_mappers::InMemoryRulesMapper> rules_mapper(
        new rules_mappers::InMemoryRulesMapper());
    auto it = option_variables.find("dump_rules_dir");
    if (it != option_variables.end()) {
      rules_mapper->set_dbg_dump_rules_dir(
          it->second.as<boost::filesystem::path>());
    }
    return rules_mapper;
  } else if (rules_mapper_type == RulesMapperType::Redis) {
    std::unique_ptr<rules_mappers::RedisRulesMapper> rules_mapper(
        new rules_mappers::RedisRulesMapper(redis_client_pool));
    return rules_mapper;
  } else {
    LOG4CPLUS_ASSERT(logger_, false);
    return nullptr;
  }
}

boost::property_tree::ptree LoadConfig(
    const boost::program_options::variables_map& variables) {
  boost::filesystem::ifstream config_stream(
      variables["config_file"].as<boost::filesystem::path>());
  boost::property_tree::ptree config;
  boost::property_tree::read_json(config_stream, config);
  return config;
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

int main(int argc, char* argv[]) {
  using apache::thrift::transport::TPipeServer;
  using apache::thrift::transport::TBufferedTransportFactory;
  using apache::thrift::protocol::TBinaryProtocolFactory;
  base::InitLogging(true);
  boost::program_options::options_description general_desc("General");
  general_desc.add_options()
      ("help", "Print help message")
      ("build_dir",
       boost::program_options::value<boost::filesystem::path>()->required(),
        "Directory where build will run")
      ("rules_mapper_type",
       boost::program_options::value<RulesMapperType>()->required(),
      "Rules mapper to use. Either \"in-memory\" or \"redis\"")
      ("dump_env_dir",
       boost::program_options::value<boost::filesystem::path>(),
        "Directory to dump env blocks for debugging purposes")
      ("config_file",
       boost::program_options::value<boost::filesystem::path>()->required(),
        "Path to config JSON file with additional options");

  boost::program_options::options_description in_memory_desc(
      "InMemory rules mapper options");
  in_memory_desc.add_options()
      ("dump_rules_dir",
       boost::program_options::value<boost::filesystem::path>(),
        "Directory to dump observed rules for debugging purposes");

  boost::program_options::options_description desc;
  desc.add(general_desc).add(in_memory_desc);

  boost::program_options::variables_map variables;
  try {
    boost::program_options::store(
        boost::program_options::parse_command_line(argc, argv, desc),
        variables);
  } catch (const std::exception& ex) {
    std::cerr << ex.what() << std::endl;
    return 1;
  }
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
  boost::filesystem::path build_dir_path =
      variables["build_dir"].as<boost::filesystem::path>();

  boost::filesystem::path current_executable_dir =
      base::GetCurrentExecutableDir();
  if (current_executable_dir.empty()) {
    LOG4CPLUS_FATAL(logger_, "Failed get current executable dir");
    return 1;
  }
  DllInjector::SystemFunctionAddr ldr_load_dll_addr = GetAddr(
      current_executable_dir, "LdrLoadDll");
  DllInjector::SystemFunctionAddr nt_set_event_addr = GetAddr(
      current_executable_dir, "NtSetEvent");
  if (!ldr_load_dll_addr.is_valid() || !nt_set_event_addr.is_valid()) {
    LOG4CPLUS_FATAL(logger_, "Failed get ntdll function addresses");
    return 1;
  }
  std::unique_ptr<DllInjector> dll_injector = std::make_unique<DllInjector>(
      current_executable_dir / base::kStHookDllName32Bit,
      current_executable_dir / base::kStHookDllName64Bit,
      ldr_load_dll_addr,
      nt_set_event_addr);

  boost::property_tree::ptree config = LoadConfig(variables);
  boost::property_tree::ptree redis_node = config.get_child("redis");

  std::string redis_sentinel_ip = redis_node.get<std::string>("sentinel_ip");
  std::string redis_slave_ip = redis_node.get<std::string>("slave_ip");
  int redis_sentinel_port = redis_node.get<int>("sentinel_port");
  int redis_slave_port = redis_node.get<int>("slave_port");
  std::string sentinel_master_name = redis_node.get<std::string>(
      "sentinel_master_name");

  std::shared_ptr<RedisClientPool> redis_client_pool =
      std::make_shared<RedisClientPool>(
          redis_sentinel_ip,
          redis_sentinel_port,
          redis_slave_ip,
          redis_slave_port,
          sentinel_master_name);

  std::unique_ptr<FilesStorage> file_storage(
      new DistributedFilesStorage(config, redis_client_pool));
  std::unique_ptr<rules_mappers::RulesMapper> rules_mapper =
      CreateRulesMapper(variables, redis_client_pool);
  if (!rules_mapper) {
    LOG4CPLUS_FATAL(logger_, "Failed create rules mapper");
    return 1;
  }
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
  auto it = variables.find("dump_env_dir");
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
