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
#include "boost/property_tree/ptree.hpp"
#include "boost/property_tree/json_parser.hpp"
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
#include "stexecutor/process_management_config.h"
#include "stexecutor/rules_mappers/in_memory_rules_mapper.h"
#include "stexecutor/rules_mappers/redis_rules_mapper.h"
#include "sthook/sthook_communication.h"
#include "third_party/redisclient/src/redisclient/redissyncclient.h"
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

boost::asio::io_service& GetIOService() {
  static std::unique_ptr<boost::asio::io_service> result;
  if (!result) {
    result.reset(new boost::asio::io_service());
  }
  return *result;
}

void OnRedisError(const std::string& error_msg) {
  LOG4CPLUS_ERROR(logger_, "REDIS ERROR " << error_msg.c_str());
}

std::unique_ptr<rules_mappers::RulesMapper> CreateRulesMapper(
    const boost::program_options::variables_map& option_variables) {
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
    std::unique_ptr<RedisSyncClient> redis_client(
        new RedisSyncClient(GetIOService()));

    std::string redis_ip = option_variables["redis_ip"].as<std::string>();
    int redis_port = option_variables["redis_port"].as<int>();
    boost::asio::ip::tcp::endpoint endpoint(
        boost::asio::ip::address::from_string(redis_ip), redis_port);
    std::string errmsg;
    if (!redis_client->connect(endpoint, errmsg)) {
      std::cerr
          << "Failed connect to the Redis server " << errmsg << std::endl;
      return nullptr;
    }
    redis_client->installErrorHandler(OnRedisError);
    std::unique_ptr<rules_mappers::RedisRulesMapper> rules_mapper(
        new rules_mappers::RedisRulesMapper(std::move(redis_client)));
    return rules_mapper;
  } else {
    LOG4CPLUS_ASSERT(logger_, false);
    return nullptr;
  }
}

std::unique_ptr<ProcessManagementConfig>
CreateProcessManagementConfig(
    const boost::program_options::variables_map& variables) {
  boost::property_tree::ptree config;
  auto it = variables.find("config_file");
  if (it != variables.end()) {
    boost::filesystem::ifstream config_stream(
        it->second.as<boost::filesystem::path>());
    boost::property_tree::read_json(config_stream, config);
  }
  return std::make_unique<ProcessManagementConfig>(config);
}

}  // namespace

int main(int argc, char* argv[]) {
  using apache::thrift::transport::TServerSocket;
  using apache::thrift::transport::TBufferedTransportFactory;
  using apache::thrift::protocol::TBinaryProtocolFactory;
  base::InitLogging(true);
  boost::program_options::options_description general_desc("General");
  general_desc.add_options()
      ("help", "Print help message")
      ("cache_dir",
       boost::program_options::value<boost::filesystem::path>()->required(),
       "Directory with cached build results")
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
       boost::program_options::value<boost::filesystem::path>(),
        "Path to config JSON file with additional options");

  boost::program_options::options_description in_memory_desc(
      "InMemory rules mapper options");
  in_memory_desc.add_options()
      ("dump_rules_dir",
       boost::program_options::value<boost::filesystem::path>(),
        "Directory to dump observed rules for debugging purposes");

  boost::program_options::options_description redis_desc(
      "Redis rules mapper options");
  redis_desc.add_options()
      ("redis_ip",
       boost::program_options::value<std::string>()->default_value(
           "127.0.0.1"),
       "IP of the Redis server")
      ("redis_port",
       boost::program_options::value<int>()->default_value(6379),
       "Port of the Redis server");
  boost::program_options::options_description desc;
  desc.add(general_desc).add(in_memory_desc).add(redis_desc);

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
  std::unique_ptr<rules_mappers::RulesMapper> rules_mapper =
      CreateRulesMapper(variables);
  if (!rules_mapper)
    return 1;
  std::unique_ptr<BuildDirectoryState> build_dir_state(
      new BuildDirectoryState(build_dir_path));
  std::unique_ptr<ExecutingEngine> executing_engine(new ExecutingEngine(
      std::move(file_storage),
      std::move(rules_mapper),
      std::move(build_dir_state),
      CreateProcessManagementConfig(variables)));

  boost::shared_ptr<ExecutorFactory> executor_factory =
      boost::make_shared<ExecutorFactory>(
          std::move(dll_injector),
          executing_engine.get());
  auto it = variables.find("dump_env_dir");
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
