# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_executable(stexecutor
  build_directory_state.cc
  build_directory_state.h
  cumulative_execution_response_builder.cc
  cumulative_execution_response_builder.h
  dll_injector.cc
  dll_injector.h
  executed_command_info.h
  executing_engine.cc
  executing_engine.h
  executor_factory.cc
  executor_factory.h
  executor_impl.cc
  executor_impl.h
  file_hash.cc
  file_hash.h
  files_storage.h
  filesystem_files_storage.cc
  filesystem_files_storage.h
  main.cc
  process_creation_request.cc
  process_creation_request.h
  process_creation_response.cc
  process_creation_response.h
  process_management_config.cc
  process_management_config.h
  redis_key_prefixes.cc
  redis_key_prefixes.h
  rules_mappers/cached_execution_response.h
  rules_mappers/file_info.h
  rules_mappers/file_set.cc
  rules_mappers/file_set.h
  rules_mappers/in_memory_request_results.cc
  rules_mappers/in_memory_request_results.h
  rules_mappers/in_memory_rules_mapper.cc
  rules_mappers/in_memory_rules_mapper.h
  rules_mappers/redis_request_results.cc
  rules_mappers/redis_request_results.h
  rules_mappers/redis_rules_mapper.cc
  rules_mappers/redis_rules_mapper.h
  rules_mappers/request_results_base.cc
  rules_mappers/request_results_base.h
  rules_mappers/rules_hashing.h
  rules_mappers/rules_mapper.h
  rules_mappers/rules_mapper_base.cc
  rules_mappers/rules_mapper_base.h
)

target_link_libraries(stexecutor
  base
  cryptopp-static
  log4cplus
  sthook_communication
)

target_compile_definitions(stexecutor PRIVATE
  # To avoid warnings about MD5. They are fine since we use it not for
  # cryptographic targets.
  CRYPTOPP_ENABLE_NAMESPACE_WEAK=1
)

target_include_directories(stexecutor PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
    ${BOOST_INCLUDE}
    ${THRIFT_INCLUDE}
    ${LOG4CPLUS_INCLUDE}
)

if(NOT CMAKE_CL_64)
  add_executable(get_load_library_addr32 get_load_library_addr.cc)
  add_dependencies(stexecutor get_load_library_addr32)
endif()
