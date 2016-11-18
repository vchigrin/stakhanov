# Copyright 2016 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

add_library(stexecutorlib STATIC
  distributed_files_storage.cc
  distributed_files_storage.h
  file_hash.cc
  file_hash.h
  files_storage.h
  filesystem_files_storage.cc
  filesystem_files_storage.h
  redis_key_prefixes.cc
  redis_key_prefixes.h
)


target_link_libraries(stexecutorlib
  ${Boost_LIBRARIES}
  cryptopp-static
  log4cplus
)

target_compile_definitions(stexecutorlib PRIVATE
  # To avoid warnings about MD5. They are fine since we use it not for
  # cryptographic targets.
  CRYPTOPP_ENABLE_NAMESPACE_WEAK=1
)

target_include_directories(stexecutorlib PUBLIC
  ${BOOST_INCLUDE}
  ${LOG4CPLUS_INCLUDE}
)
