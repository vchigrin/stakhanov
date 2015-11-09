# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

cmake_minimum_required (VERSION 3.3.2)
project (stakhanov)

set (LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set (EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

include_directories (.)

if (MSVC)
  set (MSVC_DISABLED_WARNINGS
    /wd4800  # Forcing value of BOOL to true/false
  )
  set (CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} ${MSVC_DISABLED_WARNINGS}" )
endif (MSVC)

# TODO(vchigrin): Use ExternalProject_Add
set (LOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME OFF CACHE BOOL "" FORCE)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D UNICODE -D _UNICODE")
endif()

set (BUILD_SHARED_LIBS FALSE CACHE BOOL "" FORCE)
add_subdirectory (third_party/log4cplus)
set (LOG4CPLUS_INCLUDE ${CMAKE_SOURCE_DIR}/third_party/log4cplus/include)
add_subdirectory (sthook)
