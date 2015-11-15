# Copyright 2015 The "Stakhanov" project authors. All rights reserved.
# Use of this source code is governed by a GPLv2 license that can be
# found in the LICENSE file.

cmake_minimum_required(VERSION 3.3.2)
project(stakhanov)

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

include_directories(.)

if(MSVC)
  set(MSVC_DISABLED_WARNINGS
    "/wd4800")  # Forcing value of BOOL to true/false
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${MSVC_DISABLED_WARNINGS}")
endif()

# TODO(vchigrin): Use ExternalProject_Add
set(LOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME OFF CACHE BOOL "" FORCE)

# ---------------------- Boost ---------------------------------------------
set(BOOST_ROOT "${CMAKE_SOURCE_DIR}/third_party/boost")
set(BOOST_INCLUDE "${BOOST_ROOT}")

# ---------------------- Thrift --------------------------------------------
set(WITH_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
set(BUILD_C_GLIB OFF CACHE BOOL "" FORCE)
set(BUILD_JAVA OFF CACHE BOOL "" FORCE)
set(BUILD_PYTHON OFF CACHE BOOL "" FORCE)
set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FLEX_EXECUTABLE
    "${CMAKE_SOURCE_DIR}/third_party/win_flex_bison/win_flex.exe")
set(BISON_EXECUTABLE
    "${CMAKE_SOURCE_DIR}/third_party/win_flex_bison/win_bison.exe")
set(OLD_SOURCE_DIR "${CMAKE_SOURCE_DIR}")
set(CMAKE_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third_party/thrift")
add_subdirectory(third_party/thrift)
set(CMAKE_SOURCE_DIR "${OLD_SOURCE_DIR}")

set(THRIFT_INCLUDE "${CMAKE_SOURCE_DIR}/third_party/thrift/lib/cpp/src")

# ---------------------- Log4cplus --------------------------------------------
set(BUILD_SHARED_LIBS FALSE CACHE BOOL "" FORCE)
add_subdirectory(third_party/log4cplus)

set(LOG4CPLUS_INCLUDE "${CMAKE_SOURCE_DIR}/third_party/log4cplus/include")

# ---------------------- Other --------------------------------------------
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D UNICODE -D _UNICODE")
endif()

add_subdirectory(stlaunch)
add_subdirectory(sthook)
add_subdirectory(stexecutor)
