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
  # It is guarantes these env. variables set correctly during gclient runhooks
  # only. Write them to cache only if they are present and re-use them
  # later, when CMake is re-invoked by ninja, when these variables may be
  # absent.
  if(DEFINED ENV{INCLUDE})
    set(CACHED_INCLUDE "$ENV{INCLUDE}" CACHE INTERNAL "Preserved include path")
  endif()
  if(DEFINED ENV{LIB})
    set(CACHED_LIB "$ENV{LIB}" CACHE INTERNAL "Preserved lib path")
  endif()
  include_directories(SYSTEM ${CACHED_INCLUDE})
  link_directories(${CACHED_LIB})
endif()

if (WIN32)
  # Avoid automatic inclusion of winsock.h due to conflicts with winsock2.h
  add_definitions(-DWIN32_LEAN_AND_MEAN)
endif()

# TODO(vchigrin): Use ExternalProject_Add
set(LOG4CPLUS_ENABLE_DECORATED_LIBRARY_NAME OFF CACHE BOOL "" FORCE)

# ---------------------- Boost ---------------------------------------------
set(BOOST_ROOT "C:\\local\\boost_1_60_0")
if(CMAKE_CL_64)
  set(BOOST_LIBRARYDIR "${BOOST_ROOT}\\lib64-msvc-14.0")
else()
  set(BOOST_LIBRARYDIR "${BOOST_ROOT}\\lib32-msvc-14.0")
endif()
set(BOOST_INCLUDE "${BOOST_ROOT}")
set(Boost_USE_STATIC_LIBS        ON) # only find static libs
set(Boost_USE_MULTITHREADED      ON)
find_package(Boost REQUIRED COMPONENTS
  date_time
  filesystem
  program_options
  regex
  serialization
  system
)

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

# ---------------------- Crypto++ -----------------------------------------
# TODO(vchigrin): Remove this once Crypto++ will fix this.
set(DISABLE_ASM ON CACHE BOOL "" FORCE)  # At present fails x64 build.
add_subdirectory(third_party/cryptopp)

# ---------------------- RedisClient -----------------------------------------
add_subdirectory(third_party/redisclient)

# ---------------------- Other --------------------------------------------
if(${CMAKE_SYSTEM_NAME} STREQUAL "Windows")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D UNICODE -D _UNICODE")
endif()

set(CMAKE_DEBUG_POSTFIX "")

add_subdirectory(base)
add_subdirectory(stlaunch)
add_subdirectory(sthook)
add_subdirectory(stexecutor)
add_subdirectory(stproxy)
