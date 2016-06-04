// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "sthook/reading_pipe.h"

#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"

namespace {

const int kBufferSize = 1024;

log4cplus::Logger logger_ = log4cplus::Logger::getInstance(L"ReadingPipe");

}  // namespace


ReadingPipe::ReadingPipe()
    : bytes_read_(0),
      read_in_progress_(false) {
  memset(&overlapped_, 0, sizeof(overlapped_));
  buffer_.resize(kBufferSize);
  wait_event_ = base::ScopedHandle(CreateEvent(NULL, TRUE, FALSE, NULL));
  if (!wait_event_.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CreateEvent failed, error " << error);
  }
  CreatePipePair();
  overlapped_.hEvent = wait_event_.Get();
}

ReadingPipe::~ReadingPipe() {
  if (read_in_progress_) {
    LOG4CPLUS_FATAL(
        logger_, "ERROR - destroying reading pipe while read in progress.");
  }
}

bool ReadingPipe::IssueRead() {
  LOG4CPLUS_ASSERT(logger_, !read_in_progress_);
  BOOL success = ReadFile(
      read_handle_.Get(),
      &buffer_[0],
      static_cast<DWORD>(buffer_.size()),
      &bytes_read_,
      &overlapped_);
  DWORD error = GetLastError();
  if (!success && error != ERROR_IO_PENDING) {
    if (error != ERROR_BROKEN_PIPE) {
      LOG4CPLUS_ERROR(logger_, "ReadFile failed, error " << error);
    }
    read_handle_.Close();
    return false;
  }
  read_in_progress_ = true;
  return true;
}

int ReadingPipe::CompleteReadAndGetBytesTransfered() {
  LOG4CPLUS_ASSERT(logger_, read_in_progress_);
  read_in_progress_ = false;
  if (!GetOverlappedResult(
      read_handle_.Get(),
      &overlapped_,
      &bytes_read_,
      TRUE)) {
    DWORD error = GetLastError();
    if (error != ERROR_BROKEN_PIPE) {
      LOG4CPLUS_ERROR(
          logger_, "GetOverlappedResult failed, error " << error);
    }
    read_handle_.Close();
    return 0;
  }
  return bytes_read_;
}

void ReadingPipe::CreatePipePair() {
  std::wstringstream pipe_name_buf;
  // Unique pipe name based on PID and address of this object.
  pipe_name_buf << L"\\\\.\\pipe\\stakhanov_child_"
                << GetCurrentProcessId() << "_" << this;
  std::wstring pipe_name = pipe_name_buf.str();

  // Anonymous pipes does not support overlapped I/O, so we have to create
  // named pipe.
  read_handle_ = base::ScopedHandle(CreateNamedPipeW(
      pipe_name.c_str(),
      PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE,
      PIPE_UNLIMITED_INSTANCES,
      0,
      0,
      INFINITE,
      NULL));
  if (!read_handle_.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CreateNamedPipe failed, error " << error);
    return;
  }

  OVERLAPPED overlapped_connect;
  memset(&overlapped_connect, 0, sizeof(overlapped_connect));
  if (!ConnectNamedPipe(read_handle_.Get(), &overlapped_connect)) {
    DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) {
      LOG4CPLUS_ERROR(
          logger_, "ConnectNamedPipe failed, error " << error);
      return;
    }
  }

  SECURITY_ATTRIBUTES write_security_attributes;
  memset(&write_security_attributes, 0, sizeof(write_security_attributes));
  write_security_attributes.nLength = sizeof(SECURITY_ATTRIBUTES);
  write_security_attributes.bInheritHandle = TRUE;
  write_handle_ = base::ScopedHandle(CreateFileW(
      pipe_name.c_str(),
      GENERIC_WRITE,
      0,
      &write_security_attributes,
      OPEN_EXISTING,
      0,
      NULL));
  if (!write_handle_.IsValid()) {
    DWORD error = GetLastError();
    LOG4CPLUS_ERROR(logger_, "CreateFile failed, error " << error);
  }
}
