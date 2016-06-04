// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#ifndef STHOOK_READING_PIPE_H_
#define STHOOK_READING_PIPE_H_

#include <vector>

#include "base/scoped_handle.h"

// Incapsulates pipe handle pair, used for asynchronous reading
// stdout/stderr streams from child process.
class ReadingPipe {
 public:
  ReadingPipe();
  ~ReadingPipe();
  HANDLE write_handle_for_child() const {
    return write_handle_.Get();
  }
  void CloseWriteHandle() {
    // Need to avoid ReadFile() infinite waiting for more data.
    write_handle_.Close();
  }
  HANDLE wait_handle() const {
    return wait_event_.Get();
  }
  bool IssueRead();
  int CompleteReadAndGetBytesTransfered();
  const std::vector<char> buffer() const {
    return buffer_;
  }
  ReadingPipe(const ReadingPipe&) = delete;
  const ReadingPipe& operator = (const ReadingPipe&) = delete;

 private:
  void CreatePipePair();

  std::vector<char> buffer_;
  OVERLAPPED overlapped_;
  DWORD bytes_read_;
  bool read_in_progress_;
  base::ScopedHandle read_handle_;
  base::ScopedHandle write_handle_;
  base::ScopedHandle wait_event_;
};

#endif  // STHOOK_READING_PIPE_H_
