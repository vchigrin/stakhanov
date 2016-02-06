/* Copyright 2015 The "Stakhanov" project authors. All rights reserved.
*  Use of this source code is governed by a GPLv2 license that can be
*  found in the LICENSE file.
*/

enum StdHandles {
  StdOutput,
  StdError
}

struct CacheHitInfo {
  1:bool cache_hit;
  // Further fields are valid only for cache hits.
  2:optional i32 exit_code;
  3:optional string result_stdout;
  4:optional string result_stderr;
}

service Executor {
  void Initialize(1:i32 current_pid, 2:string command_line, 3:string startup_directory);
  bool HookedCreateFile(1:string abs_path, 2:bool for_writing);
  void PushStdOutput(1:StdHandles handle, 2:binary data);
  CacheHitInfo OnBeforeProcessCreate(
      1:string exe_path,
      2:list<string> command_line,
      3:string startup_dir_utf8,
      4:list<string> environment_strings);

  void OnSuspendedProcessCreated(1:i32 child_pid);
}
