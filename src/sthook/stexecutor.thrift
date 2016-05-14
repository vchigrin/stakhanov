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
  2:i32 executor_command_id;
  // Further fields have non-default values only for cache hits.
  3:i32 exit_code;
  4:string result_stdout;
  5:string result_stderr;
}

service Executor {
  // Returns true is it is safe to use "hoax proxy" for CreateProcess calls
  // from this process.
  bool Initialize(1:i32 current_pid, 2:bool is_root_process);
  bool HookedCreateFile(1:string abs_path, 2:bool for_writing);
  void PushStdOutput(1:StdHandles handle, 2:binary data);
  void HookedRenameFile(1:string old_name_str, 2:string new_name_str);
  CacheHitInfo OnBeforeProcessCreate(
      1:string exe_path,
      2:list<string> command_line,
      3:string startup_dir_utf8,
      4:list<string> environment_strings);
  void OnBeforeExitProcess();

  void OnSuspendedProcessCreated(
      1:i32 child_pid,
      2:i32 child_main_thread_id,
      3:i32 executor_commmand_id,
      // If append_std_streams is true - then all writes to std handles
      // must be considered also as writes to std handles of parent
      // process(es).
      4:bool append_std_streams,
      5:bool leave_suspended);
  void OnFileDeleted(1:string abs_path);
}
