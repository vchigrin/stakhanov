/* Copyright 2015 The "Stakhanov" project authors. All rights reserved.
*  Use of this source code is governed by a GPLv2 license that can be
*  found in the LICENSE file.
*/

enum StdHandles {
  StdOutput,
  StdError
}

service Executor {
  void Initialize(1:i32 current_pid, 2:string command_line, 3:string startup_directory);
  bool HookedCreateFile(1:string abs_path, 2:bool for_writing);
  void PushStdOutput(1:StdHandles handle, 2:binary data);

  void OnSuspendedProcessCreated(1:i32 child_pid);
}
