/* Copyright 2015 The "Stakhanov" project authors. All rights reserved.
*  Use of this source code is governed by a GPLv2 license that can be
*  found in the LICENSE file.
*/

service Executor {
  bool HookedCreateFile(1:string abs_path, 2:bool for_writing);
  void HookedCloseFile(1:string abs_path);
}
