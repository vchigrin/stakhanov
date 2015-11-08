// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

void InstallHooks() {
}

BOOL CALLBACK DllMain(HINSTANCE h_instance, DWORD reason) {
  if (reason == DLL_PROCESS_ATTACH)
    InstallHooks();
  return TRUE;
}
