// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include <windows.h>

#include "base/init_logging.h"
#include "log4cplus/loggingmacros.h"
#include "sthook/intercepted_functions.h"


BOOL CALLBACK DllMain(HINSTANCE h_instance, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    base::InitLogging();
    if (!sthook::InstallHooks(h_instance)) {
      LOG4CPLUS_ERROR(log4cplus::Logger::getRoot(),
                      "Hook installation failed");
    }
    sthook::Initialize();
  }
  return TRUE;
}
