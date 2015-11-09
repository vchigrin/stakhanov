// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "log4cplus/appender.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/layout.h"
#include "log4cplus/win32debugappender.h"
#include "sthook/intercepted_functions.h"

#include <windows.h>

void InitLogging() {
  log4cplus::initialize();
  log4cplus::helpers::SharedObjectPtr<log4cplus::Win32DebugAppender>
      append_1(new log4cplus::Win32DebugAppender());
  append_1->setLayout(
      std::auto_ptr<log4cplus::Layout>(new log4cplus::TTCCLayout()));
  log4cplus::Logger::getRoot().addAppender(
      log4cplus::SharedAppenderPtr(append_1.get()));
  log4cplus::Logger::getRoot().setLogLevel(log4cplus::TRACE_LOG_LEVEL);
}

BOOL CALLBACK DllMain(HINSTANCE h_instance, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    InitLogging();
    if (!sthook::InstallHooks(h_instance)) {
      LOG4CPLUS_ERROR(log4cplus::Logger::getRoot(),
                      "Hook installation failed");
    }
  }
  return TRUE;
}
