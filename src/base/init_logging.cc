// Copyright 2016 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "base/init_logging.h"

#include "log4cplus/appender.h"
#include "log4cplus/consoleappender.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/layout.h"
#include "log4cplus/log4judpappender.h"
#include "log4cplus/win32debugappender.h"

namespace base {

void InitLogging(bool allow_console_output) {
  log4cplus::initialize();
  log4cplus::helpers::SharedObjectPtr<log4cplus::Win32DebugAppender>
      append_1(new log4cplus::Win32DebugAppender());
  append_1->setLayout(
      std::auto_ptr<log4cplus::Layout>(new log4cplus::TTCCLayout()));
  log4cplus::Logger::getRoot().addAppender(
      log4cplus::SharedAppenderPtr(append_1.get()));

  log4cplus::helpers::SharedObjectPtr<log4cplus::Log4jUdpAppender>
      append_2(new log4cplus::Log4jUdpAppender(L"127.0.0.1", 7071));
  log4cplus::Logger::getRoot().addAppender(
      log4cplus::SharedAppenderPtr(append_2.get()));

  if (allow_console_output) {
    // log to stderr, immediate flush true. We use console output only
    // for errors and warnings, so it is better to output them ASAP.
    log4cplus::SharedAppenderPtr console_appender(
        new log4cplus::ConsoleAppender(true, true));
    console_appender->setThreshold(log4cplus::WARN_LOG_LEVEL);
    log4cplus::Logger::getRoot().addAppender(console_appender);
  }

  log4cplus::Logger::getRoot().setLogLevel(log4cplus::TRACE_LOG_LEVEL);
}

}  // namespace base
