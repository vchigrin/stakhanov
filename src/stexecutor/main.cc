// Copyright 2015 The "Stakhanov" project authors. All rights reserved.
// Use of this source code is governed by a GPLv2 license that can be
// found in the LICENSE file.

#include "boost/smart_ptr/make_shared.hpp"
#include "log4cplus/appender.h"
#include "log4cplus/layout.h"
#include "log4cplus/logger.h"
#include "log4cplus/loggingmacros.h"
#include "log4cplus/win32debugappender.h"
#include "thrift/server/TThreadedServer.h"
#include "thrift/transport/TBufferTransports.h"
#include "thrift/transport/TServerSocket.h"

#include "gen-cpp/Executor.h"

using apache::thrift::server::TThreadedServer;
using apache::thrift::transport::TServerSocket;
using apache::thrift::transport::TBufferedTransportFactory;
using apache::thrift::protocol::TBinaryProtocolFactory;

class ExecutorImpl : public ExecutorIf {
 public:
  bool HookedCreateFile(
      const std::string& abs_path, const bool for_writing) override {
    return true;
  }

  void HookedCloseFile(const std::string& abs_path) override {
  }
};

int main(int argc, char* argv) {
  boost::shared_ptr<ExecutorImpl> executor(new ExecutorImpl());
  TThreadedServer server(
    boost::make_shared<ExecutorProcessor>(executor),
    boost::make_shared<TServerSocket>(9090),  // port
    boost::make_shared<TBufferedTransportFactory>(),
    boost::make_shared<TBinaryProtocolFactory>());
  return 0;
}
