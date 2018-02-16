/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h> //inet_addr

#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

FLAG(int32,
   local_tcp_logger_port,
   5555,
   "The port the Local TCP logger plugin will send data to (default 5555)");

class LocalTCPLoggerPlugin : public LoggerPlugin {
  int sock;

 public:
  bool usesLogStatus() override {
    return true;
  }

 protected:
  Status logString(const std::string& s) override;

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  Status logStatus(const std::vector<StatusLogLine>& log) override;
};

REGISTER(LocalTCPLoggerPlugin, "logger", "localtcp");

Status LocalTCPLoggerPlugin::logString(const std::string& s) {
  send(sock, s.c_str(), s.size(), 0);
  send(sock, "\n", 1, 0);
  return Status();
}

Status LocalTCPLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    std::string line = "severity=" + std::to_string(item.severity) +
                       " location=" + item.filename + ":" +
                       std::to_string(item.line) + " message=" + item.message + "\n";

    send(sock, line.c_str(), line.size(), 0);
  }
  return Status(0);
}

void LocalTCPLoggerPlugin::init(const std::string& name,
                              const std::vector<StatusLogLine>& log) {
  // Stop the internal Glog facilities.
  FLAGS_alsologtostderr = false;
  FLAGS_logtostderr = false;
  FLAGS_stderrthreshold = 5;

  struct sockaddr_in server;

  /* Create a socket address, with a specific port and (local) ipnumber */
  server.sin_family = AF_INET;
  server.sin_port = htons(FLAGS_local_tcp_logger_port);
  inet_aton("127.0.0.1", &server.sin_addr);

  /* Create socket */
  sock = socket(AF_INET, SOCK_STREAM, 0);

  if (connect(sock, (struct sockaddr *)&server , sizeof(server)) < 0){
    //Should be exit catastrohpic
    Initializer::requestShutdown(EXIT_CATASTROPHIC, "Could not configure logger");
  }
  // Now funnel the intermediate status logs provided to `init`.
  logStatus(log);
}
}
