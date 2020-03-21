/* Copyright 2016 The Roughtime Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. */

#ifndef SECURITY_ROUGHTIME_SIMPLE_SERVER_H_
#define SECURITY_ROUGHTIME_SIMPLE_SERVER_H_

#include <arpa/inet.h>
#include <netinet/in.h>

#include "server.h"
#include "time_source.h"
#include "udp_processor.h"

namespace roughtime {

// SimpleServer wraps |Server| with enough intelligence to read requests from,
// and write requests to, a supplied socket.  There's no reason in principle
// that one couldn't run multiple instances per socket.
//
// This class exists for testing and to provide an example rather than as a
// basis for a production-quality server.
class SimpleServer {
 public:
  // |identity| is the server's certificate.  |fd| is the socket to be used to
  // receive requests and send responses.
  SimpleServer(std::unique_ptr<Identity> identity,
               std::unique_ptr<TimeSource> time_source, int fd);

  // RunUntilError receives and responds to a batches of requests until an
  // unexpected error occurs.
  void RunUntilError();

  // ProcessBatch calls UdpProcessor::ProcessBatch.
  bool ProcessBatch();

  // MakeIdentity creates a dummy server certificate that is valid for the
  // given time range.
  static std::unique_ptr<Identity> MakeIdentity(
      const uint8_t root_private_key[kPrivateKeyLength],
      rough_time_t mint, rough_time_t maxt);

 private:
  const int fd_;
  Server server_;
  UdpProcessor udp_processor_;
};

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_SIMPLE_SERVER_H_
