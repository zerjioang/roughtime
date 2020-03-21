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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

#include "logging.h"
#include "simple_server.h"
#include "sys_time.h"

// root_private_key is an Ed25519 private key used by simple_server. The
// private part consists of all zeros and so is only for use in this example.
constexpr uint8_t root_private_key[roughtime::kPrivateKeyLength] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0x6a, 0x27, 0xbc,
    0xce, 0xb6, 0xa4, 0x2d, 0x62, 0xa3, 0xa8, 0xd0, 0x2a, 0x6f, 0x0d, 0x73,
    0x65, 0x32, 0x15, 0x77, 0x1d, 0xe2, 0x43, 0xa6, 0x3a, 0xc0, 0x48, 0xa1,
    0x8b, 0x59, 0xda, 0x29,
};

int main(int argc, char **argv) {
  int requested_port = -1;
  ROUGHTIME_INIT_LOGGER(argv[0]);
  if (argc == 2) {
    char *endptr;
    requested_port = strtoul(argv[1], &endptr, 10);
    if (*endptr != 0) {
      requested_port = -1;
    }
  }

  if (requested_port < 0 || requested_port > 65535) {
    fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
    return 1;
  }

  int fd;
  uint16_t port;
  if (!roughtime::UdpProcessor::MakeSocket(requested_port, &fd, &port)) {
    return 1;
  }

  fprintf(stderr, "Listening on port %d.\n", port);

  std::unique_ptr<roughtime::Identity> identity =
      roughtime::SimpleServer::MakeIdentity(root_private_key, 0,
                                            2147483647000000);
  std::unique_ptr<roughtime::TimeSource> time_source(
      new roughtime::SystemTimeSource);

  auto server =
      std::unique_ptr<roughtime::SimpleServer>(new roughtime::SimpleServer(
          std::move(identity), std::move(time_source), fd));
  server->RunUntilError();
  return 1;
}
