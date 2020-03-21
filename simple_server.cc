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

#include "simple_server.h"

#include <openssl/curve25519.h>

#include "logging.h"
#include "server.h"

namespace roughtime {

SimpleServer::SimpleServer(std::unique_ptr<Identity> identity,
                           std::unique_ptr<TimeSource> time_source, int fd)
    : fd_(fd), server_(std::move(identity), std::move(time_source)) {}

bool SimpleServer::ProcessBatch() {
  UdpProcessor::Stats stats;
  return udp_processor_.ProcessBatch(fd_, &server_, &stats);
}

void SimpleServer::RunUntilError() {
  UdpProcessor::Stats stats;
  while (udp_processor_.ProcessBatch(fd_, &server_, &stats)) {
  }
}

// static
std::unique_ptr<Identity> SimpleServer::MakeIdentity(
    const uint8_t root_private_key[ED25519_PRIVATE_KEY_LEN], rough_time_t mint,
    rough_time_t maxt) {
  ROUGHTIME_CHECK(mint <= maxt);
  uint8_t delegated_private_key[ED25519_PRIVATE_KEY_LEN];
  uint8_t delegated_public_key[ED25519_PUBLIC_KEY_LEN];
  ED25519_keypair(delegated_public_key, delegated_private_key);

  auto identity = std::unique_ptr<Identity>(new Identity());
  CreateCertificate(identity->certificate, root_private_key, mint, maxt,
                    delegated_public_key);
  memcpy(identity->private_key, delegated_private_key,
         sizeof(delegated_private_key));
  return identity;
}

}  // namespace roughtime
