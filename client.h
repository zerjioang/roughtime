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

#ifndef SECURITY_ROUGHTIME_CLIENT_H_
#define SECURITY_ROUGHTIME_CLIENT_H_

#include <string>

#include "protocol.h"

namespace roughtime {

// Creates a client time request with the supplied |nonce|.
std::string CreateRequest(const uint8_t nonce[kNonceLength]);

// If the supplied |response_bytes| can be parsed, sets |*out_time| and
// |*out_radius| and returns true.  Otherwise returns false and sets
// |*out_error|.  The response must contain a path from the supplied |nonce|
// and a certificate signed with a private key that matches |root_public_key|.
bool ParseResponse(uint64_t *out_time, uint32_t *out_radius,
                   std::string *out_error,
                   const uint8_t root_public_key[kPublicKeyLength],
                   const uint8_t *response_bytes, size_t response_len,
                   const uint8_t nonce[kNonceLength]);

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_CLIENT_H_
