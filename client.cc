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

#include <string>

#include <stdint.h>

#include <openssl/curve25519.h>

#include "client.h"
#include "logging.h"

namespace roughtime {

std::string CreateRequest(const uint8_t nonce[kNonceLength]) {
  uint8_t query_bytes[kMinRequestSize];
  size_t query_len;

  Builder query(query_bytes, sizeof(query_bytes), 2);

  uint8_t* padding;

  static_assert(kTagNONC < kTagPAD, "Tags must be written in order");
  ROUGHTIME_CHECK(query.AddTagData(kTagNONC, nonce, kNonceLength) &&
               query.AddTag(&padding, kTagPAD, kPaddingLen) &&
               query.Finish(&query_len));
  ROUGHTIME_CHECK_EQ(query_len, sizeof(query_bytes));

  memset(padding, 0, kPaddingLen);

  return std::string(reinterpret_cast<char*>(query_bytes), query_len);
}

bool ParseResponse(rough_time_t* out_time, uint32_t* out_radius,
                   std::string* out_error,
                   const uint8_t root_public_key[ED25519_PUBLIC_KEY_LEN],
                   const uint8_t* response_bytes, size_t response_len,
                   const uint8_t nonce[kNonceLength]) {
  *out_time = 0;
  *out_radius = 0;

  Parser response(response_bytes, response_len);
  if (!response.is_valid()) {
    *out_error = "structural error";
    return false;
  }

  const uint8_t* cert_bytes;
  size_t cert_len;
  if (!response.GetTag(&cert_bytes, &cert_len, kTagCERT)) {
    *out_error = "no certificate provided";
    return false;
  }

  Parser cert(cert_bytes, cert_len);
  if (!cert.is_valid()) {
    *out_error = "structural error in certificate";
    return false;
  }

  const uint8_t* signature;
  if (!cert.GetFixedLen(&signature, kTagSIG, ED25519_SIGNATURE_LEN)) {
    *out_error = "no signature in certificate";
    return false;
  }

  const uint8_t* delegation_bytes;
  size_t delegation_len;
  if (!cert.GetTag(&delegation_bytes, &delegation_len, kTagDELE)) {
    *out_error = "no delegation in certificate";
    return false;
  }

  std::string signed_message =
      std::string(kCertContextString, sizeof(kCertContextString)) +
      std::string(reinterpret_cast<const char*>(delegation_bytes),
                  delegation_len);

  if (!ED25519_verify(reinterpret_cast<const uint8_t*>(signed_message.data()),
                      signed_message.size(), signature, root_public_key)) {
    *out_error = "bad signature in certificate";
    return false;
  }

  const uint8_t* delegated_public_key;
  rough_time_t min_time, max_time;
  Parser delegation(delegation_bytes, delegation_len);
  if (!delegation.is_valid() ||
      !delegation.Get(&min_time, kTagMINT) ||
      !delegation.Get(&max_time, kTagMAXT) ||
      !delegation.GetFixedLen(&delegated_public_key, kTagPUBK,
                              ED25519_PUBLIC_KEY_LEN)) {
    *out_error = "delegation missing required value";
    return false;
  }

  if (max_time < min_time) {
    *out_error = "invalid delegation validity period";
    return false;
  }

  const uint8_t* signed_response_bytes;
  size_t signed_response_len;
  if (!response.GetTag(&signed_response_bytes, &signed_response_len,
                       kTagSREP)) {
    *out_error = "no signed response";
    return false;
  }

  const uint8_t* response_signature;
  if (!response.GetFixedLen(&response_signature, kTagSIG,
                            ED25519_SIGNATURE_LEN)) {
    *out_error = "no signature in response";
    return false;
  }

  signed_message =
      std::string(kContextString, sizeof(kContextString)) +
      std::string(reinterpret_cast<const char*>(signed_response_bytes),
                  signed_response_len);

  if (!ED25519_verify(reinterpret_cast<const uint8_t*>(signed_message.data()),
                      signed_message.size(), response_signature,
                      delegated_public_key)) {
    *out_error = "bad signature in response";
    return false;
  }

  Parser signed_response(signed_response_bytes, signed_response_len);
  if (!signed_response.is_valid()) {
    *out_error = "invalid signed response in response";
    return false;
  }

  const uint8_t* root;
  rough_time_t timestamp;
  uint32_t radius;
  if (!signed_response.GetFixedLen(&root, kTagROOT, kNonceLength) ||
      !signed_response.Get(&timestamp, kTagMIDP) ||
      !signed_response.Get(&radius, kTagRADI)) {
    *out_error = "signed response missing required values";
    return false;
  }

  if (timestamp < min_time || max_time < timestamp) {
    *out_error = "timestamp out of range for delegation";
    return false;
  }

  const uint8_t* path;
  size_t path_len;
  uint32_t tree_index;
  if (!response.Get(&tree_index, kTagINDX) ||
      !response.GetTag(&path, &path_len, kTagPATH)) {
    *out_error = "response missing required values";
    return false;
  }

  uint8_t hash[kNonceLength];
  HashLeaf(hash, nonce);

  if (path_len % kNonceLength != 0) {
    *out_error = "tree path is not a multiple of the hash size";
    return false;
  }

  for (size_t i = 0; i < path_len; i += kNonceLength) {
    const bool path_element_is_right = tree_index & 1;
    if (path_element_is_right) {
      HashNode(hash, hash, path + i);
    } else {
      HashNode(hash, path + i, hash);
    }
    tree_index /= 2;
  }

  if (memcmp(root, hash, kNonceLength) != 0) {
    *out_error = "calculated tree root doesn't match signed root";
    return false;
  }

  *out_time = timestamp;
  *out_radius = radius;

  return true;
}

}  // namespace roughtime
