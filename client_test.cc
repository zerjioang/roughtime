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

#include "gtest/gtest.h"
#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include "client.h"
#include "open_source_fillins.h"

namespace roughtime {

TEST(CreateRequest, RequestIsValid) {
  uint8_t nonce[kNonceLength];
  memset(nonce, 'a', kNonceLength);

  std::string request = CreateRequest(nonce);
  EXPECT_EQ(kMinRequestSize, request.size());
  Parser parser(reinterpret_cast<const uint8_t*>(request.data()),
                request.size());
  ASSERT_TRUE(parser.is_valid());

  const uint8_t* request_nonce;
  EXPECT_TRUE(parser.GetFixedLen(&request_nonce, kTagNONC, kNonceLength));
  EXPECT_EQ(0, memcmp(nonce, request_nonce, kNonceLength));

  const uint8_t* pad;
  size_t pad_len;
  EXPECT_TRUE(parser.GetTag(&pad, &pad_len, kTagPAD));
  EXPECT_GE(pad_len, 0);
}

struct ResponseBuilder {
  uint8_t nonce[kNonceLength];  // Client's nonce.

  // Delegation.
  uint8_t delegated_private_key[ED25519_PRIVATE_KEY_LEN];
  uint8_t delegated_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t delegation[kMinRequestSize];
  size_t delegation_len;

  // Certificate (incorporates the delegation).
  uint8_t root_private_key[ED25519_PRIVATE_KEY_LEN];
  uint8_t root_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t public_key_signature[ED25519_SIGNATURE_LEN];
  uint8_t cert[kMinRequestSize];
  size_t cert_len;

  // The signed portion of the response (tree root and timestamp), signed by the
  // delegated key.
  uint8_t tree_root[kNonceLength];
  uint8_t signed_response[kMinRequestSize];
  size_t signed_response_len;

  // The final response, consisting of the signed portion, signature, Merkle
  // tree path, and certificate.
  uint32_t tree_index;
  uint8_t tree_path[32 * kNonceLength];
  size_t tree_path_len;
  uint8_t response[kMinRequestSize];
  uint8_t response_signature[ED25519_SIGNATURE_LEN];
  size_t response_len;

  std::string out_error;
  rough_time_t out_time;
  uint32_t out_radius;

  // Call the below functions in order to create a response.
  ResponseBuilder();
  void MakeDelegation(rough_time_t mint, rough_time_t maxt);
  void MakeDelegation() { MakeDelegation(999, 1001); }
  void MakeCertificate(const uint8_t* private_key);
  void MakeCertificate() { MakeCertificate(root_private_key); }
  void MakeTree(uint32_t index);
  void MakeTree() { MakeTree(0); }
  void MakeSigned(rough_time_t now);
  void MakeSigned() { MakeSigned(1000); }
  void MakeResponse(const uint8_t* private_key);
  void MakeResponse() { MakeResponse(delegated_private_key); }
  bool ParseResponse(uint8_t nonce[kNonceLength]);
  bool ParseResponse() { return ParseResponse(nonce); }
};

ResponseBuilder::ResponseBuilder() {
  memset(nonce, 'a', kNonceLength);
  ED25519_keypair(delegated_public_key, delegated_private_key);
  ED25519_keypair(root_public_key, root_private_key);
}

void ResponseBuilder::MakeDelegation(rough_time_t mint, rough_time_t maxt) {
  Builder builder(delegation, arraysize(delegation), 3);
  ASSERT_TRUE(builder.AddTagData(kTagPUBK, delegated_public_key,
                                 arraysize(delegated_public_key)));
  ASSERT_TRUE(builder.AddTagData(
      kTagMINT, reinterpret_cast<const uint8_t*>(&mint), sizeof(mint)));
  ASSERT_TRUE(builder.AddTagData(
      kTagMAXT, reinterpret_cast<const uint8_t*>(&maxt), sizeof(maxt)));
  ASSERT_TRUE(builder.Finish(&delegation_len));
}

void ResponseBuilder::MakeCertificate(const uint8_t* private_key) {
  size_t context_len = arraysize(kCertContextString);
  uint8_t to_sign[kMinRequestSize];
  ASSERT_LE(delegation_len + context_len, sizeof(to_sign));
  memcpy(to_sign, kCertContextString, context_len);
  memcpy(to_sign + context_len, delegation, delegation_len);
  ASSERT_TRUE(ED25519_sign(public_key_signature, to_sign,
                           context_len + delegation_len, private_key));
  Builder builder(cert, arraysize(cert), 2);
  ASSERT_TRUE(builder.AddTagData(kTagSIG, public_key_signature,
                                 arraysize(public_key_signature)));
  ASSERT_TRUE(builder.AddTagData(kTagDELE, delegation, delegation_len));
  ASSERT_TRUE(builder.Finish(&cert_len));
}

void ResponseBuilder::MakeTree(uint32_t i) {
  tree_index = i;
  HashLeaf(tree_root, nonce);
  for (tree_path_len = 0; i > 0; i >>= 1) {
    const bool path_element_is_right = i & 1;
    uint8_t* sibling = tree_path + tree_path_len;
    RAND_bytes(sibling, kNonceLength);
    if (path_element_is_right) {
      HashNode(tree_root, tree_root, sibling);
    } else {
      HashNode(tree_root, sibling, tree_root);
    }
    tree_path_len += kNonceLength;
  }
}

void ResponseBuilder::MakeSigned(rough_time_t now) {
  Builder builder(signed_response, arraysize(signed_response), 3);
  static const uint32_t kRadius = 1000000;
  builder.AddTagData(kTagRADI, reinterpret_cast<const uint8_t*>(&kRadius),
                     sizeof(kRadius));
  builder.AddTagData(kTagMIDP, reinterpret_cast<const uint8_t*>(&now),
                     sizeof(now));
  builder.AddTagData(kTagROOT, tree_root, arraysize(tree_root));
  builder.Finish(&signed_response_len);
}

void ResponseBuilder::MakeResponse(const uint8_t* private_key) {
  size_t context_len = arraysize(kContextString);
  uint8_t to_sign[kMinRequestSize];
  ASSERT_LE(signed_response_len + context_len, sizeof(to_sign));
  memcpy(to_sign, kContextString, context_len);
  memcpy(to_sign + context_len, signed_response, signed_response_len);
  ASSERT_TRUE(ED25519_sign(response_signature, to_sign,
                           context_len + signed_response_len, private_key));
  Builder builder(response, arraysize(response), 5);
  ASSERT_TRUE(builder.AddTagData(kTagSIG, response_signature,
                                 arraysize(response_signature)));
  ASSERT_TRUE(builder.AddTagData(kTagPATH, tree_path, tree_path_len));
  ASSERT_TRUE(
      builder.AddTagData(kTagSREP, signed_response, signed_response_len));
  ASSERT_TRUE(builder.AddTagData(kTagCERT, cert, cert_len));
  ASSERT_TRUE(builder.AddTagData(kTagINDX,
                                 reinterpret_cast<const uint8_t*>(&tree_index),
                                 sizeof(tree_index)));
  ASSERT_TRUE(builder.Finish(&response_len));
}

bool ResponseBuilder::ParseResponse(uint8_t nonce[kNonceLength]) {
  return ::roughtime::ParseResponse(&out_time, &out_radius, &out_error,
                                    root_public_key, response, response_len,
                                    nonce);
}

TEST(ParseResponse, ValidResponse) {
  ResponseBuilder builder;
  builder.MakeDelegation();
  builder.MakeCertificate();
  builder.MakeTree();
  builder.MakeSigned();
  builder.MakeResponse();
  EXPECT_TRUE(builder.ParseResponse()) << builder.out_error;
  EXPECT_EQ(1000, builder.out_time);
}

TEST(ParseResponse, BadTreeRoot) {
  ResponseBuilder builder;
  builder.MakeDelegation();
  builder.MakeCertificate();
  builder.MakeTree();
  memset(builder.tree_root, 0, kNonceLength);
  builder.MakeSigned();
  builder.MakeResponse();
  EXPECT_FALSE(builder.ParseResponse());
}

TEST(ParseResponse, TestAllTreeIndices) {
  for (uint32_t i = 0; i <= 32; i++) {
    ResponseBuilder builder;
    builder.MakeDelegation();
    builder.MakeCertificate();
    builder.MakeTree(i);
    builder.MakeSigned();
    builder.MakeResponse();
    EXPECT_TRUE(builder.ParseResponse()) << "failed at index " << i;
    EXPECT_EQ(1000, builder.out_time);
  }
}

TEST(ParseResponse, WrongKeyUsedToSignResponse) {
  ResponseBuilder builder;
  builder.MakeDelegation();
  builder.MakeCertificate();
  builder.MakeTree();
  builder.MakeSigned();
  uint8_t garbage[ED25519_PRIVATE_KEY_LEN];
  memset(garbage, 0, arraysize(garbage));
  builder.MakeResponse(garbage);
  EXPECT_FALSE(builder.ParseResponse());
}

TEST(ParseResponse, WrongKeyUsedToSignCert) {
  ResponseBuilder builder;
  builder.MakeDelegation();
  uint8_t garbage[ED25519_PRIVATE_KEY_LEN];
  memset(garbage, 0, arraysize(garbage));
  builder.MakeCertificate(garbage);
  builder.MakeTree();
  builder.MakeSigned();
  builder.MakeResponse();
  EXPECT_FALSE(builder.ParseResponse());
}

TEST(ParseResponse, InvalidDelegationTimes) {
  ResponseBuilder builder;
  builder.MakeDelegation(1001, 999);  // Order reversed.
  builder.MakeCertificate();
  builder.MakeTree();
  builder.MakeSigned();
  builder.MakeResponse();
  EXPECT_FALSE(builder.ParseResponse());
}

TEST(ParseResponse, TimeOutsideDelegation) {
  ResponseBuilder builder;
  builder.MakeDelegation();
  builder.MakeCertificate();
  builder.MakeTree();
  builder.MakeSigned(1002);  // Outside bounds.
  builder.MakeResponse();
  EXPECT_FALSE(builder.ParseResponse());
}

TEST(ParseResponse, NonceNotInTree) {
  ResponseBuilder builder;
  builder.MakeDelegation();
  builder.MakeCertificate();
  builder.MakeTree();
  builder.MakeSigned();
  builder.MakeResponse();
  uint8_t nonce[kNonceLength];
  memset(nonce, 'b', arraysize(nonce));
  EXPECT_FALSE(builder.ParseResponse(nonce));  // Not the nonce in the request.
}

}  // namespace roughtime
