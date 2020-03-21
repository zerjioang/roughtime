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

#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "gtest/gtest.h"
#include <openssl/curve25519.h>
#include <openssl/rand.h>

#include "open_source_fillins.h"
#include "server.h"

namespace roughtime {

TEST(CreateCertificate, Create) {
  uint8_t delegated_private_key[ED25519_PRIVATE_KEY_LEN];  // Not used.
  uint8_t delegated_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t root_private_key[ED25519_PRIVATE_KEY_LEN];
  uint8_t root_public_key[ED25519_PUBLIC_KEY_LEN];
  ED25519_keypair(delegated_public_key, delegated_private_key);
  ED25519_keypair(root_public_key, root_private_key);

  uint8_t cert[kCertSize];
  EXPECT_TRUE(
      CreateCertificate(cert, root_private_key, 0, 1, delegated_public_key));
  Parser cert_parser(cert, sizeof(cert));
  const uint8_t* delegation;
  const uint8_t* signature;
  EXPECT_TRUE(
      cert_parser.GetFixedLen(&delegation, kTagDELE, kToBeSignedCertSize));
  EXPECT_TRUE(
      cert_parser.GetFixedLen(&signature, kTagSIG, ED25519_SIGNATURE_LEN));

  Parser delegation_parser(delegation, kToBeSignedCertSize);
  uint64_t mint, maxt;
  const uint8_t* pubk;
  EXPECT_TRUE(delegation_parser.Get(&mint, kTagMINT));
  EXPECT_TRUE(delegation_parser.Get(&maxt, kTagMAXT));
  EXPECT_TRUE(
      delegation_parser.GetFixedLen(&pubk, kTagPUBK, ED25519_PUBLIC_KEY_LEN));
  EXPECT_EQ(0, mint);
  EXPECT_EQ(1, maxt);
  EXPECT_EQ(0,
            memcmp(pubk, delegated_public_key, sizeof(delegated_public_key)));

  uint8_t verify[sizeof(kCertContextString) + kToBeSignedCertSize];
  memcpy(verify, kCertContextString, sizeof(kCertContextString));
  memcpy(verify + sizeof(kCertContextString), delegation, kToBeSignedCertSize);
  EXPECT_TRUE(
      ED25519_verify(verify, sizeof(verify), signature, root_public_key));
}

TEST(Tree, OneNode) {
  std::unique_ptr<Tree> tree(new Tree);
  uint8_t nonce[kNonceLength];
  RAND_bytes(nonce, sizeof(nonce));
  tree->AddLeaf(0, nonce);
  tree->Build(1);

  uint8_t hash[kNonceLength];
  HashLeaf(hash, nonce);
  EXPECT_EQ(0, memcmp(hash, tree->GetRoot(), kNonceLength));
  EXPECT_EQ(0, tree->GetPathLength());
}

TEST(Tree, ManyNodes) {
  std::unique_ptr<Tree> tree(new Tree);
  size_t sizes[] = {2, 3, 4, 5, 6, kBatchSize - 1, kBatchSize};
  for (size_t i = 0; i < arraysize(sizes); i++) {
    size_t size = sizes[i];
    uint8_t nonces[kBatchSize][kNonceLength];
    for (size_t j = 0; j < size; ++j) {
      RAND_bytes(nonces[j], sizeof(nonces[j]));
      tree->AddLeaf(j, nonces[j]);
    }
    tree->Build(size);

    // Verify the inclusion of each nonce.
    for (size_t j = 0; j < size; ++j) {
      uint8_t hash[kNonceLength];
      HashLeaf(hash, nonces[j]);

      uint8_t path[kBatchSize][kNonceLength];
      tree->GetPath(reinterpret_cast<uint8_t*>(path), j);
      size_t index = j;
      for (size_t elem = 0; elem < tree->GetPathLength(); elem++) {
        if (index % 2 == 0) {
          HashNode(hash, hash, path[elem]);
        } else {
          HashNode(hash, path[elem], hash);
        }
        index /= 2;
      }
      ASSERT_EQ(0, index);
      EXPECT_EQ(0, memcmp(hash, tree->GetRoot(), kNonceLength));
    }
  }
}

class DummyTimeSource : public TimeSource {
 public:
  ~DummyTimeSource() override {}
  std::pair<uint64_t, uint32_t> Now() override {
    return std::make_pair(1000000000, 0);
  }
};

// MakeServer is a helper function to create a new server.  The server's public
// key is written to |*root_public_key|, but its certificate remains hidden.
static std::unique_ptr<Server> MakeServer(uint8_t* root_public_key) {
  auto identity = std::unique_ptr<Identity>(new Identity());
  uint8_t delegated_private_key[ED25519_PRIVATE_KEY_LEN];  // Not used.
  uint8_t delegated_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t root_private_key[ED25519_PRIVATE_KEY_LEN];
  ED25519_keypair(delegated_public_key, delegated_private_key);
  ED25519_keypair(root_public_key, root_private_key);
  CreateCertificate(identity->certificate, root_private_key, 1000000000,
                    2000000000 /* 2033-05-17 */, delegated_public_key);
  memcpy(identity->private_key, delegated_private_key,
         sizeof(delegated_private_key));
  std::unique_ptr<TimeSource> time_source(new DummyTimeSource);
  Server* server = new Server(std::move(identity), std::move(time_source));
  return std::unique_ptr<Server>(server);
}

// VerifyResponse is a helper function to verify a that the supplied |response|
// is valid and includes the supplied |nonce|.
static void VerifyResponse(const uint8_t* nonce, const uint8_t* response,
                           size_t len) {
  // Parse the top-level response.
  Parser parser(response, len);
  ASSERT_TRUE(parser.is_valid());
  uint8_t to_be_verified_with_context[kToBeSignedSize + sizeof(kContextString)];
  const uint8_t* to_be_verified;
  const uint8_t* signature;
  const uint8_t* cert;
  const uint8_t* path;
  uint32_t index;
  size_t path_len;
  size_t path_elems;
  ASSERT_TRUE(parser.GetFixedLen(&to_be_verified, kTagSREP, kToBeSignedSize));
  ASSERT_TRUE(parser.GetFixedLen(&signature, kTagSIG, ED25519_SIGNATURE_LEN));
  ASSERT_TRUE(parser.GetFixedLen(&cert, kTagCERT, kCertSize));
  ASSERT_TRUE(parser.Get(&index, kTagINDX));
  ASSERT_TRUE(parser.GetTag(&path, &path_len, kTagPATH));

  // Parse the signed portion.
  Parser srep_parser(to_be_verified, kToBeSignedSize);
  ASSERT_TRUE(srep_parser.is_valid());
  const uint8_t* root;
  uint64_t time;
  ASSERT_TRUE(srep_parser.GetFixedLen(&root, kTagROOT, kNonceLength));
  ASSERT_TRUE(srep_parser.Get(&time, kTagMIDP));

  // Parse the certificate.
  Parser cert_parser(cert, kCertSize);
  ASSERT_TRUE(cert_parser.is_valid());
  const uint8_t* delegation;
  ASSERT_TRUE(
      cert_parser.GetFixedLen(&delegation, kTagDELE, kToBeSignedCertSize));

  // Parse the delegation.
  Parser delegation_parser(delegation, kToBeSignedCertSize);
  ASSERT_TRUE(delegation_parser.is_valid());
  const uint8_t* public_key;
  uint64_t maxt, mint;
  ASSERT_TRUE(delegation_parser.GetFixedLen(&public_key, kTagPUBK,
                                            ED25519_PUBLIC_KEY_LEN));
  ASSERT_TRUE(delegation_parser.Get(&mint, kTagMINT));
  ASSERT_TRUE(delegation_parser.Get(&maxt, kTagMAXT));

  // Verify that delegation is valid for the supplied time.
  EXPECT_GE(time, mint);
  EXPECT_LE(time, maxt);

  // Verify the signature.
  memcpy(to_be_verified_with_context, kContextString, sizeof(kContextString));
  memcpy(to_be_verified_with_context + sizeof(kContextString), to_be_verified,
         kToBeSignedSize);
  EXPECT_TRUE(ED25519_verify(to_be_verified_with_context,
                             sizeof(to_be_verified_with_context), signature,
                             public_key));

  // Verify the inclusion of |nonce|.
  ASSERT_EQ(0, path_len % kNonceLength);
  path_elems = path_len / kNonceLength;
  uint8_t hash[kNonceLength];
  HashLeaf(hash, nonce);
  for (size_t i = 0; i < path_elems; i++) {
    if (index % 2 == 1) {
      HashNode(hash, path, hash);
    } else {
      HashNode(hash, hash, path);
    }
    path += kNonceLength;
    index /= 2;
  }
  EXPECT_EQ(0, memcmp(hash, root, kNonceLength));
}

// MakeRequest, a helper function, writes a new client request with the given
// |nonce| to |*request|.
void MakeRequest(uint8_t* request, uint8_t* nonce) {
  Builder builder(request, kMinRequestSize, 2);
  RAND_bytes(nonce, sizeof(nonce));
  ASSERT_TRUE(builder.AddTagData(kTagNONC, nonce, kNonceLength));
  uint8_t* padding;
  ASSERT_TRUE(builder.AddTag(&padding, kTagPAD, kPaddingLen));
  size_t len;
  ASSERT_TRUE(builder.Finish(&len));
  ASSERT_EQ(kMinRequestSize, len);
}

TEST(Server, BadRequest) {
  uint8_t root_public_key[ED25519_PUBLIC_KEY_LEN];
  auto server = MakeServer(root_public_key);
  uint8_t garbage[kMinRequestSize];
  memset(garbage, 'a', sizeof(garbage));
  EXPECT_FALSE(server->AddRequest(garbage, sizeof(garbage)));
}

TEST(Server, GoodRequests) {
  uint8_t root_public_key[ED25519_PUBLIC_KEY_LEN];
  auto server = MakeServer(root_public_key);

  size_t batch_sizes[] = {1, 2, 3, 4, 5, 6, kBatchSize - 1, kBatchSize};
  for (size_t i = 0; i < arraysize(batch_sizes); ++i) {
    std::unique_ptr<uint8_t[]> requests(
        new uint8_t[kBatchSize * kMinRequestSize]);
    std::unique_ptr<uint8_t[]> nonces(new uint8_t[kBatchSize * kNonceLength]);
    memset(nonces.get(), 0, kBatchSize * kNonceLength);
    for (size_t j = 0; j < batch_sizes[i]; ++j) {
      MakeRequest(&requests[j * kMinRequestSize], &nonces[j * kNonceLength]);
      EXPECT_TRUE(
          server->AddRequest(&requests[j * kMinRequestSize], kMinRequestSize));
    }
    EXPECT_TRUE(server->Sign());

    for (size_t j = 0; j < batch_sizes[i]; ++j) {
      uint8_t response[kMaxResponseSize];
      size_t response_len;
      EXPECT_TRUE(server->MakeResponse(response, &response_len, j));
      VerifyResponse(&nonces[j * kNonceLength], response, response_len);
    }
    server->Reset();
  }
}

TEST(Server, MixedGoodAndBadRequests) {
  uint8_t root_public_key[ED25519_PUBLIC_KEY_LEN];
  auto server = MakeServer(root_public_key);

  std::unique_ptr<uint8_t[]> requests(
      new uint8_t[kBatchSize * kMinRequestSize]);
  std::unique_ptr<uint8_t[]> nonces(new uint8_t[kBatchSize * kNonceLength]);
  memset(nonces.get(), 0, kBatchSize * kNonceLength);

  MakeRequest(&requests[0 * kMinRequestSize], &nonces[0 * kNonceLength]);
  MakeRequest(&requests[1 * kMinRequestSize], &nonces[1 * kNonceLength]);
  MakeRequest(&requests[2 * kMinRequestSize], &nonces[2 * kNonceLength]);
  memset(&requests[1 * kMinRequestSize], 'a', kMinRequestSize);

  EXPECT_TRUE(
      server->AddRequest(&requests[0 * kMinRequestSize], kMinRequestSize));
  EXPECT_FALSE(
      server->AddRequest(&requests[1 * kMinRequestSize], kMinRequestSize));
  EXPECT_TRUE(
      server->AddRequest(&requests[2 * kMinRequestSize], kMinRequestSize));
  server->Sign();

  uint8_t response[kMaxResponseSize];
  size_t response_len;

  EXPECT_TRUE(server->MakeResponse(response, &response_len, 0));
  VerifyResponse(&nonces[0 * kNonceLength], response, response_len);
  EXPECT_TRUE(server->MakeResponse(response, &response_len, 1));
  // index #1 -> nonce #2
  VerifyResponse(&nonces[2 * kNonceLength], response, response_len);
}

}  // namespace roughtime
