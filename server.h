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

#ifndef SECURITY_ROUGHTIME_SERVER_H_
#define SECURITY_ROUGHTIME_SERVER_H_

#include <memory>
#include <utility>

#include "protocol.h"
#include "time_source.h"

namespace roughtime {

// kToBeSignedCertSize is the size of the signed portion (DELE) of a
// certificate.  Its tags are (PUBK, MINT, MAXT).
constexpr size_t kToBeSignedCertSize = MessageHeaderLen(3) +
                                       kPublicKeyLength + kTimestampSize +
                                       kTimestampSize;

// kCertSize is the size of the entire certificate.  Its tags are (DELE, SIG).
constexpr size_t kCertSize =
    MessageHeaderLen(2) + kSignatureLength + kToBeSignedCertSize;

// CreateCertificate signs the supplied |public_key| using |root_private_key|,
// and sets |out_cert| to a certificate containing the public key, the
// signature, and the supplied validity interval.  Returns true if successful,
// otherwise false.
// TODO(mab): Find better home for this, likely in an offline tool.
bool CreateCertificate(uint8_t out_cert[kCertSize],
                       const uint8_t root_private_key[kPrivateKeyLength],
                       rough_time_t start_time, rough_time_t end_time,
                       const uint8_t public_key[kPublicKeyLength]);

// Identity is a server's private key and certificate.  (The certificate is the
// server's public key signed by an offline private master key.)
struct Identity {
  uint8_t private_key[kPrivateKeyLength];
  uint8_t certificate[kCertSize];
};

// kBatchSizeLog2 is one less than the number of levels in the Merkle tree of
// client nonces.  The response packet must have room for this many hashes.
// This value was taken because it's too easy to saturate batches of size 32 in
// load testing so 64 seems like a reasonable number for now. We may revisit
// this if the non-crypto parts of processing become less expensive.
constexpr size_t kBatchSizeLog2 = 6;

// kBatchSize is the most requests we'll process at a time, a.k.a. the number of
// leaves in the Merkle tree.
constexpr size_t kBatchSize = 1 << kBatchSizeLog2;

// Tree encapsulates the Merkle tree of client nonces.  The tree is too large
// (2**13 bytes) to be sent to each client, so each client is sent the part of
// the tree necessary to verify the inclusion of its nonce.
class Tree {
 public:
  Tree() {}
  Tree(const Tree&) = delete;
  Tree& operator=(const Tree&) = delete;

  // AddLeaf adds a new client nonce at the specified index.
  void AddLeaf(size_t index, const uint8_t nonce[kNonceLength]) {
    HashLeaf(tree_[0][index], nonce);
  }

  // Build constructs the Merkle tree.  The existing |num_leaves| leaf hashes in
  // levels_[0] are left alone, and the tree is built by (possibly adding a
  // dummy leaf node and) creating levels 1 and higher.
  //
  // If |num_leaves| is 1, this is a no-op.  In that case, the root is the same
  // node as the one leaf.
  void Build(size_t num_leaves);

  // GetPathLength returns the number of nodes necessary to represent a path to
  // the root.  This may be zero.
  size_t GetPathLength() { return levels_ - 1; }

  // GetPath sets |*out_path| to the data needed to verify inclusion in the root
  // hash of the leaf at |index|.  The path consists of one node for each
  // sub-root level.  So, for example, the first element is the leaf that is the
  // sibling of the leaf at |index|.
  //
  // The data are intended for consumption by a client that knows the leaf at
  // |index|, because it is that client's nonce.
  void GetPath(uint8_t* out_path, size_t index);

  // GetRoot returns a pointer to the root hash, which is |kNonceLength| bytes
  // long.
  const uint8_t* GetRoot() { return tree_[levels_ - 1][0]; }

 private:
  // tree_ is a Merkle tree.  The first index is the level of the tree, with
  // leaves at level 0.
  uint8_t tree_[kBatchSizeLog2 + 1][kBatchSize][kNonceLength];

  // Level is the number of levels in the tree, including the root.  Hence,
  // after calling |Build|, the root lives at |tree_[levels_-1][0]|.
  size_t levels_;
};

constexpr size_t kMaxRecvPacketSize = kMinRequestSize;

constexpr size_t kToBeSignedSize =
    MessageHeaderLen(3) + kTimestampSize + kRadiusSize + kNonceLength;

// kMaxResponseSize is the size of the largest possible server response.
constexpr size_t kMaxResponseSize =
    MessageHeaderLen(5) + kCertSize + kToBeSignedSize + kSignatureLength +
    (kBatchSizeLog2 * kNonceLength) + sizeof(uint32_t) /* index */;

class Server {
 public:
  Server() = delete;
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  Server(std::unique_ptr<Identity> identity,
         std::unique_ptr<TimeSource> time_source);

  // AddRequest decodes |packet|.  If the packet is valid, it is added to
  // |tree_| and true is returned.  Otherwise, false is returned.
  bool AddRequest(const uint8_t* packet, size_t len);

  // Sign creates a signed response (Merkle tree root and timestamp) and a
  // signature.
  bool Sign();

  // MakeResponse creates a response for the |index|'th leaf node of the Merkle
  // tree, where the indices correspond to successful calls to |AddRequest|.
  bool MakeResponse(uint8_t* out_response, size_t* out_len, uint32_t index);

  void Reset() { num_leaves_ = 0; }

 private:
  std::unique_ptr<TimeSource> time_source_;

  std::unique_ptr<Identity> identity_;

  Tree tree_;
  // num_leaves is the number of leaf nodes inserted
  size_t num_leaves_;

  // to_be_signed_with_context_ is the signed portion of the server's response,
  // prefixed by |kContextString|.
  uint8_t to_be_signed_with_context_[kToBeSignedSize + sizeof(kContextString)];

  // to_be_signed_ points |sizeof(kContextStringBytes)| into
  // |to_be_signed_with_context_|, for convenience.  It contains tags (ROOT,
  // TIME).
  uint8_t* const to_be_signed_;

  // Signature is the ED25519 signature over |to_be_signed_with_context_|.
  uint8_t signature_[kSignatureLength];
};

// BrokenReplyGenerator is an interface for generating replies that are broken
// in a variety of ways. This is used to ensure that clients correctly handle
// various corner cases.
class BrokenReplyGenerator {
 public:
  virtual ~BrokenReplyGenerator();

  // probability_1024 returns the probability, in parts-per-1024, that this
  // generator should be used for a given request.
  uint16_t probability_1024() const;
  void set_probability_1024(uint16_t probabilty);

  // Process takes a valid request in |request| and the standard response in
  // |normal_response|. If it wishes to substitute an alternative reply then it
  // may write up to |max_out_len| bytes to |out|, set |*out_len| to the number
  // of bytes written and return true. Otherwise it must return false.
  virtual bool Process(uint8_t* out, size_t* out_len, size_t max_out_len,
                       const uint8_t* normal_response,
                       size_t normal_response_len, const uint8_t* request,
                       size_t request_len) = 0;

 protected:
  uint16_t probability_1024_ = 0;
};

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_SERVER_H_
