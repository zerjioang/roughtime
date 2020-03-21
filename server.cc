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

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/curve25519.h>

#include "logging.h"
#include "protocol.h"
#include "server.h"

namespace roughtime {

static_assert(kMaxRecvPacketSize % 4 == 0,
              "kMaxRecvPacketSize must be a multiple of four");
static_assert(kBatchSize != 0 && (kBatchSize & (kBatchSize - 1)) == 0,
              "kBatchSize must be a power of two");
static_assert(1u << kBatchSizeLog2 == kBatchSize,
              "kBatchSizeLog2 is incorrect");
static_assert(kMinRequestSize <= kMaxRecvPacketSize,
              "Miniumum request size must be <= to the maximum packet size");

static_assert(kMaxResponseSize <= kMinRequestSize,
              "This design could be a DDoS amplifier");

static_assert(ED25519_SIGNATURE_LEN == 64, "crypto constant mismatch");
static_assert(ED25519_PUBLIC_KEY_LEN == 32, "crypto constant mismatch");
static_assert(ED25519_PRIVATE_KEY_LEN == 64, "crypto constant mismatch");

Server::Server(std::unique_ptr<Identity> identity,
               std::unique_ptr<TimeSource> time_source)
    : time_source_(std::move(time_source)),
      identity_(std::move(identity)),
      num_leaves_(0),
      to_be_signed_(to_be_signed_with_context_ + sizeof(kContextString)) {
  memcpy(to_be_signed_with_context_, kContextString, sizeof(kContextString));
}

bool Server::AddRequest(const uint8_t *packet, size_t len) {
  ROUGHTIME_DCHECK_LE(num_leaves_, kBatchSize);

  if (len < kMinRequestSize) {
    return false;
  }

  Parser request(packet, len);
  if (!request.is_valid()) {
    return false;
  }

  const uint8_t *nonce;
  if (!request.GetFixedLen(&nonce, kTagNONC, kNonceLength)) {
    return false;
  }

  // kTagPAD lives here too, but we don't bother to check for it.  The check
  // above against |kMinRequestSize| is sufficient.
  tree_.AddLeaf(num_leaves_++, nonce);

  return true;
}

bool Server::Sign() {
  ROUGHTIME_DCHECK_GT(num_leaves_, 0ul);

  // The signature is over the root hash and the timestamp---that's it!
  tree_.Build(num_leaves_);
  const auto interval = time_source_->Now();
  const rough_time_t now = interval.first;
  const uint32_t radius = interval.second;

  Builder to_be_signed(to_be_signed_, kToBeSignedSize, 3);
  size_t to_be_signed_len;

  static_assert(kTagRADI < kTagMIDP, "Tags must be written in order");
  static_assert(kTagMIDP < kTagROOT, "Tags must be written in order");
  if (!to_be_signed.AddTagData(kTagRADI,
                               reinterpret_cast<const uint8_t *>(&radius),
                               sizeof(radius)) ||
      !to_be_signed.AddTagData(
          kTagMIDP, reinterpret_cast<const uint8_t *>(&now), sizeof(now)) ||
      !to_be_signed.AddTagData(kTagROOT, tree_.GetRoot(), kNonceLength) ||
      !to_be_signed.Finish(&to_be_signed_len)) {
    ROUGHTIME_LOG(ERROR) << "failed to construct to_be_signed";
    return false;
  }
  ROUGHTIME_CHECK_EQ(to_be_signed_len, kToBeSignedSize);

  if (!ED25519_sign(signature_, to_be_signed_with_context_,
                    sizeof(to_be_signed_with_context_),
                    identity_->private_key)) {
    ROUGHTIME_LOG(ERROR) << "signature failure";
    return false;
  }
  return true;
}

bool Server::MakeResponse(uint8_t *out_response, size_t *out_len,
                          uint32_t index) {
  ROUGHTIME_DCHECK_LT(index, num_leaves_);
  static_assert(kMaxResponseSize <= kMaxRecvPacketSize,
                "Receive buffers are too small to use as send buffers");
  Builder response(out_response, kMaxResponseSize, 5);
  static_assert(kTagSIG < kTagPATH, "Tags must be written in order");
  static_assert(kTagPATH < kTagSREP, "Tags must be written in order");
  static_assert(kTagSREP < kTagCERT, "Tags must be written in order");
  static_assert(kTagCERT < kTagINDX, "Tags must be written in order");

  uint8_t *path;
  uint8_t *pindex = reinterpret_cast<uint8_t *>(&index);
  if (!response.AddTagData(kTagSIG, signature_, sizeof(signature_)) ||
      !response.AddTag(&path, kTagPATH, kNonceLength * tree_.GetPathLength()) ||
      !response.AddTagData(kTagSREP, to_be_signed_, kToBeSignedSize) ||
      !response.AddTagData(kTagCERT, identity_->certificate, kCertSize) ||
      !response.AddTagData(kTagINDX, pindex, sizeof(index)) ||
      !response.Finish(out_len)) {
    ROUGHTIME_LOG(ERROR) << "failed to construct response";
    return false;
  }

  tree_.GetPath(path, index);
  return true;
}

// static
bool CreateCertificate(uint8_t out_cert[kCertSize],
                       const uint8_t root_private_key[ED25519_PRIVATE_KEY_LEN],
                       rough_time_t start_time, rough_time_t end_time,
                       const uint8_t public_key[ED25519_PUBLIC_KEY_LEN]) {
  ROUGHTIME_CHECK_LT(start_time, end_time);
  uint8_t to_be_signed_bytes[sizeof(kCertContextString) + kToBeSignedCertSize];
  size_t to_be_signed_len;
  memcpy(to_be_signed_bytes, kCertContextString, sizeof(kCertContextString));

  Builder to_be_signed(to_be_signed_bytes + sizeof(kCertContextString),
                       kToBeSignedCertSize, 3);
  static_assert(kTagPUBK < kTagMINT, "Tags must be written in order");
  static_assert(kTagMINT < kTagMAXT, "Tags must be written in order");
  if (!to_be_signed.AddTagData(kTagPUBK, public_key, ED25519_PUBLIC_KEY_LEN) ||
      !to_be_signed.AddTagData(kTagMINT,
                               reinterpret_cast<uint8_t *>(&start_time),
                               sizeof(start_time)) ||
      !to_be_signed.AddTagData(kTagMAXT, reinterpret_cast<uint8_t *>(&end_time),
                               sizeof(end_time)) ||
      !to_be_signed.Finish(&to_be_signed_len)) {
    ROUGHTIME_LOG(ERROR) << "failed to construct signed portion of certificate";
    return false;
  }
  ROUGHTIME_CHECK_EQ(to_be_signed_len, kToBeSignedCertSize);

  uint8_t signature[ED25519_SIGNATURE_LEN];
  if (!ED25519_sign(signature, to_be_signed_bytes, sizeof(to_be_signed_bytes),
                    root_private_key)) {
    ROUGHTIME_LOG(ERROR) << "failed to sign certificate";
    return false;
  }

  size_t cert_len;
  Builder cert(out_cert, kCertSize, 2);

  static_assert(kTagSIG < kTagDELE, "Tags must be written in order");
  if (!cert.AddTagData(kTagSIG, signature, sizeof(signature)) ||
      !cert.AddTagData(kTagDELE,
                       to_be_signed_bytes + sizeof(kCertContextString),
                       to_be_signed_len) ||
      !cert.Finish(&cert_len)) {
    ROUGHTIME_LOG(ERROR) << "failed to construct certificate";
    return false;
  }
  ROUGHTIME_CHECK_EQ(cert_len, kCertSize);
  return true;
}

void Tree::Build(size_t num_nodes) {
  ROUGHTIME_DCHECK_GT(num_nodes, 0ul);
  size_t level;
  for (level = 0; num_nodes > 1; level++, num_nodes /= 2) {
    // Even out the level with a dummy node, if need be. Use an existing node
    // in |tree_|, to simplify analysis that we are not inadvertently signing
    // other messages.
    if (num_nodes % 2 == 1) {
      memcpy(tree_[level][num_nodes], tree_[level][0], kNonceLength);
      num_nodes++;
    }
    for (size_t i = 0; i < num_nodes; i += 2) {
      HashNode(tree_[level + 1][i / 2], tree_[level][i], tree_[level][i + 1]);
    }
  }
  ROUGHTIME_DCHECK_EQ(1ul, num_nodes);  // Root node.
  levels_ = level + 1;
}

void Tree::GetPath(uint8_t *out_path, size_t index) {
  // At the lowest level, the client knows its own leaf hash, so send it only
  // that leaf's sibling, and so on up the tree.
  for (size_t level = 0; level < levels_ - 1; level++) {
    if (index % 2 == 1) {
      memcpy(out_path, tree_[level][index - 1], kNonceLength);
    } else {
      memcpy(out_path, tree_[level][index + 1], kNonceLength);
    }
    out_path += kNonceLength;
    index /= 2;
  }
  ROUGHTIME_DCHECK_EQ(0ul, index);
}

BrokenReplyGenerator::~BrokenReplyGenerator() {}

uint16_t BrokenReplyGenerator::probability_1024() const {
  return probability_1024_;
}

void BrokenReplyGenerator::set_probability_1024(uint16_t probability) {
  probability_1024_ = probability;
}

}  // namespace roughtime
