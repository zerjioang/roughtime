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

#include "protocol.h"

#if defined(__APPLE__)
#include <machine/endian.h>
#else
#include <endian.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <openssl/sha.h>
#include <openssl/curve25519.h>

#include "logging.h"

namespace roughtime {

static_assert(BYTE_ORDER == LITTLE_ENDIAN,
              "This code assumes little-endian processors");

// The OpenSSL constants are kept out of the headers to allow consumers to
// avoid needing OpenSSL's at build time, but the values should still match.
static_assert(kPrivateKeyLength == ED25519_PRIVATE_KEY_LEN,
              "Private key length mismatch");
static_assert(kPublicKeyLength == ED25519_PUBLIC_KEY_LEN,
              "Public key length mismatch");
static_assert(kSignatureLength == ED25519_SIGNATURE_LEN,
              "Signature length mismatch");

static void advance(const uint8_t **ptr, size_t *len, size_t bytes) {
  *ptr += bytes;
  *len -= bytes;
}

Parser::Parser(const uint8_t *req, size_t len) {
  if (len < sizeof(uint32_t)) {
    return;
  }

  // Read number of tags.
  uint32_t num_tags_32;
  memcpy(&num_tags_32, req, sizeof(uint32_t));
  num_tags_ = num_tags_32;
  advance(&req, &len, sizeof(uint32_t));

  if (0xffff < num_tags_) {  // Avoids any subsequent overflows.
    return;
  }

  // Validate table of offsets.
  const size_t num_offsets = NumMessageOffsets(num_tags_);
  if (len < num_offsets * sizeof(uint32_t)) {
    return;
  }
  offsets_ = req;
  advance(&req, &len, num_offsets * sizeof(uint32_t));

  uint32_t previous_offset = 0;
  for (size_t i = 0; i < num_offsets; i++) {
    // A tag may have no data.  Hence, subsequent offsets may be equal.
    uint32_t offset;
    memcpy(&offset, offsets_ + sizeof(uint32_t)*i, sizeof(uint32_t));

    if (offset < previous_offset ||
        offset % 4 != 0) {
      return;
    }
    previous_offset = offset;
  }
  uint32_t last_offset = previous_offset;

  // Validate list of tags.  Tags must be in increasing order.
  if (len < num_tags_ * sizeof(tag_t)) {
    return;
  }
  tags_ = req;
  advance(&req, &len, num_tags_ * sizeof(tag_t));

  tag_t previous_tag = 0;
  for (size_t i = 0; i < num_tags_; i++) {
    tag_t tag;
    memcpy(&tag, tags_ + sizeof(tag_t) * i, sizeof(tag_t));
    if (i > 0 && tag <= previous_tag) {
      return;
    }
    previous_tag = tag;
  }

  // Make sure the offset table doesn't point past the end of the data.
  if (len < last_offset) {
    return;
  }

  data_ = req;
  len_ = len;
  is_valid_ = true;
}

static int tag_cmp(const void *keyp, const void *memberp) {
  tag_t key, member;
  memcpy(&key, keyp, sizeof(tag_t));
  memcpy(&member, memberp, sizeof(uint32_t));

  if (key == member) {
    return 0;
  }
  return key < member ? -1 : 1;
}

bool Parser::GetTag(const uint8_t **out_data, size_t *out_len,
                    tag_t tag) const {
  uint8_t *tagp = reinterpret_cast<uint8_t *>(
      bsearch(&tag, tags_, num_tags_, sizeof(tag_t), tag_cmp));
  if (tagp == nullptr) {
    return false;
  }
  size_t tag_number = (tagp - tags_) / sizeof(uint32_t);

  uint32_t offset = 0;
  if (tag_number != 0) {
    memcpy(&offset, offsets_ + sizeof(uint32_t) * (tag_number - 1),
           sizeof(uint32_t));
  }

  *out_data = data_ + offset;
  if (tag_number == num_tags_ - 1) {
    *out_len = len_ - offset;
  } else {
    uint32_t next_offset;
    memcpy(&next_offset, offsets_ + sizeof(uint32_t) * tag_number,
           sizeof(uint32_t));
    *out_len = next_offset - offset;
  }
  return true;
}

bool Parser::GetFixedLen(const uint8_t **out_data, tag_t tag,
                         size_t expected_len) const {
  size_t len;
  return GetTag(out_data, &len, tag) && len == expected_len;
}

template <typename T>
bool Parser::Get(T *out_value, tag_t tag) const {
  const uint8_t *data;
  size_t len;
  if (!GetTag(&data, &len, tag) ||
      len != sizeof(T)) {
    return false;
  }
  *out_value = *reinterpret_cast<const T *>(data);
  return true;
}

template bool Parser::Get(uint32_t *, tag_t) const;
template bool Parser::Get(uint64_t *, tag_t) const;

Builder::Builder(uint8_t *out, size_t out_len, size_t num_tags)
    : num_tags_(num_tags),
      header_len_(MessageHeaderLen(num_tags)),
      offsets_(out + sizeof(uint32_t)),
      tags_(out + sizeof(uint32_t) * (1 + NumMessageOffsets(num_tags))) {
  if (out_len < sizeof(uint32_t) ||
      out_len < header_len_ ||
      0xffff < num_tags) {
    return;
  }

  const uint32_t num_tags_32 = num_tags;
  memcpy(out, &num_tags_32, sizeof(uint32_t));

  data_ = out + header_len_;
  len_ = out_len - header_len_;
  valid_ = true;
}

bool Builder::AddTag(uint8_t **out_data, tag_t tag, size_t len) {
  if (!valid_ ||
      len%4 != 0 ||
      len_ < len ||
      tag_i_ >= num_tags_ ||
      (have_previous_tag_ && tag <= previous_tag_)) {
    return false;
  }

  memcpy(tags_ + sizeof(uint32_t)*tag_i_, &tag, sizeof(tag_t));
  if (tag_i_ > 0) {
    const uint32_t offset_32 = offset_;
    memcpy(offsets_ + sizeof(uint32_t) * (tag_i_ - 1), &offset_32,
           sizeof(uint32_t));
  }
  tag_i_++;
  previous_tag_ = tag;
  have_previous_tag_ = true;

  *out_data = data_;

  offset_ += len;
  len_ -= len;
  data_ += len;

  return true;
}

bool Builder::AddTagData(tag_t tag, const uint8_t *data, size_t len) {
  uint8_t *out;
  if (!AddTag(&out, tag, len)) {
    return false;
  }
  memcpy(out, data, len);
  return true;
}

bool Builder::Finish(size_t *out_len) {
  if (!valid_ || tag_i_ != num_tags_) {
    return false;
  }
  *out_len = header_len_ + offset_;
  valid_ = false;
  return true;
}

constexpr uint8_t kHashLeafTweak[] = {0x00};
constexpr uint8_t kHashNodeTweak[] = {0x01};

void HashLeaf(uint8_t *out, const uint8_t *in) {
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, kHashLeafTweak, 1);
  SHA512_Update(&ctx, in, kNonceLength);
  SHA512_Final(out, &ctx);
}

void HashNode(uint8_t *out, const uint8_t *left, const uint8_t *right) {
  SHA512_CTX ctx;
  SHA512_Init(&ctx);
  SHA512_Update(&ctx, kHashNodeTweak, 1);
  SHA512_Update(&ctx, left, SHA512_DIGEST_LENGTH);
  SHA512_Update(&ctx, right, SHA512_DIGEST_LENGTH);
  SHA512_Final(out, &ctx);
}

}  // namespace roughtime
