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

#ifndef SECURITY_ROUGHTIME_PROTOCOL_H_
#define SECURITY_ROUGHTIME_PROTOCOL_H_

#include <stdint.h>
#include <string.h>

namespace roughtime {

// Minimum size of a time request.  Requests must be padded to larger than their
// contents in order to reduce the value of a time server as a DDOS amplifier.
constexpr size_t kMinRequestSize = 1024;

constexpr size_t kNonceLength = 64;  // Size of the client's nonce.

constexpr size_t kTimestampSize = 8;  // Size of the server's time.

constexpr size_t kRadiusSize = 4;  // Size of the server's uncertainty.

constexpr size_t kPrivateKeyLength = 64; // Size of the server's private key.

constexpr size_t kPublicKeyLength = 32; // Size of the server's public key.

constexpr size_t kSignatureLength = 64; // Size of server signatures.

typedef uint32_t tag_t;

// rough_time_t is the type of a time stamp. Time is UTC and is given as
// milliseconds since the UNIX epoch (00:00:00 UTC on 1 January 1970). Leap
// seconds are linearly smeared over a 24-hour period. That is, the smear
// extends from UTC noon to noon over 86,401 or 86,399 SI seconds, and all the
// smeared seconds are the same length.
typedef uint64_t rough_time_t;

// MakeTag creates an integer value representing a tag.  Requests and responses
// in the time protocol are made up of tagged data, QUIC-style.  Tags are 4
// bytes long and meant to be readable-ish, but they cannot be chosen with
// complete freedom, because they must be strictly increasing within a message
// to permit binary searches.
constexpr tag_t MakeTag(char a, char b, char c, char d) {
  return static_cast<uint32_t>(a) | static_cast<uint32_t>(b) << 8 |
         static_cast<uint32_t>(c) << 16 | static_cast<uint32_t>(d) << 24;
}

// kTagNONC ("nonce") is used in client requests.  It tags the request's nonce.
constexpr tag_t kTagNONC = MakeTag('N', 'O', 'N', 'C');
// kTagPAD ("padding") is used in client requests.  It tags the padding that
// fills out the request to at least |kMinRequestSize|.
constexpr tag_t kTagPAD = MakeTag('P', 'A', 'D', '\xff');

// kTagMIDP is used in the signed portion of server responses.  It tags the
// midpoint of the server's time in Unix epoch-microseconds.
constexpr tag_t kTagMIDP = MakeTag('M', 'I', 'D', 'P');
// kTagRADI contains the radius of uncertainty (in microseconds) of the
// server's time.
constexpr tag_t kTagRADI = MakeTag('R', 'A', 'D', 'I');
// kTagROOT is used in the signed portion of server responses.  It tags the root
// of a Merkle tree that contains the nonces from a batch of client requests.
constexpr tag_t kTagROOT = MakeTag('R', 'O', 'O', 'T');

// kTagSIG ("signature") is used in in the unsigned portion of server responses.
// It tags a signature made using the key from the server's certificate.
constexpr tag_t kTagSIG = MakeTag('S', 'I', 'G', '\0');
// kTagPATH is used in the unsigned portion of server responses.  It tags the
// path from the client's nonce, a leaf node, to the root of the Merkle tree, so
// that the client can verify the inclusion of its nonce in the tree.
constexpr tag_t kTagPATH = MakeTag('P', 'A', 'T', 'H');
// kTagSREP ("signed response") is used in the unsigned portion
// of server responses.  It tags the signed portion of the response.
constexpr tag_t kTagSREP = MakeTag('S', 'R', 'E', 'P');
// kTagCERT ("certificate") is used in the unsigned portion of server responses.
// It tags a (not X.509) certificate.  The tagged value is the public key whose
// private key the server uses to sign its response.  The public key is signed
// offline by another keypair, whose public key is baked into the client.
constexpr tag_t kTagCERT = MakeTag('C', 'E', 'R', 'T');
// kTagINDX ("index") is used in the unsigned portion of server responses.  It
// tells the client the index that was assigned to its nonce when generating the
// Merkle tree.
constexpr tag_t kTagINDX = MakeTag('I', 'N', 'D', 'X');

// kTagPUBK ("public key") is used in server certificates.  It tags the public
// key whose private key was used to sign the server's response.
constexpr tag_t kTagPUBK = MakeTag('P', 'U', 'B', 'K');
// kTagMINT ("minimum validity timestamp") is used in server certificates.  It
// tags the beginning of the certificate's validity period.
constexpr tag_t kTagMINT = MakeTag('M', 'I', 'N', 'T');
// kTagMAXT ("maximum validity timestamp") is used in server certificates.  It
// tags the end of the certificate's validity period.
constexpr tag_t kTagMAXT = MakeTag('M', 'A', 'X', 'T');
// kTagDELE ("delegation") is used in server certificates.  It tags the data
// signed by the server's offline key.
constexpr tag_t kTagDELE = MakeTag('D', 'E', 'L', 'E');

// kContextString is prefixed to the server's response before generating or
// verifying the server's signature.
static const char kContextString[] = "RoughTime v1 response signature";
static_assert(sizeof(kContextString) % 4 == 0,
              "Context strings must be a multiple of four bytes long");

// kCertContextString is added as a prefix to the server's certificate before
// generating or verifying the certificate's signature.
static const char kCertContextString[] = "RoughTime v1 delegation signature--";
static_assert(sizeof(kCertContextString) % 4 == 0,
              "Context strings must be a multiple of four bytes long");

// NumMessageOffsets gives the size in entries of the table of offsets for a
// time protocol message having |num_tags| tags.  (Since the length of messages
// in the time protocol is known, a message with only one tag does not need a
// table of offsets.)
constexpr size_t NumMessageOffsets(size_t num_tags) {
  return num_tags == 0 ? 0 : num_tags - 1;
}

// MessageHeaderLen gives the size in bytes of a message header, which consists
// of a tag count, a table of offsets (if there are least two tags), and a list
// of 0 or more tags.
constexpr size_t MessageHeaderLen(size_t num_tags) {
  return sizeof(uint32_t) /* tag count */ +
         sizeof(uint32_t) * NumMessageOffsets(num_tags) /* offsets */ +
         sizeof(tag_t) * num_tags /* tag values */;
}

// kPaddingLen is the number of padding bytes necessary to make a client request
// sufficiently long.
constexpr size_t kPaddingLen =
    kMinRequestSize - (MessageHeaderLen(2) + kNonceLength);

// Parser decodes requests from a time server client.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Number of tags                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Offset, Tag 1 Data                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Offset, Tag N Data                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Tag 0                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                              ...                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Tag N                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Data...                           |
// |                      (indexed by offsets)                     |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
class Parser {
 public:
  // Parses the supplied data.  No copies are made, so the data pointed to by
  // |req| must live as long as the |Parser| object.  Callers should check
  // |is_valid| before calling any other method.
  Parser(const uint8_t* req, size_t len);

  Parser() = delete;
  Parser(const Parser&) = delete;
  Parser& operator=(const Parser&) = delete;

  bool is_valid() const { return is_valid_; }

  // GetTag sets |*out_data| and |*out_len| to reflect the location (within the
  // data supplied to the constructor) of the tag |tag|, if found.  Returns true
  // if |tag| is found.
  bool GetTag(const uint8_t** out_data, size_t* out_len, tag_t tag) const;

  // GetFixedLen is a specialization of |GetTag| that returns true only if the
  // data tagged by |tag| is |expected_len| bytes long.
  bool GetFixedLen(const uint8_t** out_data, tag_t tag,
                   size_t expected_len) const;

  // Get is a specialization of |GetFixedLen| that expects |tag| to tag a value
  // of type |T|.  The tagged value is assigned to |*out_value|.
  template <typename T>
  bool Get(T* out_value, tag_t tag) const;

 private:
  bool is_valid_ = false;
  size_t num_tags_;
  const uint8_t* offsets_;  // |NumMessageOffsets| offsets into |data_|.
  const uint8_t* tags_;        // |num_tags_| 32-bit tags.
  const uint8_t* data_;      // |len_| bytes.
  size_t len_;
};

// Builder creates a time server response.
class Builder {
 public:
  Builder() = delete;
  Builder(const Builder&) = delete;
  Builder& operator=(const Builder&) = delete;

  // Prepares to write tags and data to a buffer |out| of |out_len| bytes.
  Builder(uint8_t* out, size_t out_len, size_t num_tags);

  // AddTag adds the tag |tag| to the response, which must be greater than any
  // previously added tag, and sets |*out_data| to an address where |len| bytes
  // may be written.  Returns true iff the tag may be written.
  bool AddTag(uint8_t** out_data, tag_t tag, size_t len);

  // AddTagData is a specialization of |AddTag| that copies the |len| bytes
  // pointed to by |data| into the response.  Returns true iff the tag was
  // written.
  bool AddTagData(tag_t tag, const uint8_t* data, size_t len);

  // Finish returns true if the response is valid, and sets |out_len| to the
  // size of the response.  After calling |Finish| all subsequent calls will
  // fail.
  bool Finish(size_t* out_len);

 private:
  const size_t num_tags_;
  const size_t header_len_;
  uint8_t* const offsets_;
  uint8_t* const tags_;

  uint8_t* data_;      // Offset of next |AddTag|.
  size_t len_;         // Bytes remaining in the output buffer.
  size_t offset_ = 0;  // Offset of data for next tag.

  size_t tag_i_ = 0;  // Index of next tag.
  tag_t previous_tag_;
  bool have_previous_tag_ = false;

  bool valid_ = false;
};

// Computes the SHA-512 hash of a Merkle tree leaf, i.e. a client's nonce, as
// 0||nonce.  |in| is assumed to point to |kNonceLength| bytes and |out| is
// assumed to have space for |SHA512_DIGEST_LENGTH| bytes.
void HashLeaf(uint8_t* out, const uint8_t* in);

// Computes the SHA-512 hash of a Merkle tree node as 1||left||right.  |left|,
// |right|, and |out| are assumed to point to |SHA512_DIGEST_LENGTH| bytes.
void HashNode(uint8_t* out, const uint8_t* left, const uint8_t* right);

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_PROTOCOL_H_
