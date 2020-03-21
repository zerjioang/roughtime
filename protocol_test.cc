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
#include "gtest/gtest.h"

#include <openssl/sha.h>

namespace roughtime {

constexpr tag_t kTagTAG1 = MakeTag('T', 'A', 'G', '1');
constexpr tag_t kTagTAG2 = MakeTag('T', 'A', 'G', '2');
constexpr tag_t kTagTAG3 = MakeTag('T', 'A', 'G', '3');
constexpr tag_t kTagTAG4 = MakeTag('T', 'A', 'G', '4');

TEST(ParserTest, Success) {
  const uint8_t buffer[] = {
      0x03, 0x00, 0x00, 0x00,  // 3 tags
      0x04, 0x00, 0x00, 0x00,  // tag #2 has offset 4
      0x08, 0x00, 0x00, 0x00,  // tag #3 has offset 8
      0x54, 0x41, 0x47, 0x31,  // TAG1
      0x54, 0x41, 0x47, 0x32,  // TAG2
      0x54, 0x41, 0x47, 0x33,  // TAG3
      0x11, 0x11, 0x11, 0x11,  // data for tag #1
      0x22, 0x22, 0x22, 0x22,  // data for tag #2
      0x33, 0x33, 0x33, 0x33,  // data for tag #3
  };

  Parser parser(buffer, sizeof(buffer));
  EXPECT_TRUE(parser.is_valid());
  const uint8_t* datap;
  size_t len;

  EXPECT_TRUE(parser.GetTag(&datap, &len, kTagTAG1));
  EXPECT_EQ(4, len);
  EXPECT_TRUE(memcmp("\x11\x11\x11\x11", datap, len) == 0);
  datap = nullptr;
  EXPECT_TRUE(parser.GetFixedLen(&datap, kTagTAG1, 4));
  EXPECT_TRUE(memcmp("\x11\x11\x11\x11", datap, len) == 0);
  datap = nullptr;

  EXPECT_TRUE(parser.GetTag(&datap, &len, kTagTAG2));
  EXPECT_EQ(4, len);
  EXPECT_TRUE(memcmp("\x22\x22\x22\x22", datap, len) == 0);
  datap = nullptr;
  EXPECT_TRUE(parser.GetFixedLen(&datap, kTagTAG2, 4));
  EXPECT_TRUE(memcmp("\x22\x22\x22\x22", datap, len) == 0);
  datap = nullptr;

  EXPECT_TRUE(parser.GetTag(&datap, &len, kTagTAG3));
  EXPECT_EQ(4, len);
  EXPECT_TRUE(memcmp("\x33\x33\x33\x33", datap, len) == 0);
  datap = nullptr;
  EXPECT_TRUE(parser.GetFixedLen(&datap, kTagTAG3, 4));
  EXPECT_TRUE(memcmp("\x33\x33\x33\x33", datap, len) == 0);
  datap = nullptr;

  EXPECT_FALSE(parser.GetTag(&datap, &len, kTagTAG4));
  EXPECT_FALSE(parser.GetFixedLen(&datap, kTagTAG4, 1));
}

TEST(ParserTest, UnalignedInput) {
  alignas(4) const uint8_t buffer[] = {
      0x00,                    // unalign input.
      0x02, 0x00, 0x00, 0x00,  // 2 tags
      0x04, 0x00, 0x00, 0x00,  // tag #2 has offset 4
      0x54, 0x41, 0x47, 0x31,  // TAG1
      0x54, 0x41, 0x47, 0x32,  // TAG2
      0x11, 0x11, 0x11, 0x11,  // data for tag #1
      0x22, 0x22, 0x22, 0x22,  // data for tag #2
  };

  Parser parser(buffer + 1, sizeof(buffer) - 1);
  EXPECT_TRUE(parser.is_valid());
  const uint8_t* datap;
  size_t len;

  EXPECT_TRUE(parser.GetTag(&datap, &len, kTagTAG1));
  EXPECT_EQ(4, len);
  EXPECT_TRUE(memcmp("\x11\x11\x11\x11", datap, len) == 0);
  datap = nullptr;
  EXPECT_TRUE(parser.GetFixedLen(&datap, kTagTAG1, 4));
  EXPECT_TRUE(memcmp("\x11\x11\x11\x11", datap, len) == 0);
  datap = nullptr;

  EXPECT_TRUE(parser.GetTag(&datap, &len, kTagTAG2));
  EXPECT_EQ(4, len);
  EXPECT_TRUE(memcmp("\x22\x22\x22\x22", datap, len) == 0);
  datap = nullptr;
  EXPECT_TRUE(parser.GetFixedLen(&datap, kTagTAG2, 4));
  EXPECT_TRUE(memcmp("\x22\x22\x22\x22", datap, len) == 0);
  datap = nullptr;

  EXPECT_FALSE(parser.GetTag(&datap, &len, kTagTAG4));
  EXPECT_FALSE(parser.GetFixedLen(&datap, kTagTAG4, 1));
}

TEST(ParserTest, IntegerTypes) {
  uint8_t buffer[128];
  Builder builder(buffer, sizeof(buffer), 2);
  uint64_t big = 0xdeaddeaddeaddeadULL;
  uint32_t little = 0xbeefbeef;

  ASSERT_TRUE(builder.AddTagData(kTagTAG1, reinterpret_cast<uint8_t*>(&big),
                                 sizeof(big)));
  ASSERT_TRUE(builder.AddTagData(kTagTAG2, reinterpret_cast<uint8_t*>(&little),
                                 sizeof(little)));
  size_t out_len;
  ASSERT_TRUE(builder.Finish(&out_len));

  Parser parser(buffer, out_len);
  EXPECT_TRUE(parser.is_valid());
  big = 0;
  little = 0;

  EXPECT_FALSE(parser.Get(&big, kTagTAG2));  // Wrong tag.
  EXPECT_TRUE(parser.Get(&big, kTagTAG1));
  EXPECT_EQ(0xdeaddeaddeaddeadULL, big);

  EXPECT_FALSE(parser.Get(&little, kTagTAG1));  // Wrong tag.
  EXPECT_TRUE(parser.Get(&little, kTagTAG2));
  EXPECT_EQ(0xbeefbeef, little);
}

TEST(ParserTest, EmptyMessage) {
  uint8_t buffer[] = {
      0x00, 0x00, 0x00, 0x00,  // 0 tags.
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_TRUE(parser.is_valid());
}

TEST(ParserTest, TooManyTags) {
  uint8_t buffer[] = {
      0xff, 0xff, 0xff, 0xff,  // hella tags.
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_FALSE(parser.is_valid());
}

TEST(ParserTest, TwoEmptyTags) {
  uint8_t buffer[] = {
      0x02, 0x00, 0x00, 0x00,  // 2 tags.
      0x00, 0x00, 0x00, 0x00,  // tag #2 has offset 0
      0x01, 0x00, 0x00, 0x00,  // tag #1
      0x02, 0x00, 0x00, 0x00,  // tag #2
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_TRUE(parser.is_valid());
}

TEST(ParserTest, OffsetNotAMultipleOf4) {
  uint8_t buffer[] = {
      0x02, 0x00, 0x00, 0x00,  // 2 tags.
      0x03, 0x00, 0x00, 0x00,  // tag #2 has offset 3
      0x54, 0x41, 0x47, 0x31,  // TAG1
      0x55, 0x41, 0x47, 0x31,  // TAG2
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_FALSE(parser.is_valid());
}

TEST(ParserTest, OffsetsOutOfOrder) {
  uint8_t buffer[] = {
      0x03, 0x00, 0x00, 0x00,  // 3 tags.
      0x08, 0x00, 0x00, 0x00,  // tag #2 has offset 8
      0x04, 0x00, 0x00, 0x00,  // tag #3 has offset 4
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_FALSE(parser.is_valid());
}

TEST(ParserTest, TagsOutOfOrder) {
  uint8_t buffer[] = {
      0x02, 0x00, 0x00, 0x00,  // 2 tags.
      0x00, 0x00, 0x00, 0x00,  // tag #2 has offset 0
      0x01, 0x00, 0x00, 0x00,  // tag #1
      0x01, 0x00, 0x00, 0x00,  // tag #2, same as #1 (out of order)
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_FALSE(parser.is_valid());
}

TEST(ParserTest, InvalidOffset) {
  uint8_t buffer[] = {
      0x02, 0x00, 0x00, 0x00,  // 2 tags.
      0x04, 0x00, 0x00, 0x00,  // tag #2 has offset 4 (past end of message)
      0x01, 0x00, 0x00, 0x00,  // tag #1
      0x02, 0x00, 0x00, 0x00,  // tag #2
  };
  Parser parser(buffer, sizeof(buffer));
  EXPECT_FALSE(parser.is_valid());
}

TEST(BuilderTest, Success) {
  uint8_t buffer[128];
  Builder builder(buffer, sizeof(buffer), 3);
  const uint8_t* data = reinterpret_cast<const uint8_t*>("1234");

  EXPECT_TRUE(builder.AddTagData(kTagTAG1, data, 4));
  EXPECT_TRUE(builder.AddTagData(kTagTAG2, data, 4));
  EXPECT_TRUE(builder.AddTagData(kTagTAG3, data, 4));
  size_t out_len = 0;
  EXPECT_TRUE(builder.Finish(&out_len));
  constexpr uint8_t kExpected[] = {
      0x03, 0x00, 0x00, 0x00,  // 3 tags
      0x04, 0x00, 0x00, 0x00,  // tag #2 has offset 4
      0x08, 0x00, 0x00, 0x00,  // tag #3 has offset 8
      0x54, 0x41, 0x47, 0x31,  // TAG1
      0x54, 0x41, 0x47, 0x32,  // TAG2
      0x54, 0x41, 0x47, 0x33,  // TAG3
      0x31, 0x32, 0x33, 0x34,
      0x31, 0x32, 0x33, 0x34,
      0x31, 0x32, 0x33, 0x34,
  };
  EXPECT_EQ(sizeof(kExpected), out_len);
  EXPECT_EQ(0, memcmp(kExpected, buffer, sizeof(kExpected)));
}

TEST(BuilderTest, ExtraTag) {
  uint8_t buffer[128];
  Builder builder(buffer, sizeof(buffer), 1);
  uint32_t data = 42;
  EXPECT_TRUE(builder.AddTagData(
      kTagTAG1, reinterpret_cast<const uint8_t*>(&data), sizeof(data)));
  EXPECT_FALSE(builder.AddTagData(
      kTagTAG2, reinterpret_cast<const uint8_t*>(&data), sizeof(data)));
}

TEST(BuilderTest, AddAfterFinish) {
  uint8_t buffer[128];
  Builder builder(buffer, sizeof(buffer), 1);
  uint32_t data = 42;
  EXPECT_TRUE(builder.AddTagData(
      kTagTAG1, reinterpret_cast<const uint8_t*>(&data), sizeof(data)));
  size_t out_len = 0;
  EXPECT_TRUE(builder.Finish(&out_len));
  EXPECT_FALSE(builder.AddTagData(
      kTagTAG2, reinterpret_cast<const uint8_t*>(&data), sizeof(data)));
}

TEST(BuilderTest, EmptyMessage) {
  uint8_t buffer[4];
  Builder builder(buffer, sizeof(buffer), 0);
  size_t len;
  EXPECT_TRUE(builder.Finish(&len));
}

TEST(BuilderTest, FinishAfterFinish) {
  uint8_t buffer[4];
  Builder builder(buffer, sizeof(buffer), 0);
  size_t len;
  EXPECT_TRUE(builder.Finish(&len));
  EXPECT_FALSE(builder.Finish(&len));
}

TEST(BuilderTest, MissingTag) {
  uint8_t buffer[4];
  Builder builder(buffer, sizeof(buffer), 1);
  size_t len;
  EXPECT_FALSE(builder.Finish(&len));
}

TEST(BuilderTest, ShortBuffer) {
  uint8_t buffer[3];
  Builder builder(buffer, sizeof(buffer), 0);
  size_t len;
  EXPECT_FALSE(builder.Finish(&len));
}

TEST(HashTest, SimpleTree) {
  uint8_t zeros[kNonceLength];
  memset(zeros, 0, sizeof(zeros));
  uint8_t left[SHA512_DIGEST_LENGTH];
  HashLeaf(left, zeros);
  constexpr uint8_t kExpectedLeftHash[SHA512_DIGEST_LENGTH] = {
      0x19, 0xdc, 0x6a, 0xe1, 0x2d, 0xe0, 0x8b, 0x21, 0xb3, 0x6c, 0x1e,
      0xc7, 0xf3, 0x53, 0xce, 0x9e, 0x7c, 0xef, 0x73, 0xfa, 0x4d, 0x13,
      0x54, 0xc4, 0x36, 0x23, 0x41, 0x67, 0xf0, 0x84, 0x7b, 0xc9, 0xe2,
      0xb8, 0x5e, 0x2f, 0x36, 0x20, 0x8f, 0x77, 0x3e, 0xf3, 0x24, 0xe2,
      0xd7, 0x9e, 0x6a, 0xf1, 0xbe, 0xca, 0x44, 0x70, 0xe4, 0x4b, 0x86,
      0x72, 0xb4, 0x7d, 0x07, 0x7e, 0xfe, 0x33, 0xa1, 0xf8};
  EXPECT_EQ(0, memcmp(kExpectedLeftHash, left, SHA512_DIGEST_LENGTH));

  uint8_t nonzeros[kNonceLength];
  memset(nonzeros, 'a', sizeof(nonzeros));
  uint8_t right[SHA512_DIGEST_LENGTH];
  HashLeaf(right, nonzeros);
  constexpr uint8_t kExpectedRightHash[SHA512_DIGEST_LENGTH] = {
      0x3d, 0x3a, 0xb5, 0x8a, 0x53, 0xc4, 0x57, 0x2a, 0x2a, 0x47, 0xeb,
      0x04, 0xd3, 0x22, 0x18, 0x5a, 0x7b, 0x47, 0xe6, 0x85, 0xd2, 0xa6,
      0x8f, 0x3b, 0xb8, 0xee, 0x4d, 0x34, 0x78, 0xa3, 0x34, 0x2a, 0xa7,
      0xe1, 0x06, 0xb7, 0x28, 0xb6, 0x06, 0xbd, 0x73, 0x17, 0xf0, 0x8f,
      0x37, 0xd9, 0xb0, 0xb5, 0x46, 0x90, 0x0b, 0x6e, 0x02, 0xa4, 0x01,
      0x7e, 0x77, 0xce, 0xbc, 0x63, 0xc4, 0x77, 0xb6, 0x7f,
  };
  EXPECT_EQ(0, memcmp(kExpectedRightHash, right, SHA512_DIGEST_LENGTH));

  uint8_t root[SHA512_DIGEST_LENGTH];
  HashNode(root, left, right);
  constexpr uint8_t kExpectedRootHash[SHA512_DIGEST_LENGTH] = {
      0x6a, 0xcd, 0xdd, 0x50, 0x32, 0x56, 0xc3, 0x53, 0x6c, 0x19, 0xe5,
      0x79, 0x20, 0xf3, 0xeb, 0xa9, 0x81, 0xb8, 0x8a, 0x1b, 0x25, 0x10,
      0x88, 0x97, 0xb4, 0x4a, 0x9a, 0x39, 0xc7, 0x58, 0x0d, 0x33, 0x87,
      0xab, 0x4f, 0x1e, 0x91, 0x49, 0x7d, 0xd7, 0xb7, 0xc3, 0xa9, 0xf5,
      0xa2, 0x24, 0xe1, 0x77, 0x50, 0x50, 0xa4, 0x69, 0xf1, 0x68, 0xcf,
      0x51, 0x0a, 0xac, 0xd2, 0x04, 0x39, 0x1a, 0x48, 0x7e};
  EXPECT_EQ(0, memcmp(kExpectedRootHash, root, SHA512_DIGEST_LENGTH));
}

}  // namespace roughtime
