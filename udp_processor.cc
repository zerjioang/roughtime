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

#include "udp_processor.h"

#include <fcntl.h>
#include <unistd.h>


#include "logging.h"
#include "open_source_fillins.h"

namespace roughtime {

UdpProcessor::UdpProcessor() {
  // These never change.  We can set them up just once and reuse them forever.
  memset(recv_mmsghdrs_, 0, sizeof(recv_mmsghdrs_));
  for (size_t i = 0; i < kBatchSize; i++) {
    recv_iov_[i].iov_base = recv_buf_[i];
    recv_iov_[i].iov_len = sizeof(recv_buf_[i]);
    recv_mmsghdrs_[i].msg_hdr.msg_name = &sockaddrs_[i];
    recv_mmsghdrs_[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
    recv_mmsghdrs_[i].msg_hdr.msg_iov = &recv_iov_[i];
    recv_mmsghdrs_[i].msg_hdr.msg_iovlen = 1;
  }

  memset(send_mmsghdrs_, 0, sizeof(send_mmsghdrs_));
  for (size_t i = 0; i < kBatchSize; i++) {
    send_iov_[i].iov_base = send_buf_[i];
    send_mmsghdrs_[i].msg_hdr.msg_iov = &send_iov_[i];
    send_mmsghdrs_[i].msg_hdr.msg_iovlen = 1;
    // iov_len varies per batch, as does msg_name.
  }
}

UdpProcessor::~UdpProcessor() {}

bool UdpProcessor::AddBrokenReplyGenerator(
    std::unique_ptr<BrokenReplyGenerator> broken_reply_generator) {
  const uint16_t new_sum =
      broken_reply_generator_sum_ + broken_reply_generator->probability_1024();
  if (new_sum > 1024) {
    return false;
  }

  broken_reply_generator_sum_ = new_sum;
  broken_reply_generators_.push_back(std::move(broken_reply_generator));

  return true;
}

// static
bool UdpProcessor::MakeSocket(int port, int *out_sock, uint16_t *out_port) {
  *out_sock = -1;
  *out_port = 0;

  const int fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd == -1) {
    ROUGHTIME_PLOG(ERROR) << "socket";
    return false;
  }

  struct sockaddr_in6 sin6;
  memset(&sin6, 0, sizeof(sin6));
  sin6.sin6_family = AF_INET6;
  sin6.sin6_addr = in6addr_any;
  sin6.sin6_port = htons(port);
  if (bind(fd, reinterpret_cast<sockaddr *>(&sin6), sizeof(sin6))) {
    ROUGHTIME_PLOG(ERROR) << "bind";
    close(fd);
    return false;
  }

  socklen_t sin6_len = sizeof(sin6);
  if (getsockname(fd, reinterpret_cast<sockaddr *>(&sin6), &sin6_len)) {
    ////ROUGHTIME_PLOG(ERROR) << "getsockname";
    close(fd);
    return false;
  }

  *out_sock = fd;
  *out_port = ntohs(sin6.sin6_port);
  return true;
}

void UdpProcessor::PrepareResponse(struct msghdr *out_send_header,
                                   const struct msghdr &recv_header) {
  out_send_header->msg_name = recv_header.msg_name;
  out_send_header->msg_namelen = recv_header.msg_namelen;
}

void UdpProcessor::Reset() {
  // Clear out the addresses from last time.  (Without this |recvmmsg| thinks
  // we are trying to receive from these addresses.)
  memset(sockaddrs_, 0, sizeof(sockaddrs_));
  for (size_t i = 0; i < kBatchSize; i++) {
    recv_mmsghdrs_[i].msg_hdr.msg_flags = 0;
    recv_mmsghdrs_[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);
  }
}

#if defined(__MACH__)
static const unsigned MSG_WAITFORONE = 0;
#endif

#if defined(__MACH__) || defined(__Fuchsia__)
static int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen,
                    unsigned flags, struct timespec *timeout) {
  ssize_t r = recvmsg(fd, &msgvec->msg_hdr, 0);
  if (r < 0) {
    return r;
  }

  msgvec->msg_len = r;
  return 1;
}

int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned vlen, unsigned flags) {
  ROUGHTIME_CHECK_EQ((unsigned) 1, vlen);
  ssize_t r = sendmsg(fd, &msgvec->msg_hdr, 0);
  if (r < 0) {
    return r;
  }

  msgvec->msg_len = r;
  return 1;
}
#endif

bool UdpProcessor::HandleOne(const struct msghdr *from, const uint8_t *packet,
                             size_t len, Server *server) {
  return server->AddRequest(packet, len);
}

bool UdpProcessor::ProcessBatch(int fd, Server *server, Stats *out_stats) {
  server->Reset();
  memset(out_stats, 0, sizeof(Stats));
  Reset();

  int r;
  do {
    r = recvmmsg(fd, recv_mmsghdrs_, kBatchSize, MSG_WAITFORONE,
                 nullptr /* timeout */);
  } while (r == -1 && errno == EINTR);

  if (r < 0) {
    ROUGHTIME_PLOG(ERROR) << "recvmmsg";
    return false;
  } else if (r == 0) {
    return true;
  }

  out_stats->packets_in = r;

  size_t index = 0;
  for (size_t i = 0; i < static_cast<size_t>(r); i++) {
    const msghdr *recv_header = &recv_mmsghdrs_[i].msg_hdr;
    out_stats->bytes_in += recv_mmsghdrs_[i].msg_len;
    if ((recv_header->msg_flags & (MSG_CTRUNC | MSG_TRUNC)) != 0) {
      out_stats->requests_truncated++;
      continue;
    }
    if (!HandleOne(recv_header, recv_buf_[i], recv_mmsghdrs_[i].msg_len,
                   server)) {
      out_stats->requests_invalid++;
      continue;
    }

    // Fill in the destination address for this response.  The data and its
    // length will be set below.
    msghdr *send_header = &send_mmsghdrs_[index].msg_hdr;
    PrepareResponse(send_header, *recv_header);
    index++;
  }

  if (index == 0) {
    return true;
  }

  server->Sign();

  out_stats->packets_out = index;
  for (size_t i = 0; i < index; i++) {
    size_t reply_len;
    if (!server->MakeResponse(send_buf_[i], &reply_len, i)) {
      ROUGHTIME_LOG(ERROR) << "failed to assemble responses";
      return false;
    }
    requests_processed_++;

    uint8_t broken_output_buf[kMaxResponseSize];
    if (MaybeBreakResponse(broken_output_buf, &reply_len,
                           sizeof(broken_output_buf), send_buf_[i], reply_len,
                           recv_buf_[i], recv_mmsghdrs_[i].msg_len)) {
      ROUGHTIME_DCHECK_LE(reply_len, sizeof(broken_output_buf));
      memcpy(send_buf_[i], broken_output_buf, reply_len);
    }

    out_stats->bytes_out += reply_len;
    send_iov_[i].iov_len = reply_len;
  }

  int messages_sent;
  do {
    messages_sent = sendmmsg(fd, send_mmsghdrs_, index, 0);
  } while (messages_sent == -1 && errno == EINTR);

  if (messages_sent == -1) {
    ROUGHTIME_PLOG(ERROR) << "sendmmsg";
    return false;
  }
  ROUGHTIME_LOG_IF_EVERY_N_SEC(ERROR, (static_cast<size_t>(messages_sent) < index),
                            30)
      << "only " << messages_sent << " of " << index << " messages were sent";

  return true;
}

bool UdpProcessor::MaybeBreakResponse(uint8_t *out, size_t *out_len,
                                      size_t max_out_len,
                                      const uint8_t *normal_response,
                                      size_t normal_response_len,
                                      const uint8_t *request,
                                      size_t request_len) {
  const uint16_t rand = requests_processed_ & 1023;
  if (rand >= broken_reply_generator_sum_) {
    return false;
  }

  uint16_t sum = 0;
  BrokenReplyGenerator *selected = nullptr;
  for (const auto &i : broken_reply_generators_) {
    sum += i->probability_1024();
    if (rand < sum) {
      selected = i.get();
      break;
    }
  }

  return selected->Process(out, out_len, max_out_len, normal_response,
                           normal_response_len, request, request_len);
}

}  // namespace roughtime
