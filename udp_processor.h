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

#ifndef SECURITY_ROUGHTIME_UDP_PROCESSOR_H_
#define SECURITY_ROUGHTIME_UDP_PROCESSOR_H_

#include <arpa/inet.h>
#include <netinet/in.h>

#include <memory>
#include <vector>

#include "server.h"

namespace roughtime {

#if defined(__MACH__) || defined(__Fuchsia__)
struct mmsghdr {
  uint8_t *iov_base;
  size_t msg_len;
  msghdr msg_hdr;
};
#endif

// UdpProcessor manages a set of receive buffers for processing UDP requests.
class UdpProcessor {
 public:
  // Stats contains various counters for a single batch.
  struct Stats {
    size_t bytes_in;
    size_t bytes_out;
    unsigned packets_in;
    unsigned packets_out;
    unsigned requests_invalid;
    unsigned requests_truncated;
  };

  UdpProcessor();
  virtual ~UdpProcessor();

  // AddBrokenReplyGenerator adds a BrokenReplyGenerator that will be used for
  // a fraction of single-request batches. It can answer the request with
  // replies that are designed to test edge cases in clients. The sum of
  // probabilities of all generators passed to |AddBrokenReplyGenerator| must
  // be ≤ 1024.
  bool AddBrokenReplyGenerator(std::unique_ptr<BrokenReplyGenerator> generator);

  // ProcessBatch reads zero or more requests from |fd|, has |server| process
  // them and sends out the replies. It returns false if there was an
  // unexpected error during processing and true otherwise. (Reading zero
  // packets, finding invalid requests etc are not counted as unexpected
  // errors.)
  virtual bool ProcessBatch(int fd, Server* server, Stats* out_stats);

  // HandleOne processes a single |packet| of length |len| received from |from|.
  // It should return true if the message was accepted by |server|.
  virtual bool HandleOne(const struct msghdr* from, const uint8_t* packet,
                         size_t len, Server* server);

  // MakeSocket sets |*out_sock| to a UDP socket bound to the given port and
  // sets |*out_port| to the bound port number. If |port| is zero then a free
  // port number is used. It returns true on success or false on error.
  static bool MakeSocket(int port, int* out_sock, uint16_t* out_port);

 protected:
  // See recvmmsg(2) for help understanding these.  Note that indices in the
  // sending arrays don't correspond 1:1 with indices in the receiving arrays,
  // due to the possibility of invalid requests.
  mmsghdr recv_mmsghdrs_[kBatchSize];
  iovec recv_iov_[kBatchSize];
  uint8_t recv_buf_[kBatchSize][kMaxRecvPacketSize];

  mmsghdr send_mmsghdrs_[kBatchSize];
  iovec send_iov_[kBatchSize];
  uint8_t send_buf_[kBatchSize][kMaxResponseSize];

  // PrepareResponse sets up |send_mmsghdrs[index]|.
  virtual void PrepareResponse(struct msghdr* out_send_header,
                               const struct msghdr& recv_header);

  // Reset clears state in order to prepare for recvmmsg(2).
  virtual void Reset();

 private:
  // MaybeBreakResponse takes a valid request in |request| and the standard
  // response in |normal_response|. If any element of
  // |broken_reply_generators_| should be applied then it does so. It returns
  // true if the response in |out| should be sent and false if not.
  bool MaybeBreakResponse(uint8_t* out, size_t* out_len, size_t max_out_len,
                          const uint8_t* normal_response,
                          size_t normal_response_len, const uint8_t* request,
                          size_t request_len);

  sockaddr_storage sockaddrs_[kBatchSize];

  // requests_processed_ is the total number of valid requests that have been
  // processed.
  uint64_t requests_processed_ = 0;

  std::vector<std::unique_ptr<BrokenReplyGenerator>> broken_reply_generators_;

  // broken_reply_generator_sum_ is the sum of the probabilities of
  // |broken_reply_generators_|.
  uint16_t broken_reply_generator_sum_ = 0;
};

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_UDP_PROCESSOR_H_
