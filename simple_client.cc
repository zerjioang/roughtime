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

// simple_client is the most basic Roughtime client possible. Given a filename
// containing a servers list as the sole argument it prints the time obtained
// from a single server and the offset from the current system clock.

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <google/protobuf/stubs/status.h>
#include <google/protobuf/util/json_util.h>
#include <openssl/rand.h>

#include "client.h"
#include "config.pb.h"
#include "protocol.h"

// kTimeoutSeconds is the number of seconds that we will wait for a reply
// from the server.
static const int kTimeoutSeconds = 3;

namespace roughtime {

// MonotonicUs returns the value of the monotonic clock in microseconds.
uint64_t MonotonicUs();

// MonotonicUs returns the value of the realtime clock in microseconds.
uint64_t RealtimeUs();

// GetUsableServer parses the JSON-encoded server information from
// |servers_contents| and looks for the first server with an Ed25519 public key
// and UDP address. If it finds one, it sets |*out_name|, |*out_address| and
// |*out_public_key| and returns true. Otherwise it returns false.
static bool GetUsableServer(std::string* out_name, std::string* out_address,
                            std::string* out_public_key,
                            const std::string& servers_contents) {
  config::ServersJSON servers;
  google::protobuf::util::Status status =
      google::protobuf::util::JsonStringToMessage(servers_contents, &servers);
  if (!status.ok()) {
    std::string error_message(status.error_message().data(),
                              status.error_message().size());
    fprintf(stderr, "Failed to parse servers JSON: %s\n",
            error_message.c_str());
    return false;
  }

  for (int i = 0; i < servers.servers_size(); i++) {
    const config::Server& server = servers.servers(i);

    if (server.public_key_type() != "ed25519") {
      continue;
    }

    for (int j = 0; j < server.addresses_size(); j++) {
      const config::ServerAddress& address = server.addresses(j);

      if (address.protocol() != "udp") {
        continue;
      }

      *out_name = server.name();
      *out_address = address.address();
      *out_public_key = server.public_key();
      return true;
    }
  }

  fprintf(stderr, "Failed to find any usable servers.\n");
  return false;
}

}  // namespace roughtime

// ReadServersFile reads the contents of |filename| and sets |*out_contents| to
// contain them. It returns true on success and false on error.
static bool ReadServersFile(std::string* out_contents, const char* filename) {
  FILE* servers_file = fopen(filename, "r");
  if (servers_file == nullptr) {
    fprintf(stderr, "Failed to open JSON servers file.\n");
    return false;
  }

  if (fseek(servers_file, 0, SEEK_END) != 0) {
    fprintf(stderr, "Failed to seek within JSON servers file.\n");
    fclose(servers_file);
    return false;
  }

  const long length = ftell(servers_file);  // NOLINT
  if (length < 0) {
    fprintf(stderr, "Failed to get offset within JSON servers file.\n");
    fclose(servers_file);
    return false;
  }

  if (fseek(servers_file, 0, SEEK_SET) != 0) {
    fprintf(stderr, "Failed to seek within JSON servers file.\n");
    fclose(servers_file);
    return false;
  }

  std::unique_ptr<uint8_t[]> buf(new uint8_t[length]);
  if (fread(buf.get(), static_cast<size_t>(length), 1, servers_file) != 1) {
    fprintf(stderr, "Failed to read JSON servers file.\n");
    fclose(servers_file);
    return false;
  }

  fclose(servers_file);
  out_contents->assign(reinterpret_cast<const char*>(buf.get()), length);
  return true;
}

// CreateSocket resolves the given address (which must be of the form
// "host:port") and sets |*out_socket| to reference a fresh socket connected to
// that address. It returns true on success and false on error.
static bool CreateSocket(int* out_socket, const std::string& address) {
  const size_t colon_offset = address.rfind(':');
  if (colon_offset == std::string::npos) {
    fprintf(stderr, "No port number in server address: %s\n", address.c_str());
    return false;
  }
  std::string host(address.substr(0, colon_offset));
  const std::string port_str(address.substr(colon_offset + 1));

  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_protocol = IPPROTO_UDP;
  hints.ai_flags = AI_NUMERICSERV;

  if (!host.empty() && host[0] == '[' && host[host.size() - 1] == ']') {
    host = host.substr(1, host.size() - 1);
    hints.ai_family = AF_INET6;
    hints.ai_flags |= AI_NUMERICHOST;
  }

  struct addrinfo* addrs;
  int r = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &addrs);
  if (r != 0) {
    fprintf(stderr, "Failed to resolve %s: %s", address.c_str(),
            gai_strerror(r));
    return false;
  }

  int sock = socket(addrs->ai_family, addrs->ai_socktype, addrs->ai_protocol);
  if (sock < 0) {
    perror("Failed to create UDP socket");
    freeaddrinfo(addrs);
    return false;
  }

  if (connect(sock, addrs->ai_addr, addrs->ai_addrlen)) {
    perror("Failed to connect UDP socket");
    freeaddrinfo(addrs);
    close(sock);
    return false;
  }

  char dest_str[INET6_ADDRSTRLEN];
  r = getnameinfo(addrs->ai_addr, addrs->ai_addrlen, dest_str, sizeof(dest_str),
                  NULL /* don't want port information */, 0, NI_NUMERICHOST);
  freeaddrinfo(addrs);

  if (r != 0) {
    fprintf(stderr, "getnameinfo: %s", gai_strerror(r));
    close(sock);
    return false;
  }

  printf("Sending request to %s, port %s.\n", dest_str, port_str.c_str());
  *out_socket = sock;
  return true;
}

enum ExitCode {
  kExitBadSystemTime = 1,
  kExitBadArguments = 2,
  kExitNoServer = 3,
  kExitNetworkError = 4,
  kExitTimeout = 5,
  kExitBadReply = 6,
};

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <roughtime-servers.json>\n", argv[0]);
    return kExitBadArguments;
  }

  std::string servers_contents;
  if (!ReadServersFile(&servers_contents, argv[1])) {
    return kExitBadArguments;
  }

  std::string name, address, public_key;
  if (!roughtime::GetUsableServer(&name, &address, &public_key,
                                  servers_contents)) {
    return kExitNoServer;
  }

  int fd = 0;
  if (!CreateSocket(&fd, address)) {
    return kExitNetworkError;
  }

  uint8_t nonce[roughtime::kNonceLength];
  RAND_bytes(nonce, sizeof(nonce));
  const std::string request = roughtime::CreateRequest(nonce);

  struct timeval timeout;
  timeout.tv_sec = kTimeoutSeconds;
  timeout.tv_usec = 0;
  setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

  ssize_t r;
  do {
    r = send(fd, request.data(), request.size(), 0 /* flags */);
  } while (r == -1 && errno == EINTR);
  const uint64_t start_us = roughtime::MonotonicUs();

  if (r < 0 || static_cast<size_t>(r) != request.size()) {
    perror("send on UDP socket");
    close(fd);
    return kExitNetworkError;
  }

  uint8_t recv_buf[roughtime::kMinRequestSize];
  ssize_t buf_len;
  do {
    buf_len = recv(fd, recv_buf, sizeof(recv_buf), 0 /* flags */);
  } while (buf_len == -1 && errno == EINTR);

  const uint64_t end_us = roughtime::MonotonicUs();
  const uint64_t end_realtime_us = roughtime::RealtimeUs();

  close(fd);

  if (buf_len == -1) {
    if (errno == EINTR) {
      fprintf(stderr, "No response from %s with %d seconds.\n", name.c_str(),
              kTimeoutSeconds);
      return kExitTimeout;
    }

    perror("recv from UDP socket");
    return kExitNetworkError;
  }

  roughtime::rough_time_t timestamp;
  uint32_t radius;
  std::string error;
  if (!roughtime::ParseResponse(
          &timestamp, &radius, &error,
          reinterpret_cast<const uint8_t*>(public_key.data()), recv_buf,
          buf_len, nonce)) {
    fprintf(stderr, "Response from %s failed verification: %s", name.c_str(),
            error.c_str());
    return kExitBadReply;
  }

  // We assume that the path to the Roughtime server is symmetric and thus add
  // half the round-trip time to the server's timestamp to produce our estimate
  // of the current time.
  timestamp += (end_us - start_us) / 2;

  printf("Received reply in %" PRIu64 "μs.\n", end_us - start_us);
  printf("Current time is %" PRIu64 "μs from the epoch, ±%uμs \n", timestamp,
         static_cast<unsigned>(radius));
  int64_t system_offset =
      static_cast<int64_t>(timestamp) - static_cast<int64_t>(end_realtime_us);
  printf("System clock differs from that estimate by %" PRId64 "μs.\n",
         system_offset);

  static const int64_t kTenMinutes = 10 * 60 * 1000000;
  if (imaxabs(system_offset) > kTenMinutes) {
    return kExitBadSystemTime;
  }

  return 0;
}
