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

#include "sys_time.h"

#if defined(__MACH__)
#include <sys/time.h>
#else
#include <time.h>
#endif

#include "logging.h"

namespace roughtime {

static const uint32_t kOneSecondRadius = 1000000;

SystemTimeSource::SystemTimeSource() {}

SystemTimeSource::~SystemTimeSource() {}

#if defined(__MACH__)
std::pair<rough_time_t, uint32_t> SystemTimeSource::Now() {
  struct timeval tv;
  ROUGHTIME_CHECK_EQ(0, gettimeofday(&tv, nullptr));
  uint64_t now = tv.tv_sec;
  now *= 1000000;
  now += tv.tv_usec;

  return std::make_pair(now, kOneSecondRadius);
}
#else
std::pair<rough_time_t, uint32_t> SystemTimeSource::Now() {
  struct timespec ts;
  ROUGHTIME_CHECK_EQ(0, clock_gettime(CLOCK_REALTIME_COARSE, &ts));
  uint64_t now = ts.tv_sec;
  now *= 1000000;
  now += ts.tv_nsec / 1000;

  return std::make_pair(now, kOneSecondRadius);
}
#endif

}  // namespace roughtime
