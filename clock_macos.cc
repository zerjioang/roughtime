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


#if defined(__APPLE__)

#include <mach/clock.h>
#include <mach/mach.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

namespace roughtime {

// TimeUs returns the current value of the specified clock in microseconds.
static uint64_t TimeUs(clock_id_t clock) {
  clock_serv_t clock_ref;
  mach_timespec_t tv;

  if (host_get_clock_service(mach_host_self(), clock, &clock_ref) !=
          KERN_SUCCESS ||
      clock_get_time(clock_ref, &tv) != KERN_SUCCESS ||
      mach_port_deallocate(mach_task_self(), clock_ref) != KERN_SUCCESS) {
    abort();
  }

  uint64_t ret = tv.tv_sec;
  ret *= 1000000;
  ret += tv.tv_nsec / 1000;
  return ret;
}

// MonotonicUs returns the value of the monotonic clock in microseconds.
uint64_t MonotonicUs() { return TimeUs(REALTIME_CLOCK); }

// MonotonicUs returns the value of the realtime clock in microseconds.
uint64_t RealtimeUs() { return TimeUs(CALENDAR_CLOCK); }

}  // namespace roughtime

#endif  // __linux
