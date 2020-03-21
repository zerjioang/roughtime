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

#ifndef SECURITY_ROUGHTIME_TIME_SOURCE_H_
#define SECURITY_ROUGHTIME_TIME_SOURCE_H_

#include <stdint.h>

#include <utility>

#include "protocol.h"

namespace roughtime {

// TimeSource is an interface that can provide the current time.
class TimeSource {
 public:
  virtual ~TimeSource() {}

  // Now returns the midpoint time in epoch-microseconds and a radius of
  // uncertainty.
  virtual std::pair<rough_time_t, uint32_t> Now() = 0;
};

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_TIME_SOURCE_H_
