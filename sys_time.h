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

#ifndef SECURITY_ROUGHTIME_SYS_TIME_H_
#define SECURITY_ROUGHTIME_SYS_TIME_H_

#include <stdint.h>

#include "time_source.h"

namespace roughtime {

// SystemTimeSource uses gettimeofday to provide the current time and has a
// fixed uncertainly of one second. Roughtime defines time to include smeared
// leap seconds but it's unlikely that the system clock respects that. Thus
// the radius is meant to reflect that and this time source is only provided as
// an example.
class SystemTimeSource : public TimeSource {
 public:
  SystemTimeSource();
  ~SystemTimeSource() override;

  std::pair<uint64_t, uint32_t> Now() override;
};

}  // namespace roughtime

#endif  // SECURITY_ROUGHTIME_SYS_TIME_H_
