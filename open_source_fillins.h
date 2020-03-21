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

#ifndef SECURITY_ROUGHTIME_OPEN_SOURCE_FILLINS_H_
#define SECURITY_ROUGHTIME_OPEN_SOURCE_FILLINS_H_

#if defined(ROUGHTIME_OPEN_SOURCE)

#include <errno.h>
#include <memory>

#include "logging.h"

#define ROUGHTIME_PLOG(level) ROUGHTIME_LOG(level) << strerror(errno) << ": "
#define ROUGHTIME_LOG_IF_EVERY_N_SEC(level, condition, time) \
  ROUGHTIME_LOG_IF(level, condition)

#if !defined(arraysize)
template <typename T, size_t N>
char (&ArraySizeHelper(T (&array)[N]))[N];

#define arraysize(array) (sizeof(ArraySizeHelper(array)))
#endif

#endif  // ROUGHTIME_OPEN_SOURCE

#endif  // SECURITY_ROUGHTIME_OPEN_SOURCE_FILLINS_H_
