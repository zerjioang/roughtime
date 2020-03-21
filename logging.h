/* Copyright 2017 The Roughtime Authors.
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


#ifndef ROUGHTIME_LOGGER_H_
#define ROUGHTIME_LOGGER_H_

#if defined(USE_GLOG)
#include <glog/logging.h>

#define GLOG_logtostderr 1
#define ROUGHTIME_LOG LOG
#define ROUGHTIME_LOG_IF LOG_IF

#define ROUGHTIME_CHECK CHECK

#define ROUGHTIME_CHECK_EQ CHECK_EQ
#define ROUGHTIME_CHECK_NE CHECK_NE
#define ROUGHTIME_CHECK_LT CHECK_LT
#define ROUGHTIME_CHECK_LE CHECK_LE
#define ROUGHTIME_CHECK_GT CHECK_GT
#define ROUGHTIME_CHECK_GE CHECK_GE

#define ROUGHTIME_DLOG DLOG
#define ROUGHTIME_DCHECK    DCHECK
#define ROUGHTIME_DCHECK_OK DCHECK_OK
#define ROUGHTIME_DCHECK_EQ DCHECK_EQ
#define ROUGHTIME_DCHECK_NE DCHECK_NE
#define ROUGHTIME_DCHECK_LT DCHECK_LT
#define ROUGHTIME_DCHECK_LE DCHECK_LE
#define ROUGHTIME_DCHECK_GT DCHECK_GT
#define ROUGHTIME_DCHECK_GE DCHECK_GE

#define ROUGHTIME_INIT_LOGGER  google::InitGoogleLogging

#else
#include <google/protobuf/stubs/logging.h>
#include <google/protobuf/stubs/macros.h>

#define ROUGHTIME_LOG GOOGLE_LOG
#define ROUGHTIME_LOG_IF GOOGLE_LOG_IF

#define ROUGHTIME_CHECK GOOGLE_CHECK

#define ROUGHTIME_CHECK_EQ GOOGLE_CHECK_EQ
#define ROUGHTIME_CHECK_NE GOOGLE_CHECK_NE
#define ROUGHTIME_CHECK_LT GOOGLE_CHECK_LT
#define ROUGHTIME_CHECK_LE GOOGLE_CHECK_LE
#define ROUGHTIME_CHECK_GT GOOGLE_CHECK_GT
#define ROUGHTIME_CHECK_GE GOOGLE_CHECK_GE

#define ROUGHTIME_DLOG GOOGLE_DLOG
#define ROUGHTIME_DCHECK    GOOGLE_DCHECK
#define ROUGHTIME_DCHECK_OK GOOGLE_DCHECK_OK
#define ROUGHTIME_DCHECK_EQ GOOGLE_DCHECK_EQ
#define ROUGHTIME_DCHECK_NE GOOGLE_DCHECK_NE
#define ROUGHTIME_DCHECK_LT GOOGLE_DCHECK_LT
#define ROUGHTIME_DCHECK_LE GOOGLE_DCHECK_LE
#define ROUGHTIME_DCHECK_GT GOOGLE_DCHECK_GT
#define ROUGHTIME_DCHECK_GE GOOGLE_DCHECK_GE
#define ROUGHTIME_INIT_LOGGER(a)
#endif

#endif
