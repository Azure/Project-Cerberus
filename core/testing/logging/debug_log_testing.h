// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEBUG_LOG_TESTING_H_
#define DEBUG_LOG_TESTING_H_


// Since time field of a debug log entry is filled by the value returned from the OS function call,
// its value is not predictable from the test point of view, to exclude the time field from the
// ptr_contains validation, the size of time field is subtracted from the entry size.
#define LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED (sizeof (struct debug_log_entry_info) - sizeof (uint64_t))


#endif /* DEBUG_LOG_TESTING_H_ */
