// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOGGING_MEMORY_H_
#define LOGGING_MEMORY_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "logging.h"
#include "platform.h"


/**
 * A log that will store entries in volatile memory.
 */
struct logging_memory {
	struct logging base;			/**< The base logging instance. */
	uint8_t *log_buffer;			/**< The buffer used for log entries. */
	size_t log_size;				/**< The size of the log buffer. */
	platform_mutex lock;			/**< Synchronization for log accesses. */
	size_t entry_size;				/**< The length of a single log entry. */
	size_t log_start;				/**< The first entry of the log. */
	size_t log_end;					/**< The end of the log where new entries will be added. */
	uint32_t next_entry_id;			/**< Next ID to assign to a log entry. */
	bool alloc_buffer;				/**< Flag indicating if the buffer was allocated by the log. */
	bool is_full;					/**< Flag indicating when the log is full. */
};


int logging_memory_init (struct logging_memory *logging, size_t entry_count, size_t entry_length);
int logging_memory_init_from_buffer (struct logging_memory *logging, uint8_t *log_buffer,
	size_t log_size, size_t entry_length);
int logging_memory_init_append_existing (struct logging_memory *logging, uint8_t *log_buffer,
	size_t log_size, size_t entry_length);
void logging_memory_release (struct logging_memory *logging);


#endif /* LOGGING_MEMORY_H_ */
