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
 * Variable context for a log that stores data in volatile memory.
 */
struct logging_memory_state {
	platform_mutex lock;				/**< Synchronization for log accesses. */
	size_t log_start;					/**< The first entry of the log. */
	size_t log_end;						/**< The end of the log where new entries will be added. */
	uint32_t next_entry_id;				/**< Next ID to assign to a log entry. */
	bool is_full;						/**< Flag indicating when the log is full. */
};

/**
 * A log that will store entries in volatile memory.
 */
struct logging_memory {
	struct logging base;				/**< The base logging instance. */
	struct logging_memory_state *state;	/**< Variable context for the log instance. */
	uint8_t *log_buffer;				/**< The buffer used for log entries. */
	size_t log_size;					/**< The size of the log buffer. */
	size_t entry_size;					/**< The length of a single log entry. */
	bool alloc_buffer;					/**< Flag indicating if the buffer was allocated by the log. */
};


int logging_memory_init (struct logging_memory *logging, struct logging_memory_state *state,
	size_t entry_count, size_t entry_length);
int logging_memory_init_from_buffer (struct logging_memory *logging,
	struct logging_memory_state *state, uint8_t *log_buffer, size_t log_size, size_t entry_length);
int logging_memory_init_append_existing (struct logging_memory *logging,
	struct logging_memory_state *state, uint8_t *log_buffer, size_t log_size, size_t entry_length);

int logging_memory_init_dynamic_state (struct logging_memory *logging);
int logging_memory_init_state (const struct logging_memory *logging);
int logging_memory_init_state_append_existing (const struct logging_memory *logging);

void logging_memory_release (struct logging_memory *logging);


#endif /* LOGGING_MEMORY_H_ */
