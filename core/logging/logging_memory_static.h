// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef LOGGING_MEMORY_STATIC_H_
#define LOGGING_MEMORY_STATIC_H_

#include "logging/logging_memory.h"


/* Internal functions declared to allow for static initialization. */
int logging_memory_create_entry (const struct logging *logging, uint8_t *entry, size_t length);
int logging_memory_flush (const struct logging *logging);
int logging_memory_clear (const struct logging *logging);
int logging_memory_get_size (const struct logging *logging);
int logging_memory_read_contents (const struct logging *logging, uint32_t offset, uint8_t *contents,
	size_t length);


/**
 * Constant initializer for the the flush operation.
 */
#ifndef LOGGING_DISABLE_FLUSH
#define	LOGGING_MEMORY_FLUSH_API	.flush = logging_memory_flush,
#else
#define	LOGGING_MEMORY_FLUSH_API
#endif

/**
 * Constant initializer for the logging API.
 */
#define	LOGGING_MEMORY_API_INIT  { \
		.create_entry = logging_memory_create_entry, \
		LOGGING_MEMORY_FLUSH_API \
		.clear = logging_memory_clear, \
		.get_size = logging_memory_get_size, \
		.read_contents = logging_memory_read_contents \
	}


/**
 * Initialize a static instance of a log that uses volatile memory.  Since the buffer is also
 * static, this can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the log.
 * @param buffer_ptr The buffer to use for log entries.
 * @param buffer_len Length of the provided log buffer.
 * @param entry_len The length of a single log entry.  This does not include the length of standard
 * logging overhead.
 */
#define	logging_memory_static_init(state_ptr, buffer_ptr, buffer_len, entry_len)	{ \
		.base = LOGGING_MEMORY_API_INIT, \
		.state = state_ptr, \
		.log_buffer = buffer_ptr, \
		.log_size = buffer_len, \
		.entry_size = entry_len + sizeof (struct logging_entry_header), \
		.alloc_buffer = false \
	}

/**
 * Initialize a static instance of a log that uses volatile memory.  The buffer will be dynamically
 * allocated when the state is initialized, so this cannot be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state Variable context for the log.
 * @param entry_count The maximum number of entries the log should be able to hold.
 * @param entry_len The length of a single log entry.  This does not include the length of standard
 * logging overhead.
 */
#define	logging_memory_dynamic_buffer_static_init(state_ptr, entry_cnt, entry_len)	{ \
		.base = LOGGING_MEMORY_API_INIT, \
		.state = state_ptr, \
		.log_buffer = NULL, \
		.log_size = (entry_len + sizeof (struct logging_entry_header)) * entry_cnt, \
		.entry_size = entry_len + sizeof (struct logging_entry_header), \
		.alloc_buffer = true \
	}


#endif /* LOGGING_MEMORY_STATIC_H_ */
