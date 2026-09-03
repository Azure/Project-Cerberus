// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SHARED_BUFFER_H_
#define SHARED_BUFFER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "common/shared_buffer_interface.h"

/**
 * Variable context for a static shared buffer ownership guard.
 */
struct shared_buffer_state {
	bool held;					/**< Whether the buffer is currently held by a consumer. */
	uintptr_t current_owner;	/**< Owner tag issued to the current holder; 0 when free. */
	uintptr_t next_owner;		/**< Owner tag to issue on the next successful lock. */
};

/**
 * Ownership guard for a caller-provided buffer region. Not thread-safe; single-thread use only.
 */
struct shared_buffer {
	struct shared_buffer_interface base;	/**< Base shared buffer interface. */
	struct shared_buffer_state *state;		/**< Variable context for the guard. */
	uint8_t *buffer;						/**< The arbitrated buffer region. */
	size_t buffer_size;						/**< Size of the buffer region, in bytes. */
};


int shared_buffer_init (struct shared_buffer *shared, struct shared_buffer_state *state,
	uint8_t *buffer, size_t buffer_size);
int shared_buffer_init_state (const struct shared_buffer *shared);
void shared_buffer_release (const struct shared_buffer *shared);


#endif	/* SHARED_BUFFER_H_ */
