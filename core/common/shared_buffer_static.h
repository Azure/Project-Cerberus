// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SHARED_BUFFER_STATIC_H_
#define SHARED_BUFFER_STATIC_H_

#include <stddef.h>
#include <stdint.h>
#include "shared_buffer.h"


/* Internal functions declared to allow for static initialization. */
int shared_buffer_get_buffer_size (const struct shared_buffer_interface *buffer, size_t *size);
int shared_buffer_lock (const struct shared_buffer_interface *buffer,
	struct shared_buffer_handle *handle);
int shared_buffer_unlock (const struct shared_buffer_interface *buffer,
	struct shared_buffer_handle *handle);

/**
 * Constant initializer for the shared buffer API.
 */
#define	SHARED_BUFFER_STATIC_API_INIT  { \
		.get_buffer_size = shared_buffer_get_buffer_size, \
		.lock = shared_buffer_lock, \
		.unlock = shared_buffer_unlock, \
	}

/**
 * Initialize a static instance of a shared buffer ownership guard.  The variable context must still
 * be initialized with shared_buffer_init_state.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the guard.
 * @param buffer_ptr The buffer region to arbitrate.
 * @param buffer_size_arg Size of the buffer region, in bytes.
 */
#define	shared_buffer_static_init(state_ptr, buffer_ptr, buffer_size_arg)	{ \
		.base = SHARED_BUFFER_STATIC_API_INIT, \
		.state = state_ptr, \
		.buffer = buffer_ptr, \
		.buffer_size = buffer_size_arg, \
	}


#endif	/* SHARED_BUFFER_STATIC_H_ */
