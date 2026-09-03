// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "shared_buffer_static.h"
#include "common/unused.h"


int shared_buffer_get_buffer_size (const struct shared_buffer_interface *buffer, size_t *size)
{
	const struct shared_buffer *shared = (const struct shared_buffer*) buffer;

	if ((shared == NULL) || (size == NULL)) {
		return SHARED_BUFFER_INVALID_ARGUMENT;
	}

	*size = shared->buffer_size;

	return 0;
}

int shared_buffer_lock (const struct shared_buffer_interface *buffer,
	struct shared_buffer_handle *handle)
{
	const struct shared_buffer *shared = (const struct shared_buffer*) buffer;

	if ((shared == NULL) || (handle == NULL)) {
		return SHARED_BUFFER_INVALID_ARGUMENT;
	}

	if (shared->state->held) {
		return SHARED_BUFFER_BUSY;
	}

	shared->state->held = true;
	shared->state->current_owner = shared->state->next_owner++;

	/* On wraparound skip 0 so it stays reserved as the "no owner" tag and a zeroed handle can never
	 * match a live holder. */
	if (shared->state->next_owner == 0) {
		shared->state->next_owner = 1;
	}

	handle->ptr = shared->buffer;
	handle->size = shared->buffer_size;
	handle->owner = shared->state->current_owner;

	return 0;
}

int shared_buffer_unlock (const struct shared_buffer_interface *buffer,
	struct shared_buffer_handle *handle)
{
	const struct shared_buffer *shared = (const struct shared_buffer*) buffer;

	if ((shared == NULL) || (handle == NULL)) {
		return SHARED_BUFFER_INVALID_ARGUMENT;
	}

	if (!shared->state->held) {
		return SHARED_BUFFER_NOT_HELD;
	}

	if (handle->owner != shared->state->current_owner) {
		return SHARED_BUFFER_WRONG_OWNER;
	}

	shared->state->held = false;
	shared->state->current_owner = 0;

	/* Clear the handle so its stale region pointer can't be reused and a repeated unlock is
	 * rejected. */
	handle->ptr = NULL;
	handle->size = 0;
	handle->owner = 0;

	return 0;
}

/**
 * Initialize an ownership guard over a single, caller-provided buffer region.
 *
 * @param shared The shared buffer guard to initialize.
 * @param state Variable context for the guard.  This must be uninitialized.
 * @param buffer The buffer region to arbitrate.
 * @param buffer_size Size of the buffer region, in bytes.
 *
 * @return 0 if the guard was initialized successfully or an error code.
 */
int shared_buffer_init (struct shared_buffer *shared, struct shared_buffer_state *state,
	uint8_t *buffer, size_t buffer_size)
{
	if ((shared == NULL) || (state == NULL) || (buffer == NULL) || (buffer_size == 0)) {
		return SHARED_BUFFER_INVALID_ARGUMENT;
	}

	memset (shared, 0, sizeof (struct shared_buffer));

	shared->base.get_buffer_size = shared_buffer_get_buffer_size;
	shared->base.lock = shared_buffer_lock;
	shared->base.unlock = shared_buffer_unlock;

	shared->state = state;
	shared->buffer = buffer;
	shared->buffer_size = buffer_size;

	return shared_buffer_init_state (shared);
}

/**
 * Initialize only the variable context for a shared buffer ownership guard.  The rest of the guard
 * is assumed to already have been initialized.
 *
 * This is used to initialize the variable context of a guard that was created using
 * shared_buffer_static_init.
 *
 * @param shared The shared buffer guard whose state should be initialized.
 *
 * @return 0 if the state was initialized successfully or an error code.
 */
int shared_buffer_init_state (const struct shared_buffer *shared)
{
	if ((shared == NULL) || (shared->state == NULL) || (shared->buffer == NULL) ||
		(shared->buffer_size == 0)) {
		return SHARED_BUFFER_INVALID_ARGUMENT;
	}

	memset (shared->state, 0, sizeof (struct shared_buffer_state));

	/* Owner tags start at 1 so that 0 is always reserved as the "no owner" tag. */
	shared->state->next_owner = 1;

	return 0;
}

/**
 * Release the resources used by a shared buffer ownership guard.
 *
 * @param shared The shared buffer guard to release.
 */
void shared_buffer_release (const struct shared_buffer *shared)
{
	UNUSED (shared);
}
