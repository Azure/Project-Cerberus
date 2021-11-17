// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "platform_base.h"
#include "platform.h"
#include "status/rot_status.h"


#define	PLATFORM_SEMAPHORE_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_SEMAPHORE, code)

/**
 * Initialize a semaphore.
 *
 * @param sem The semaphore to initialize.
 *
 * @return 0 if the semaphore was initialized successfully or an error code.
 */
int platform_semaphore_init (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem = 0;
	return 0;
}

/**
 * Free a semaphore.
 *
 * @param sem The semaphore to free.
 */
void platform_semaphore_free (platform_semaphore *sem)
{
	UNUSED (sem);
}

/**
 * Signal a semaphore.
 *
 * @param sem The semaphore to signal.
 *
 * @return 0 if the semaphore was signaled successfully or an error code.
 */
int platform_semaphore_post (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem += 1;
	return 0;
}

/**
 * Wait for a semaphore to be signaled.  This will block until either the semaphore is signaled or
 * the timeout expires.  If the semaphore is already signaled, it will return immediately.
 *
 * @param sem The semaphore to wait on.
 * @param ms_timeout The amount of time to wait for the semaphore to be signaled, in milliseconds.
 * Specifying at timeout of 0 will cause the call to block indefinitely.
 *
 * @return 0 if the semaphore was signaled, 1 if the timeout expired, or an error code.
 */
int platform_semaphore_wait (platform_semaphore *sem, uint32_t ms_timeout)
{
	platform_clock timeout;
	int status;

	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	status = platform_init_timeout (ms_timeout, &timeout);
	if (status != 0) {
		return status;
	}

	while ((*sem == 0) && !platform_has_timeout_expired (&timeout));

	if (*sem != 0) {
		*sem -= 1;
		return 0;
	}
	else {
		return 1;
	}
}

/**
 * Check the state of the semaphore and return immediately.  If the semaphore was signaled, checking
 * the state will consume the signal.
 *
 * @param sem The semaphore to check.
 *
 * @return 0 if the semaphore was signaled, 1 if it was not, or an error code.
 */
int platform_semaphore_try_wait (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	return !(*sem);
}

/**
 * Reset a semaphore to the unsignaled state.
 *
 * @param sem The semaphore to reset.
 *
 * @return 0 if the semaphore was reset successfully or an error code.
 */
int platform_semaphore_reset (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem = 0;
	return 0;
}
