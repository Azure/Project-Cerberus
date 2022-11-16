// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include "platform_api.h"
#include "status/rot_status.h"


int platform_semaphore_init (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem = 0;
	return 0;
}

void platform_semaphore_free (platform_semaphore *sem)
{
	UNUSED (sem);
}

int platform_semaphore_post (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem += 1;
	return 0;
}

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

int platform_semaphore_try_wait (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	return !(*sem);
}

int platform_semaphore_reset (platform_semaphore *sem)
{
	if (sem == NULL) {
		return PLATFORM_SEMAPHORE_ERROR (PLATFORM_INVALID_ARGUMENT);
	}

	*sem = 0;
	return 0;
}
