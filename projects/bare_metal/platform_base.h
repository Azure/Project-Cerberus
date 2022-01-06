// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_BASE_H_
#define PLATFORM_BASE_H_

#include <stdlib.h>
#include <stdint.h>
#include "common/common_math.h"
#include "common/unused.h"


/* This file provides a basic set of platform abstractions for bare metal systems that don't
 * require any hardware knowledge. */

/* Memory management. */
#define	platform_malloc		malloc
#define	platform_calloc		calloc
#define	platform_realloc	realloc
#define	platform_free		free


/* Internet operations.  Assumes a little endian CPU. */
#define	platform_htonl		SWAP_BYTES_UINT32
#define platform_htons		SWAP_BYTES_UINT16


/* platform_clock and system time functions depend on hardware features. */


/* Mutex.  Single-threaded environment without a need for synchronization. */
typedef int platform_mutex;
static inline int platform_mutex_init (platform_mutex *mutex)
{
	UNUSED (mutex);
	return 0;
}

static inline int platform_mutex_free (platform_mutex *mutex)
{
	UNUSED (mutex);
	return 0;
}

static inline int platform_mutex_lock (platform_mutex *mutex)
{
	UNUSED (mutex);
	return 0;
}

static inline int platform_mutex_unlock (platform_mutex *mutex)
{
	UNUSED (mutex);
	return 0;
}

/* Recursive mutex. */
#define	platform_recursive_mutex_init		platform_mutex_init
#define	platform_recursive_mutex_free		platform_mutex_free
#define	platform_recursive_mutex_lock		platform_mutex_lock
#define	platform_recursive_mutex_unlock		platform_mutex_unlock


/* platform_timer depends on hardware features. */


/* Semaphore. */
typedef int platform_semaphore;
int platform_semaphore_init (platform_semaphore *sem);
void platform_semaphore_free (platform_semaphore *sem);
int platform_semaphore_post (platform_semaphore *sem);
int platform_semaphore_wait (platform_semaphore *sem, uint32_t ms_timeout);
int platform_semaphore_try_wait (platform_semaphore *sem);
int platform_semaphore_reset (platform_semaphore *sem);


/* Error codes to use for bare metal platform API failures. */
#define	PLATFORM_INVALID_ARGUMENT		0
#define	PLATFORM_NO_MEMORY				1
#define	PLATFORM_FAILURE				2


#endif /* PLATFORM_BASE_H_ */
