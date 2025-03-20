// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_H_
#define PLATFORM_H_

#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <arpa/inet.h>


/* Use the stdlib calls for malloc/free. */
#define	platform_malloc		malloc
#define	platform_calloc		calloc
#define	platform_realloc	realloc
#define	platform_free		free


/* Use the Linux APIs for byte swapping. */
#define	platform_htonll		htobe64
#define	platform_ntohll		be64toh
#define	platform_htonl		htonl
#define	platform_ntohl		ntohl
#define	platform_htons		htons
#define	platform_ntohs		ntohs


/* Use timespec for timeouts. */
typedef struct timespec platform_clock;


/* Use pthread for mutex. */
typedef pthread_mutex_t platform_mutex;

/* free/lock/unlock are the same calls for recursive mutexes. */
#define	platform_recursive_mutex_free(x)		platform_mutex_free (x)
#define	platform_recursive_mutex_lock(x)		platform_mutex_lock (x)
#define	platform_recursive_mutex_unlock(x)		platform_mutex_unlock (x)


/**
 * Container for managing a timer using a pthread thread.
 */
typedef struct {
	sem_t timer;
	pthread_mutex_t lock;
	volatile uint8_t disarm;
	volatile uint8_t destroy;
	pthread_t thread;
	struct timespec timeout;
	timer_callback callback;
	void *context;
} platform_timer;


/* Use Linux semaphore implementation. */
typedef sem_t platform_semaphore;

#define	platform_semaphore_post_from_isr		platform_semaphore_post


#endif /* PLATFORM_H_ */
