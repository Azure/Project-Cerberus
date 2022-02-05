// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_H_
#define PLATFORM_H_

#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <semaphore.h>
#include <arpa/inet.h>


/* Linux memory management. */
#define	platform_malloc		malloc
#define	platform_calloc		calloc
#define	platform_realloc	realloc
#define	platform_free		free


/* Linux internet operations. */
#define	platform_htonl		htonl
#define	platform_htons		htons


/* Linux sleep and system time. */
void platform_msleep (uint32_t msec);

typedef struct timespec platform_clock;
int platform_init_timeout (uint32_t msec, platform_clock *timeout);
int platform_increase_timeout (uint32_t msec, platform_clock *timeout);
int platform_init_current_tick (platform_clock *currtime);
int platform_has_timeout_expired (platform_clock *timeout);
uint64_t platform_get_time (void);
uint32_t platform_get_duration (const platform_clock *start, const platform_clock *end);


/* Linux mutex. */
typedef pthread_mutex_t platform_mutex;
int platform_mutex_init (platform_mutex *mutex);
int platform_mutex_free (platform_mutex *mutex);
int platform_mutex_lock (platform_mutex *mutex);
int platform_mutex_unlock (platform_mutex *mutex);

/* Linux recursive mutex. */
int platform_recursive_mutex_init (platform_mutex *mutex);
#define	platform_recursive_mutex_free(x)		platform_mutex_free (x)
#define	platform_recursive_mutex_lock(x)		platform_mutex_lock (x)
#define	platform_recursive_mutex_unlock(x)		platform_mutex_unlock (x)


/* Linux timer. */
typedef void (*timer_callback) (void *context);
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

int platform_timer_create (platform_timer *timer, timer_callback callback, void *context);
int platform_timer_arm_one_shot (platform_timer *timer, uint32_t ms_timeout);
int platform_timer_disarm (platform_timer *timer);
void platform_timer_delete (platform_timer *timer);


/* Linux semaphore */
typedef sem_t platform_semaphore;
int platform_semaphore_init (platform_semaphore *sem);
void platform_semaphore_free (platform_semaphore *sem);
int platform_semaphore_post (platform_semaphore *sem);
int platform_semaphore_wait (platform_semaphore *sem, uint32_t ms_timeout);
int platform_semaphore_try_wait (platform_semaphore *sem);
int platform_semaphore_reset (platform_semaphore *sem);


#endif /* PLATFORM_H_ */
