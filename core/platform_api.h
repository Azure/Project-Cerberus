// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_API_H_
#define PLATFORM_API_H_

#include <stdlib.h>
#include <stdint.h>
#include "status/rot_status.h"


/* This file contains the platform abstraction API that can be used to decouple code from the
 * environment in which it will be run.  If the platform provides native functions that provide
 * exactly the required functionality (such as in stdlib), they can be mapped via a macro in the
 * platform.h file.  Otherwise, the platform port will need to provide a suitable implementation
 * of the function. */


/* The timer callback prototype needs to be defined prior to including platform.h since the platform
 * ports will need to use this type with the platform_timer definition. */

/**
 * Callback function prototype used when timers are executed.
 *
 * @param context Calling context to pass to the timer handler.
 */
typedef void (*timer_callback) (void *context);


/* Include specifics for the platform port. */
#include "platform.h"


/* Generic error codes that can be used for platform API failures. */
#define	PLATFORM_INVALID_ARGUMENT		0
#define	PLATFORM_NO_MEMORY				1
#define	PLATFORM_FAILURE				2
#define	PLATFORM_UNSUPPORTED			3


/*******************************
 * Memory management routines.
 *******************************/

#ifndef platform_malloc
/**
 * Dynamically allocate a block of memory.  Equivalent to the stdlib 'malloc' call.
 *
 * @param size The amount of memory to allocate.
 *
 * @return A pointer to the allocated block of memory or null if the memory could not be allocated.
 */
void* platform_malloc (size_t size);
#endif

#ifndef platform_calloc
/**
 * Dynamically allocate an array of memory and initialize the memory to zero.  Equivalent to the
 * stdlib 'calloc' call.
 *
 * @param nmemb The number of elements to allocate.
 * @param size The size of each element.
 *
 * @return A pointer to the allocated block of memory or null if the memory could not be allocated.
 */
void* platform_calloc (size_t nmemb, size_t size);
#endif

#ifndef platform_realloc
/**
 * Change the size of a previously allocated block of memory.  Equivalent to the stdlib 'realloc'
 * call.
 *
 * This function only exists to support the unit testing framework and should not be used in
 * production code.  It is not guaranteed that every platform can support this capability.
 *
 * @param ptr A pointer to the memory that should be resized.
 * @param size The new size of the allocated memory.
 *
 * @return A pointer to the allocated block of memory or null if the memory could not be resized.
 */
void* platform_realloc (void *ptr, size_t size);
#endif

#ifndef platform_free
/**
 * Free a previously allocated block of memory.  Equivalent to the stdlib 'free' call.
 *
 * @param ptr A pointer to the memory that should be freed.
 */
void free (void *ptr);
#endif


/**************************
 * Byte order conversion.
 **************************/

#ifndef platform_htonl
/**
 * Convert a 32-bit integer from host byte order to network byte order (big endian).
 *
 * @param hostlong Integer in host byte order.
 *
 * @return Integer in network byte order.
 */
uint32_t platform_htonl (uint32_t hostlong);
#endif

#ifndef platform_htons
/**
 * Convert a 16-bit integer from host byte order to network byte order (big endian).
 *
 * @param hostshort Integer in host byte order.
 *
 * @return Integer in network byte order.
 */
uint32_t platform_htons (uint32_t hostshort);
#endif


/*****************************
 * Sleep and system time.
 *****************************/

/**
 * Module defined for timeout and clock error codes.  The actual error codes will vary based on the
 * platform, but the error will be reported with the same module ID.
 */
#define	PLATFORM_TIMEOUT_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_TIMEOUT, code)


#ifndef PLATFORM_CLOCK_RESOLUTION
/**
 * The resolution of the clock implementation for the platform.  This is the minimum duration that
 * can be measured and is the minimum time that will be used for timeouts.
 *
 * If the platform doesn't override this value, it defaults to a 1 millisecond resolution.
 */
#define	PLATFORM_CLOCK_RESOLUTION			1
#endif


#ifndef platform_msleep
/**
 * Sleep for a specified number of milliseconds.
 *
 * It is guaranteed that at least the specified time will elapse before this functions returns, but
 * there are no guarantees about how close the specified this will happen.
 *
 * @param msec The number of milliseconds to sleep.
 */
void platform_msleep (uint32_t msec);
#endif

#ifndef platform_get_time
/**
 * Get the current system time.
 *
 * What this ultimately represents depends on what time source is available to the platform.  Some
 * possibilities include:
 * 		- A monotonic counter that runs from the time the system boots.
 * 		- A reading from an RTC.
 * 		- The current OS tick which is generally monotonic but could be subject to rollover.
 *
 * Due to the variability of time sources, this should only be used to get a single snapshot of the
 * current time.  No decisions should be made based on this time since it cannot be known what the
 * time really represents.
 *
 * This time should not be relied on for determining timeouts or execution durations.  There are
 * other APIs more appropriate for those use cases that account for any platform details.
 *
 * @return The current time, in milliseconds.
 */
uint64_t platform_get_time (void);
#endif


#ifndef platform_init_timeout
/**
 * Initialize a clock structure to represent the time at which a timeout expires.
 *
 * @param msec The number of milliseconds to use for the timeout.
 * @param timeout The timeout to initialize.
 *
 * @return 0 if the timeout was initialized successfully or an error code.
 */
int platform_init_timeout (uint32_t msec, platform_clock *timeout);
#endif

#ifndef platform_increase_timeout
/**
 * Increase the amount of time for an existing timeout.
 *
 * The clock structure must already have been initialized with {@link platform_init_timeout} to set
 * the original timeout.  Other usage results in undefined behavior.
 *
 * @param msec The number of milliseconds to increase the timeout expiration by.  This is not the
 * total timeout from when timeout was initialized.  It is just the increment to apply to the
 * existing timeout.
 * @param timeout The timeout to update.
 *
 * @return 0 if the timeout was updated successfully or an error code.
 */
int platform_increase_timeout (uint32_t msec, platform_clock *timeout);
#endif

#ifndef platform_has_timeout_expired
/**
 * Determine if the specified timeout has expired.
 *
 * This should only be used with clock structures initialized by {@link platform_init_timeout}.
 * Other usage results in undefined behavior.
 *
 * @param timeout The timeout to check.
 *
 * @return 1 if the timeout has expired, 0 if it has not, or an error code.
 */
int platform_has_timeout_expired (const platform_clock *timeout);
#endif

#ifndef platform_get_timeout_remaining
/**
 * Get the amount of time remaining before a timeout expires.
 *
 * This should only be used with clock structures initialized by {@link platform_init_timeout}.
 * Other usage results in undefined behavior.
 *
 * @param timeout The timeout to check.
 * @param msec Output for he number of milliseconds remaining until the timeout expires.  If the
 * timeout has already expired, this will be 0.
 *
 * @return 0 if the remaining time was successfully determined or an error code.
 */
int platform_get_timeout_remaining (const platform_clock *timeout, uint32_t *msec);
#endif


#ifndef platform_init_current_tick
/**
 * Initialize a clock structure to represent the current time in way that can be compared against.
 * This will use the same time source that used to manage timeouts, which could be different then
 * the representation of time returned by {@link platform_get_time}.
 *
 * @param currtime Output for the current system time.
 *
 * @return 0 if the current time was initialized successfully or an error code.
 */
int platform_init_current_tick (platform_clock *currtime);
#endif

#ifndef platform_get_duration
/**
 * Get the time that has elapsed between two clock instances.
 *
 * This is intended to measure small durations.  Very long durations may not be accurately
 * calculated due to value limitations and/or overflow.
 *
 * There are a few defined use-cases for this function:
 * 		1.  Calculating the elapsed time between two times, both of which have been initialized with
 * 			{@link platform_init_current_tick}.
 * 		2.  Determining how much time has elapsed since a timeout has expired.  This only works with
 * 			expired timeouts, and that argument must be the starting point for the calculation.
 * 		3.  Calculating the difference between the expiration times of two timeouts, both of which
 * 			have been initialized with {@link platform_init_timeout}.
 *
 * Using this function with any other combination of clock instances results in undefined behavior.
 * Checking unexpired timeouts must be done using {@link platform_has_timeout_expired} and
 * {@link platform_get_timeout_remaining}.
 *
 * In all cases the start time must be earlier than the end time.  Passing a clock instance with
 * start and end times swapped results in undefined behavior.
 *
 * @param start The start time for the time duration calculation.
 * @param end The end time for the time duration calculation.
 *
 * @return The elapsed time, in milliseconds.  If either clock is null, the elapsed time will be 0.
 */
uint32_t platform_get_duration (const platform_clock *start, const platform_clock *end);
#endif


/*************************
 * Mutex operations.
 *************************/

/**
 * Module defined for mutex error codes.  The actual error codes will vary based on the platform,
 * but the error will be reported with the same module ID.
 */
#define	PLATFORM_MUTEX_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_MUTEX, code)

#ifndef platform_mutex_init
/**
 * Initialize a mutex.
 *
 * This mutex may not support recursive locking.  If recursive locking is required,
 * {@link platform_recursive_mutex_init} must be used instead.
 *
 * @param mutex The mutex to initialize.
 *
 * @return 0 if the mutex was successfully initialized or an error code.
 */
int platform_mutex_init (platform_mutex *mutex);
#endif

#ifndef platform_mutex_free
/**
 * Free a mutex.
 *
 * This must only be called for mutex instances initalized with {@link platform_mutex_init}.
 *
 * @param mutex The mutex to free.
 *
 * @return 0 if the mutex was freed or an error code.
 */
int platform_mutex_free (platform_mutex *mutex);
#endif

#ifndef platform_mutex_lock
/**
 * Acquire the mutex lock.
 *
 * This must only be called for mutex instances initalized with {@link platform_mutex_init}.
 *
 * @param mutex The mutex to lock.
 *
 * @return 0 if the mutex was successfully locked or an error code.
 */
int platform_mutex_lock (platform_mutex *mutex);
#endif

#ifndef platform_mutex_unlock
/**
 * Release the mutex lock.
 *
 * This must only be called for mutex instances initalized with {@link platform_mutex_init}.
 *
 * @param mutex The mutex to unlock.
 *
 * @return 0 if the mutex was successfully unlocked or an error code.
 */
int platform_mutex_unlock (platform_mutex *mutex);
#endif


#ifndef platform_recursive_mutex_init
/**
 * Initialize a mutex that supports recursive locking.
 *
 * @param mutex The mutex to initialize.
 *
 * @return 0 if the mutex was successfully initialized or an error code.
 */
int platform_recursive_mutex_init (platform_mutex *mutex);
#endif

#ifndef platform_recursive_mutex_free
/**
 * Free a recursive mutex.
 *
 * This must only be called for mutex instances initalized with
 * {@link platform_recursive_mutex_init}.
 *
 * @param mutex The mutex to free.
 *
 * @return 0 if the mutex was freed or an error code.
 */
int platform_recursive_mutex_free (platform_mutex *mutex);
#endif

#ifndef platform_recursive_mutex_lock
/**
 * Acquire the recursive mutex lock.
 *
 * This must only be called for mutex instances initalized with
 * {@link platform_recursive_mutex_init}.
 *
 * @param mutex The mutex to lock.
 *
 * @return 0 if the mutex was successfully locked or an error code.
 */
int platform_recursive_mutex_lock (platform_mutex *mutex);
#endif

#ifndef platform_recursive_mutex_unlock
/**
 * Release the recursive mutex lock.  This must be called the same number of times as
 * {@link platform_recursive_mutex_lock} was called in order to fully release the lock.
 *
 * This must only be called for mutex instances initalized with
 * {@link platform_recursive_mutex_init}.
 *
 * @param mutex The mutex to unlock.
 *
 * @return 0 if the mutex was successfully unlocked or an error code.
 */
int platform_recursive_mutex_unlock (platform_mutex *mutex);
#endif


/***********************************
 * Timer scheduling and management
 ***********************************/

/**
 * Module defined for timer error codes.  The actual error codes will vary based on the platform,
 * but the error will be reported with the same module ID.
 */
#define	PLATFORM_TIMER_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_TIMER, code)

#ifndef platform_timer_create
/**
 * Create a timer that is not yet armed.
 *
 * @param timer The container for the created timer.
 * @param callback The function to call when the timer expires.
 * @param context The context to pass to the notification function.
 *
 * @return 0 if the timer was created or an error code.
 */
int platform_timer_create (platform_timer *timer, timer_callback callback, void *context);
#endif

#ifndef platform_timer_arm_one_shot
/**
 * Start a timer that will call the notification function once on expiration.  If additional
 * notifications are required, the timer must be rearmed.
 *
 * Calling this on an already armed timer will restart the timer with the specified timeout.
 *
 * @param timer The timer to start.
 * @param ms_timeout The timeout to wait for timer expiration, in milliseconds.
 *
 * @return 0 if the timer has started or an error code.
 */
int platform_timer_arm_one_shot (platform_timer *timer, uint32_t ms_timeout);
#endif

#ifndef platform_timer_disarm
/**
 * Stop a timer and prevent the notification from being called.  The timer instance remains valid
 * and can rearmed.
 *
 * @param timer The timer to stop.
 *
 * @return 0 if the timer is stopped or an error code.
 */
int platform_timer_disarm (platform_timer *timer);
#endif

#ifndef platform_timer_delete
/**
 * Stop a timer and prevent the notification from being called.  The timer instance will be deleted
 * and cannot be reused without calling {@link platform_timer_create}.
 *
 * A timer instance must never be deleted from within the context of the event callback.
 *
 * @param timer The timer to delete.
 */
void platform_timer_delete (platform_timer *timer);
#endif


/*************************
 * Semaphore operations
 *************************/

/**
 * Module defined for semaphore error codes.  The actual error codes will vary based on the
 * platform, but the error will be reported with the same module ID.
 */
#define	PLATFORM_SEMAPHORE_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_SEMAPHORE, code)

#ifndef platform_semaphore_init
/**
 * Initialize a semaphore.
 *
 * There are no assertions on what type of semaphore is created.  It could equally be a binary or
 * counting semaphore.  Semaphore usage should not be designed to require specific semaphore
 * capabilities beyond what the platform API provides.
 *
 * @param sem The semaphore to initialize.
 *
 * @return 0 if the semaphore was initialized successfully or an error code.
 */
int platform_semaphore_init (platform_semaphore *sem);
#endif

#ifndef platform_semaphore_free
/**
 * Free a semaphore.
 *
 * @param sem The semaphore to free.
 */
void platform_semaphore_free (platform_semaphore *sem);
#endif

#ifndef platform_semaphore_post
/**
 * Signal a semaphore from the context of a normal thread or task.
 *
 * Some platforms have different requirements for signaling semaphores from task vs. interrupt
 * context.  This call must only be used to signal semaphores from task context. Use
 * platform_semaphore_post_from_isr to signal from interrupt context.
 *
 * @param sem The semaphore to signal.
 *
 * @return 0 if the semaphore was signaled successfully or an error code.
 */
int platform_semaphore_post (platform_semaphore *sem);
#endif

#ifndef platform_semaphore_post_from_isr
/**
 * Signal a semaphore from the context of an interrupt service routine (ISR).
 *
 * Some platforms have different requirements for signaling semaphores from task vs. interrupt
 * context.  This call must only be used to signal semaphores from interrupt context. Use
 * platform_semaphore_post to signal from task context.
 *
 * @param sem The semaphore to signal.
 *
 * @return 0 if the semaphore was signaled successfully or an error code.
 */
int platform_semaphore_post_from_isr (platform_semaphore *sem);
#endif

#ifndef platform_semaphore_wait
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
int platform_semaphore_wait (platform_semaphore *sem, uint32_t ms_timeout);
#endif

#ifndef platform_semaphore_try_wait
/**
 * Check the state of the semaphore and return immediately.  If the semaphore was signaled, checking
 * the state will consume the signal.
 *
 * @param sem The semaphore to check.
 *
 * @return 0 if the semaphore was signaled, 1 if it was not, or an error code.
 */
int platform_semaphore_try_wait (platform_semaphore *sem);
#endif

#ifndef platform_semaphore_reset
/**
 * Reset a semaphore to the unsignaled state.
 *
 * @param sem The semaphore to reset.
 *
 * @return 0 if the semaphore was reset successfully or an error code.
 */
int platform_semaphore_reset (platform_semaphore *sem);
#endif


/*************************
 * Task and OS control
 *************************/

/**
 * Module defined for OS and task control error codes.  The actual error codes will vary based on
 * the platform, but the error will be reported with the same module ID.
 */
#define	PLATFORM_OS_ERROR(code)		ROT_ERROR (ROT_MODULE_PLATFORM_OS, code)

#ifndef platform_suspend_scheduler
/**
 * Suspend the OS scheduler to ensure no task context switches happen, leaving the currently running
 * task executing.  Depending on the platform, this may cause interrupts to be disabled.
 *
 * Every call must be paired with a call to platform_os_resume_scheduler to enable task switching
 * again.
 *
 * @return 0 if the OS task scheduler was suspended or an error code.
 */
int platform_os_suspend_scheduler (void);
#endif

#ifndef platform_resume_scheduler
/**
 * Resume the OS scheduler, enabling task context switching.  Depending on the platform, this may
 * immediately cause a context switch.
 *
 * @return 0 if the OS task scheduler was resumed or an error code.
 */
int platform_os_resume_scheduler (void);
#endif

#endif /* PLATFORM_API_H_ */
