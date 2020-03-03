// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "observable.h"


/**
 * Initialize a manager for observers.
 *
 * @param observable The observer manager to initialize.
 *
 * @return 0 if the observable was initialized successfully or an error code.
 */
int observable_init (struct observable *observable)
{
	int status;

	if (observable == NULL) {
		return OBSERVABLE_INVALID_ARGUMENT;
	}

	memset (observable, 0, sizeof (struct observable));

	status = platform_mutex_init (&observable->lock);
	if (status != 0) {
		return status;
	}

	return 0;
}

/**
 * Release the resources used by an observer manager.
 *
 * @param observable The observable to release.
 */
void observable_release (struct observable *observable)
{
	if (observable) {
		platform_mutex_free (&observable->lock);

		while (observable->observer_head) {
			struct observable_observer *temp = observable->observer_head;
			observable->observer_head = observable->observer_head->next;
			platform_free (temp);
		}
	}
}

/**
 * Add an observer to be notified of events.
 *
 * An observer will only be notified once for each event, regardless of the number of times it is
 * added.  The order in which observers are notified is not guaranteed to be the same as the order
 * in which they were added.
 *
 * @param observable The observable module to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was added for notifications or an error code.
 */
int observable_add_observer (struct observable *observable, void *observer)
{
	struct observable_observer *entry;
	struct observable_observer *pos;
	struct observable_observer *prev;

	if ((observable == NULL) || (observer == NULL)) {
		return OBSERVABLE_INVALID_ARGUMENT;
	}

	entry = platform_malloc (sizeof (struct observable_observer));
	if (entry == NULL) {
		return OBSERVABLE_NO_MEMORY;
	}

	entry->observer = observer;
	entry->next = NULL;

	platform_mutex_lock (&observable->lock);

	if (!observable->observer_head) {
		observable->observer_head = entry;
	}
	else {
		pos = observable->observer_head;
		while (pos) {
			if (observer == pos->observer) {
				platform_free (entry);
				break;
			}

			prev = pos;
			pos = pos->next;
		}

		if (!pos) {
			prev->next = entry;
		}
	}

	platform_mutex_unlock (&observable->lock);

	return 0;
}

/**
 * Remove an observer so it will no longer be notified of events.
 *
 * @param observable The observable module to update.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was removed from future notifications or an error code.
 */
int observable_remove_observer (struct observable *observable, void *observer)
{
	struct observable_observer *pos;
	struct observable_observer *prev;

	if ((observable == NULL) || (observer == NULL)) {
		return OBSERVABLE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&observable->lock);

	pos = observable->observer_head;
	prev = NULL;
	while (pos) {
		if (pos->observer == observer) {
			if (prev == NULL) {
				observable->observer_head = pos->next;
			}
			else {
				prev->next = pos->next;
			}

			platform_free (pos);
			break;
		}

		prev = pos;
		pos = pos->next;
	}

	platform_mutex_unlock (&observable->lock);

	return 0;
}

/**
 * Call the notification on each registered observer.
 *
 * @param observable The observable module generating the notification.
 * @param type Type of the notification function pointer.
 * @param notify Temporary function pointer to use for calling the observer notification handler.
 * @param ... Argument list to send to the notification function.  The first argument must always be
 * 'observer' to pass the observer instance.
 */
#define	FOR_EACH_OBSERVER(observable, type, notify, ...) \
	{ \
		struct observable_observer *pos; \
		\
		if (observable == NULL) { \
			return OBSERVABLE_INVALID_ARGUMENT; \
		} \
		\
		platform_mutex_lock (&observable->lock); \
		\
		pos = observable->observer_head; \
		while (pos) { \
			notify = (type) (*((uintptr_t*) ((uintptr_t) pos->observer + callback_offset))); \
			if (notify) { \
				notify (pos->__VA_ARGS__); \
			} \
			pos = pos->next; \
		} \
		\
		platform_mutex_unlock (&observable->lock); \
		\
		return 0; \
	}

/**
 * Notify all observers of an event.
 *
 * @param observable The observable module generating the event.
 * @param callback_offset The offset in the observer structure for the notification to call.  This
 * will be calculated using offsetof (struct <observer>, <notification member>).
 *
 * @return 0 if the observers were notified or an error code.
 */
int observable_notify_observers (struct observable *observable, size_t callback_offset)
{
	void (*notify) (void*);

	FOR_EACH_OBSERVER (observable, void (*) (void*), notify, observer);
}

/**
 * Notify all observers of an event.
 *
 * @param observable The observable module generating the event.
 * @param callback_offset The offset in the observer structure for the notification to call.  This
 * will be calculated using offsetof (<struct observer>, <notification member>).
 * @param arg The pointer argument to send with the notification.
 *
 * @return 0 if the observers were notified or an error code.
 */
int observable_notify_observers_with_ptr (struct observable *observable, size_t callback_offset,
	void *arg)
{
	void (*notify) (void*, void*);

	FOR_EACH_OBSERVER (observable, void (*) (void*, void*), notify, observer, arg);
}
