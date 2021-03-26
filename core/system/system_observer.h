// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_OBSERVER_H_
#define SYSTEM_OBSERVER_H_


/**
 * Interface for notifying observers of system events.  Unwanted event notifications will be set to
 * null.
 */
struct system_observer {
	/**
	 * Notification that the processor is about to reset.  Observers of this notification have the
	 * opportunity to delay reset until operations that are in progress have completed or to ensure
	 * persistent data has been saved.
	 *
	 * Arguments passed with the notification will never be null.
	 *
	 * @param observer The observer instance being notified.
	 */
	void (*on_shutdown) (struct system_observer *observer);
};


#endif /* SYSTEM_OBSERVER_H_ */
