// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_OBSERVER_H_
#define FIRMWARE_UPDATE_OBSERVER_H_


/**
 * Observer interface for handling firmware update events.
 */
struct firmware_update_observer {
	/**
	 * Notification that a firmware update is about to start.  Observers of this notification have
	 * the opportunity to cause the update process to fail if the system is not in a state where an
	 * update should be allowed.
	 *
	 * Arguments passed with the notification will never be null.
	 *
	 * @param observer The observer instance being notified.
	 * @param update_allowed Output to indicate if the update process should be allowed or not.
	 * This will initially be 0, but should be changed to an error code if the update should fail.
	 * If this value is not 0 upon being called, the value should not be changed by an observer and
	 * any notification processing may optionally be skipped.
	 */
	void (*on_update_start) (struct firmware_update_observer *observer, int *update_allowed);
};


#endif /* FIRMWARE_UPDATE_OBSERVER_H_ */
