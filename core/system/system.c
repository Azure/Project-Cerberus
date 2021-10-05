// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "system.h"
#include "system_logging.h"


/**
 * Initialize the main system manager.
 *
 * @param system The system manager to initialize.
 * @param device Interface to the device hardware.
 *
 * @return 0 if the manager was successfully initialized or an error code.
 */
int system_init (struct system *system, struct cmd_device *device)
{
	if ((system == NULL) || (device == NULL)) {
		return SYSTEM_INVALID_ARGUMENT;
	}

	memset (system, 0, sizeof (struct system));

	system->device = device;

	return observable_init (&system->observable);
}

/**
 * Release the resources used for system management.
 *
 * @param system The system manager to release.
 */
void system_release (struct system *system)
{
	if (system) {
		observable_release (&system->observable);
	}
}

/**
 * Add an observer for system notifications.
 *
 * @param system The system instance to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int system_add_observer (struct system *system, struct system_observer *observer)
{
	if (system == NULL) {
		return SYSTEM_INVALID_ARGUMENT;
	}

	return observable_add_observer (&system->observable, observer);
}

/**
 * Remove an observer from system notifications.
 *
 * @param system The system instance to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int system_remove_observer (struct system *system, struct system_observer *observer)
{
	if (system == NULL) {
		return SYSTEM_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&system->observable, observer);
}

/**
 * Reset the device.  This function will not return if able to successfully trigger the reset.
 *
 * @param system The system manger that will execute the device reset.
 */
void system_reset (struct system *system)
{
	int status;

	if (system) {
		/* Notify other components of the reset and provide an opportunity to gracefully halt. */
		observable_notify_observers (&system->observable,
			offsetof (struct system_observer, on_shutdown));

		debug_log_flush ();
		status = system->device->reset (system->device);

		/* If we get here, the reset has failed. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_RESET_FAIL, status, 0);
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_RESET_NOT_EXECUTED, SYSTEM_INVALID_ARGUMENT, 0);
	}
}
