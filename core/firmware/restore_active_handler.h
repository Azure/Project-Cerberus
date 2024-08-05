// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RESTORE_ACTIVE_HANDLER_H_
#define RESTORE_ACTIVE_HANDLER_H_

#include "firmware_update.h"
#include "system/event_task.h"


/**
 * Action identifiers for the firmware update handler.
 */
enum {
	RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE = 1,	/**< Restore the active image from recovery. */
};


/**
 * Handler for run-time requests to restore the active boot region of flash from the recovery image.
 * This must be run within the same task context as the firmware update handling to ensure this
 * operation is synchronized with any ongoing firmware update requests.
 */
struct restore_active_handler {
	struct event_task_handler base;			/**< The task event handler interface. */
	const struct firmware_update *updater;	/**< The firmware updater. */
	const struct event_task *task;			/**< Task to handle firmware update events. */
};


int restore_active_handler_init (struct restore_active_handler *handler,
	const struct firmware_update *updater, const struct event_task *task);
void restore_active_handler_release (const struct restore_active_handler *handler);

int restore_active_handler_restore_from_recovery_flash (
	const struct restore_active_handler *handler);
void restore_active_handler_restore_from_recovery_flash_and_log_error (
	const struct restore_active_handler *handler);

void restore_active_handler_log_start_restore_error (int error_code);


/* This module will be treated as an extension of the firmware updater and use FIRMWARE_UPDATE_*
 * error codes. */


#endif	/* RESTORE_ACTIVE_HANDLER_H_ */
