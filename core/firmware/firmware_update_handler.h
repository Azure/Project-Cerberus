// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_HANDLER_H_
#define FIRMWARE_UPDATE_HANDLER_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "firmware_update_control.h"
#include "cmd_interface/cerberus_protocol.h"
#include "system/event_task.h"
#include "system/system.h"


/**
 * Action identifiers for the firmware update handler.
 */
enum {
	FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE = 1,		/**< Apply a firmware update. */
	FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING = 2,	/**< Prepare the staging flash to receive an update. */
	FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING = 4,	/**< Write image data into staging flash. */
};

/**
 * Variable context for the firmware update handler.
 */
struct firmware_update_handler_state {
	int update_status;	/**< The last firmware update status. */
	bool recovery_boot;	/**< Flag indicating the system has booted the recovery image. */
};

/**
 * Handler for firmware update requests.  The update operations will be run on a separate task from
 * the one interfacing with the control interface.
 */
struct firmware_update_handler {
	struct firmware_update_control base_ctrl;			/**< The base control instance. */
	struct firmware_update_notification base_notify;	/**< The update notification interface. */
	struct event_task_handler base_event;				/**< The task event handler interface. */
	struct firmware_update_handler_state *state;		/**< Variable context for the handler. */
	const struct firmware_update *updater;				/**< The firmware updater. */
	const struct event_task *task;						/**< Task to handle firmware update events. */
	bool force_recovery_update;							/**< Flag to force recovery update on initialization. */

	/**
	 * Internal reference to the function that will be used to execute a firmware update.
	 *
	 * This follows the signature of the firmware updater interface functions.
	 */
	int (*run_update) (const struct firmware_update *updater,
		const struct firmware_update_notification *callback);
};


int firmware_update_handler_init (struct firmware_update_handler *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery);
int firmware_update_handler_init_keep_recovery_updated (struct firmware_update_handler *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery);
int firmware_update_handler_init_state (const struct firmware_update_handler *handler,
	bool running_recovery);
void firmware_update_handler_release (const struct firmware_update_handler *handler);

/* Internal functions for use by derived types. */
int firmware_update_handler_start_update (const struct firmware_update_control *update);
int firmware_update_handler_get_status (const struct firmware_update_control *update);
int32_t firmware_update_handler_get_remaining_len (const struct firmware_update_control *update);
int firmware_update_handler_prepare_staging (const struct firmware_update_control *update,
	size_t size);
int firmware_update_handler_write_staging (const struct firmware_update_control *update,
	uint8_t *buf, size_t buf_len);

void firmware_update_handler_status_change (const struct firmware_update_notification *context,
	enum firmware_update_status status);

void firmware_update_handler_prepare_for_updates (const struct firmware_update_handler *fw);
void firmware_update_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset);


/* This module will be treated as an extension of the firmware updater and use FIRMWARE_UPDATE_*
 * error codes. */


#endif	/* FIRMWARE_UPDATE_HANDLER_H_ */
