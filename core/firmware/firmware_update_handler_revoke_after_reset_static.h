// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_STATIC_H_
#define FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_STATIC_H_

#include "firmware_update_handler_revoke_after_reset.h"
#include "firmware_update_handler_static.h"


/* Internal functions declared to allow for static initialization. */
void firmware_update_handler_revoke_after_reset_prepare (const struct event_task_handler *handler);


/**
 * Constant initializer for the firmware update task API.
 */
#define	FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_EVENT_API_INIT  { \
		.prepare = firmware_update_handler_revoke_after_reset_prepare, \
		.execute = firmware_update_handler_execute \
	}


/**
 * Initialize a static instance of a firmware update handler.  The updater will treat firmware image
 * update and image revocation as separate steps.  Any revocation, along with all recovery updates,
 * will happen after running the updated firmware image.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the update handler.
 * @param updater_ptr The firmware updater that will be used by the handler.
 * @param task_ptr The task that will be used to execute firmware update operations.
 */
#define	firmware_update_handler_revoke_after_reset_static_init(state_ptr, updater_ptr, \
	task_ptr)	{ \
		.base = { \
			.base_ctrl = FIRMWARE_UPDATE_HANDLER_CONTROL_API_INIT, \
			.base_notify = FIRMWARE_UPDATE_HANDLER_NOTIFICATION_API_INIT, \
			.base_event = FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_EVENT_API_INIT, \
			.state = state_ptr, \
			.updater = updater_ptr, \
			.task = task_ptr, \
			.force_recovery_update = false, \
			.run_update = firmware_update_run_update_no_revocation \
		} \
	}

/**
 * Initialize a static instance of a firmware update handler.  The updater will treat firmware image
 * update and image revocation as separate steps.  Any revocation, along with all recovery updates,
 * will happen after running the updated firmware image.  In addition, the updater will ensure the
 * recovery image will always match the current active image.
 *
 * This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the update handler.
 * @param updater_ptr The firmware updater that will be used by the handler.
 * @param task_ptr The task that will be used to execute firmware update operations.
 */
#define	firmware_update_handler_revoke_after_reset_static_init_keep_recovery_updated(state_ptr, \
	updater_ptr, task_ptr)	{ \
		.base = { \
			.base_ctrl = FIRMWARE_UPDATE_HANDLER_CONTROL_API_INIT, \
			.base_notify = FIRMWARE_UPDATE_HANDLER_NOTIFICATION_API_INIT, \
			.base_event = FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_EVENT_API_INIT, \
			.state = state_ptr, \
			.updater = updater_ptr, \
			.task = task_ptr, \
			.force_recovery_update = true, \
			.run_update = firmware_update_run_update_no_revocation \
		} \
	}


#endif	/* FIRMWARE_UPDATE_HANDLER_REVOKE_AFTER_RESET_STATIC_H_ */
