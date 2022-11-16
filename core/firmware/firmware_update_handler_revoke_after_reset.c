// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_logging.h"
#include "firmware_update_handler_revoke_after_reset.h"
#include "common/type_cast.h"


void firmware_update_handler_revoke_after_reset_prepare (const struct event_task_handler *handler)
{
	const struct firmware_update_handler *fw = TO_DERIVED_TYPE (handler,
		const struct firmware_update_handler, base_event);
	int status;

	firmware_update_handler_prepare_for_updates (fw);

	if (!fw->state->recovery_boot) {
		status = firmware_update_run_revocation (fw->updater, &fw->base_notify);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_REVOCATION_FAIL, fw->state->update_status, status);
		}

		firmware_update_handler_status_change (&fw->base_notify, UPDATE_STATUS_NONE_STARTED);
	}
}

/**
 * Initialize a handler for firmware update commands.  The updater will treat firmware image update
 * and image revocation as separate steps.  Any revocation, along with all recovery updates, will
 * happen after running the updated firmware image.
 *
 * @param handler The update handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param updater The firmware updater that will be used by the handler.
 * @param task The task that will be used to execute firmware update operations.
 * @param running_recovery Flag to indicate that the system has booted the image located in recovery
 * flash.
 *
 * @return 0 if the update handler was successfully initialized or an error code.
 */
int firmware_update_handler_revoke_after_reset_init (
	struct firmware_update_handler_revoke_after_reset *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery)
{
	if ((handler == NULL) || (state == NULL) || (updater == NULL) || (task == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct firmware_update_handler_revoke_after_reset));

	handler->base.base_ctrl.start_update = firmware_update_handler_start_update;
	handler->base.base_ctrl.get_status = firmware_update_handler_get_status;
	handler->base.base_ctrl.get_remaining_len = firmware_update_handler_get_remaining_len;
	handler->base.base_ctrl.prepare_staging = firmware_update_handler_prepare_staging;
	handler->base.base_ctrl.write_staging = firmware_update_handler_write_staging;

	handler->base.base_notify.status_change = firmware_update_handler_status_change;

	handler->base.base_event.prepare = firmware_update_handler_revoke_after_reset_prepare;
	handler->base.base_event.execute = firmware_update_handler_execute;

	handler->base.state = state;
	handler->base.updater = updater;
	handler->base.task = task;
	handler->base.run_update = firmware_update_run_update_no_revocation;

	return firmware_update_handler_init_state (&handler->base, running_recovery);
}

/**
 * Initialize a handler for firmware update commands.  The updater will treat firmware image update
 * and image revocation as separate steps.  Any revocation, along with all recovery updates, will
 * happen after running the updated firmware image.  In addition, the updater will ensure the
 * recovery image will always match the current active image.
 *
 * @param handler The update handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param updater The firmware updater that will be used by the handler.
 * @param task The task that will be used to execute firmware update operations.
 * @param recovery_boot Flag to indicate that the system has booted the image located in recovery
 * flash.
 *
 * @return 0 if the update handler was successfully initialized or an error code.
 */
int firmware_update_handler_revoke_after_reset_init_keep_recovery_updated (
	struct firmware_update_handler_revoke_after_reset *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery)
{
	int status;

	status = firmware_update_handler_revoke_after_reset_init (handler, state, updater, task,
		running_recovery);
	if (status == 0) {
		handler->base.force_recovery_update = true;
	}

	return status;
}

/**
 * Release the resources used by a firmware update handler.
 *
 * @param handler The update handler to release.
 */
void firmware_update_handler_revoke_after_reset_release (
	const struct firmware_update_handler_revoke_after_reset *handler)
{

}
