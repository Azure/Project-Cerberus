// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_logging.h"
#include "firmware_update_handler.h"
#include "common/type_cast.h"


void firmware_update_handler_status_change (const struct firmware_update_notification *context,
	enum firmware_update_status status)
{
	const struct firmware_update_handler *handler = TO_DERIVED_TYPE (context,
		const struct firmware_update_handler, base_notify);

	handler->task->lock (handler->task);
	handler->state->update_status = status;
	handler->task->unlock (handler->task);
}

/**
 * Notify the updater task that a firmware update event needs to be processed.
 *
 * @param handler The handler that received the event.
 * @param action The firmware update action that needs to be performed.
 * @param data Data associated with the update event.  Null if there is no data.
 * @param length Length of the event data.
 *
 * @return 0 if the update task was notified successfully or an error code.
 */
static int firmware_update_handler_submit_event (const struct firmware_update_handler *handler,
	uint32_t action, const uint8_t *data, size_t length)
{
	int status;

	status = event_task_submit_event (handler->task, &handler->base_event, action, data, length,
		UPDATE_STATUS_STARTING, &handler->state->update_status);
	if (status != 0) {
		if (status == EVENT_TASK_BUSY) {
			/* Do not change the update status when the task is busy.  Something is running, which
			 * could be using the update status. */
			status = FIRMWARE_UPDATE_TASK_BUSY;
		}
		else if (status == EVENT_TASK_TOO_MUCH_DATA) {
			/* Do not change the command status, since we don't know that state of the task. */
			return FIRMWARE_UPDATE_TOO_MUCH_DATA;
		}
		else if (status == EVENT_TASK_NO_TASK) {
			handler->state->update_status = UPDATE_STATUS_TASK_NOT_RUNNING;
			status = FIRMWARE_UPDATE_NO_TASK;
		}
		else {
			firmware_update_handler_status_change (&handler->base_notify,
				UPDATE_STATUS_START_FAILURE);
		}
	}

	return status;
}

int firmware_update_handler_start_update (const struct firmware_update_control *update)
{
	const struct firmware_update_handler *handler = TO_DERIVED_TYPE (update,
		const struct firmware_update_handler, base_ctrl);

	if (handler == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return firmware_update_handler_submit_event (handler, FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE,
		NULL, 0);
}

int firmware_update_handler_get_status (const struct firmware_update_control *update)
{
	const struct firmware_update_handler *handler = TO_DERIVED_TYPE (update,
		const struct firmware_update_handler, base_ctrl);
	int status;

	if (handler == NULL) {
		return UPDATE_STATUS_UNKNOWN;
	}

	handler->task->lock (handler->task);
	status = handler->state->update_status;
	handler->task->unlock (handler->task);

	return status;
}

int32_t firmware_update_handler_get_remaining_len (const struct firmware_update_control *update)
{
	const struct firmware_update_handler *handler = TO_DERIVED_TYPE (update,
		const struct firmware_update_handler, base_ctrl);
	int32_t bytes;

	if (handler == NULL) {
		return 0;
	}

	handler->task->lock (handler->task);
	bytes = firmware_update_get_update_remaining (handler->updater);
	handler->task->unlock (handler->task);

	return bytes;
}

int firmware_update_handler_prepare_staging (const struct firmware_update_control *update,
	size_t size)
{
	const struct firmware_update_handler *handler = TO_DERIVED_TYPE (update,
		const struct firmware_update_handler, base_ctrl);

	if (handler == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return firmware_update_handler_submit_event (handler,
		FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING, (uint8_t*) &size, sizeof (size));
}

int firmware_update_handler_write_staging (const struct firmware_update_control *update,
	uint8_t *buf, size_t buf_len)
{
	const struct firmware_update_handler *handler = TO_DERIVED_TYPE (update,
		const struct firmware_update_handler, base_ctrl);

	if ((handler == NULL) || (buf == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return firmware_update_handler_submit_event (handler,
		FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING, buf, buf_len);
}

/**
 * Prepare the updater state and flash to correctly handle firmware update commands.  In the case of
 * recovery boot, this ensures that the active image gets restored.  Otherwise, the recovery image
 * is validated to make sure it is good.
 *
 * @param fw The handler to prepare for updates.
 */
void firmware_update_handler_prepare_for_updates (const struct firmware_update_handler *fw)
{
	int status;

	if (fw->state->recovery_boot) {
		/* The system is running from the recovery image, so mark that image as good and restore the
		 * active image to a functional state. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_ACTIVE_RESTORE_START, 0, 0);

		firmware_update_set_recovery_good (fw->updater, true);
		status = firmware_update_restore_active_image (fw->updater);

		debug_log_create_entry ((status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_ERROR,
			DEBUG_LOG_COMPONENT_CERBERUS_FW, FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE, status, 0);
	}
	else {
		/* Check the current state of the recovery image. */
		if (firmware_update_is_recovery_good (fw->updater)) {
			if (fw->force_recovery_update) {
				status = firmware_update_recovery_matches_active_image (fw->updater);
				if (status != 0) {
					firmware_update_set_recovery_good (fw->updater, false);
				}

				debug_log_create_entry (
					(status == 0) ? DEBUG_LOG_SEVERITY_INFO : DEBUG_LOG_SEVERITY_WARNING,
					DEBUG_LOG_COMPONENT_CERBERUS_FW, FIRMWARE_LOGGING_RECOVERY_IMAGE, (status != 0),
					status);
			}
			else {
				firmware_update_validate_recovery_image (fw->updater);
			}
		}
	}
}

void firmware_update_handler_prepare (const struct event_task_handler *handler)
{
	const struct firmware_update_handler *fw = TO_DERIVED_TYPE (handler,
		const struct firmware_update_handler, base_event);

	firmware_update_handler_prepare_for_updates (fw);

	if (!fw->state->recovery_boot) {
		/* Ensure the recovery image is in a good state. */
		firmware_update_restore_recovery_image (fw->updater);
	}
}

void firmware_update_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct firmware_update_handler *fw = TO_DERIVED_TYPE (handler,
		const struct firmware_update_handler, base_event);
	int status;
	bool unknown_action = false;

	switch (context->action) {
		case FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_UPDATE_START, 0, 0);

			status = fw->run_update (fw->updater, &fw->base_notify);
			if (status == 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_UPDATE_COMPLETE, 0, 0);

#ifndef FIRMWARE_UPDATE_DISABLE_SELF_RESET
				*reset = true;
#endif
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_UPDATE_FAIL, fw->state->update_status, status);
			}

			debug_log_flush ();
			break;

		case FIRMWARE_UPDATE_HANDLER_ACTION_PREP_STAGING:
			status = firmware_update_prepare_staging (fw->updater, &fw->base_notify,
				*((size_t*) context->event_buffer));
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_ERASE_FAIL, fw->state->update_status, status);
			}
			break;

		case FIRMWARE_UPDATE_HANDLER_ACTION_WRITE_STAGING:
			status = firmware_update_write_to_staging (fw->updater, &fw->base_notify,
				context->event_buffer, context->buffer_length);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_WRITE_FAIL, fw->state->update_status, status);
			}
			break;

		default:
			unknown_action = true;
			break;
	}

	if (!unknown_action) {
		fw->task->lock (fw->task);
		if (status == 0) {
			fw->state->update_status = 0;
		}
		else {
			fw->state->update_status |= (status << 8);
		}
		fw->task->unlock (fw->task);
	}
}

/**
 * Initialize a handler for firmware update commands.
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
int firmware_update_handler_init (struct firmware_update_handler *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery)
{
	if ((handler == NULL) || (state == NULL) || (updater == NULL) || (task == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct firmware_update_handler));

	handler->base_ctrl.start_update = firmware_update_handler_start_update;
	handler->base_ctrl.get_status = firmware_update_handler_get_status;
	handler->base_ctrl.get_remaining_len = firmware_update_handler_get_remaining_len;
	handler->base_ctrl.prepare_staging = firmware_update_handler_prepare_staging;
	handler->base_ctrl.write_staging = firmware_update_handler_write_staging;

	handler->base_notify.status_change = firmware_update_handler_status_change;

	handler->base_event.prepare = firmware_update_handler_prepare;
	handler->base_event.execute = firmware_update_handler_execute;

	handler->state = state;
	handler->updater = updater;
	handler->task = task;
	handler->run_update = firmware_update_run_update;

	return firmware_update_handler_init_state (handler, running_recovery);
}

/**
 * Initialize a handler for firmware update commands.  During initialization, the updater will
 * ensure the recovery image will always match the current active image.
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
int firmware_update_handler_init_keep_recovery_updated (struct firmware_update_handler *handler,
	struct firmware_update_handler_state *state, const struct firmware_update *updater,
	const struct event_task *task, bool running_recovery)
{
	int status;

	status = firmware_update_handler_init (handler, state, updater, task, running_recovery);
	if (status == 0) {
		handler->force_recovery_update = true;
	}

	return status;
}

/**
 * Initialize only the variable state for a firmware update handler.  The rest of the handler is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The update handler that contains the state to initialize.
 * @param running_recovery Flag to indicate that the system has booted the image located in recovery
 * flash.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int firmware_update_handler_init_state (const struct firmware_update_handler *handler,
	bool running_recovery)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->updater == NULL) ||
		(handler->task == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (struct firmware_update_handler_state));

	handler->state->update_status = UPDATE_STATUS_NONE_STARTED;
	handler->state->recovery_boot = running_recovery;

	return 0;
}

/**
 * Release the resources used by a firmware update handler.
 *
 * @param handler The update handler to release.
 */
void firmware_update_handler_release (const struct firmware_update_handler *handler)
{

}
