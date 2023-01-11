// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "manifest_cmd_handler.h"
#include "manifest_logging.h"
#include "common/type_cast.h"


/**
 * Set the current manifest operation status.
 *
 * @param handler The command handler instance to update.
 * @param status The status value to set.
 */
void manifest_cmd_handler_set_status (const struct manifest_cmd_handler *handler, int status)
{
	handler->task->lock (handler->task);
	handler->state->status = status;
	handler->task->unlock (handler->task);
}

/**
 * Notify the task that a manifest event needs to be processed.
 *
 * @param handler The handler that received the event.
 * @param action The manifest action that needs to be performed.
 * @param data Data associated with the event.  Null if there is no data.
 * @param length Length of the event data.
 *
 * @return 0 if the task was notified successfully or an error code.
 */
static int manifest_cmd_handler_submit_event (const struct manifest_cmd_handler *handler,
	uint32_t action, const uint8_t *data, size_t length)
{
	int status;

	status = event_task_submit_event (handler->task, &handler->base_event, action, data, length,
		MANIFEST_CMD_STATUS_STARTING, &handler->state->status);
	if (status != 0) {
		if (status == EVENT_TASK_BUSY) {
			/* Do not change the command status when the task is busy.  Something is running, which
			 * could be using the status. */
			status = MANIFEST_MANAGER_TASK_BUSY;
		}
		else if (status == EVENT_TASK_TOO_MUCH_DATA) {
			/* Do not change the command status, since we don't know that state of the task. */
			return MANIFEST_MANAGER_TOO_MUCH_DATA;
		}
		else if (status == EVENT_TASK_NO_TASK) {
			handler->state->status = MANIFEST_CMD_STATUS_TASK_NOT_RUNNING;
			status = MANIFEST_MANAGER_NO_TASK;
		}
		else {
			manifest_cmd_handler_set_status (handler, MANIFEST_CMD_STATUS_INTERNAL_ERROR);
		}
	}

	return status;
}

int manifest_cmd_handler_prepare_manifest (struct manifest_cmd_interface *cmd,
	uint32_t manifest_size)
{
	const struct manifest_cmd_handler *handler = (const struct manifest_cmd_handler*) cmd;

	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_cmd_handler_submit_event (handler, MANIFEST_CMD_HANDLER_ACTION_PREPARE,
		(uint8_t*) &manifest_size, sizeof (manifest_size));
}

int manifest_cmd_handler_store_manifest (struct manifest_cmd_interface *cmd, const uint8_t *data,
	size_t length)
{
	const struct manifest_cmd_handler *handler = (const struct manifest_cmd_handler*) cmd;

	if ((handler == NULL) || (data == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_cmd_handler_submit_event (handler, MANIFEST_CMD_HANDLER_ACTION_STORE, data,
		length);
}

int manifest_cmd_handler_finish_manifest (struct manifest_cmd_interface *cmd, bool activate)
{
	const struct manifest_cmd_handler *handler = (const struct manifest_cmd_handler*) cmd;
	uint32_t action = MANIFEST_CMD_HANDLER_ACTION_FINALIZE;

	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (activate) {
		action |= MANIFEST_CMD_HANDLER_ACTION_ACTIVATE;
	}

	return manifest_cmd_handler_submit_event (handler, action, NULL, 0);
}

int manifest_cmd_handler_get_status (struct manifest_cmd_interface *cmd)
{
	const struct manifest_cmd_handler *handler = (const struct manifest_cmd_handler*) cmd;
	int status;

	if (handler == NULL) {
		return MANIFEST_CMD_STATUS_UNKNOWN;
	}

	handler->task->lock (handler->task);
	status = handler->state->status;
	handler->task->unlock (handler->task);

	return status;
}

void manifest_cmd_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct manifest_cmd_handler *manifest_handler = TO_DERIVED_TYPE (handler,
		const struct manifest_cmd_handler, base_event);
	int status = MANIFEST_MANAGER_UNSUPPORTED_OP;

	if (context->action & MANIFEST_CMD_HANDLER_ACTION_PREPARE) {
		manifest_cmd_handler_set_status (manifest_handler, MANIFEST_CMD_STATUS_PREPARE);

		status = manifest_handler->manifest->clear_pending_region (manifest_handler->manifest,
			*((uint32_t*) context->event_buffer));
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_ERASE_FAIL, manifest_manager_get_port (manifest_handler->manifest),
				status);

			status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_PREPARE_FAIL, status);
		}
	}
	else if (context->action & MANIFEST_CMD_HANDLER_ACTION_STORE) {
		manifest_cmd_handler_set_status (manifest_handler, MANIFEST_CMD_STATUS_STORE_DATA);

		status = manifest_handler->manifest->write_pending_data (manifest_handler->manifest,
			context->event_buffer, context->buffer_length);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_WRITE_FAIL, manifest_manager_get_port (manifest_handler->manifest),
				status);

			status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_STORE_FAIL, status);
		}
	}
	else if (context->action & MANIFEST_CMD_HANDLER_ACTION_FINALIZE) {
		manifest_cmd_handler_set_status (manifest_handler, MANIFEST_CMD_STATUS_VALIDATION);

		status = manifest_handler->manifest->verify_pending_manifest (manifest_handler->manifest);
		if (context->action & MANIFEST_CMD_HANDLER_ACTION_ACTIVATE) {
			/* Run activation after a successful manifest verification.  In this context, situations
			 * where no new manifest was sent are considered successful, which allows activation
			 * flows to run with the existing manifests. */
			if ((status == 0) || (status == MANIFEST_MANAGER_HAS_PENDING) ||
				(status == MANIFEST_MANAGER_NONE_PENDING)) {
				if (manifest_handler->activation) {
					/* The command status is set to indicate activation has started.  Further status
					 * updates are left to the specific implementation providing the activation
					 * workflow. */
					manifest_cmd_handler_set_status (manifest_handler,
						MANIFEST_CMD_STATUS_ACTIVATING);
					status = manifest_handler->activation (manifest_handler, reset);

					/* The status return from the activation call is used directly to report command
					 * status.  Any logging of error status or generation of MANIFEST_CMD_STATUS
					 * values needs to be done in the specific implementation. */
				}
				else {
					status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_FAIL,
						MANIFEST_MANAGER_UNSUPPORTED_OP);
				}
			}
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
					MANIFEST_LOGGING_VERIFY_FAIL,
					manifest_manager_get_port (manifest_handler->manifest), status);

				status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_VALIDATE_FAIL, status);
			}
		}
		else if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_VERIFY_FAIL,
				manifest_manager_get_port (manifest_handler->manifest), status);

			status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_VALIDATE_FAIL, status);
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_MANIFEST,
			MANIFEST_LOGGING_NOTIFICATION_ERROR,
			manifest_manager_get_port (manifest_handler->manifest), context->action);

		status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);
	}

	manifest_cmd_handler_set_status (manifest_handler, status);
}

/**
 * Initialize a handler for manifest commands.
 *
 * @param handler The manifest handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param manifest The manifest manager to use during command processing.
 * @param task The task that will be used to execute manifest operations.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int manifest_cmd_handler_init (struct manifest_cmd_handler *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task)
{
	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct manifest_cmd_handler));

	handler->base_cmd.prepare_manifest = manifest_cmd_handler_prepare_manifest;
	handler->base_cmd.store_manifest = manifest_cmd_handler_store_manifest;
	handler->base_cmd.finish_manifest = manifest_cmd_handler_finish_manifest;
	handler->base_cmd.get_status = manifest_cmd_handler_get_status;

	handler->base_event.execute = manifest_cmd_handler_execute;

	handler->state = state;
	handler->manifest = manifest;
	handler->task = task;

	return manifest_cmd_handler_init_state (handler);
}

/**
 * Initialize only the variable state for a manifest handler.  The rest of the handler is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The manifest handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_cmd_handler_init_state (const struct manifest_cmd_handler *handler)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->manifest == NULL) ||
		(handler->task == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (struct manifest_cmd_handler_state));

	handler->state->status = MANIFEST_CMD_STATUS_NONE_STARTED;

	return 0;
}

/**
 * Release the resources used by a manifest handler.
 *
 * @param handler The manifest handler to release.
 */
void manifest_cmd_handler_release (const struct manifest_cmd_handler *handler)
{

}
