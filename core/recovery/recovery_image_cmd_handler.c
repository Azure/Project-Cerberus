// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "recovery_image_cmd_handler.h"
#include "recovery_logging.h"
#include "common/type_cast.h"
#include "common/unused.h"


/**
 * Set the current recovery image operation status.
 *
 * @param handler The command handler instance to update.
 * @param status The status value to set.
 */
void recovery_image_cmd_handler_set_status (const struct recovery_image_cmd_handler *handler,
	int status)
{
	handler->task->lock (handler->task);
	handler->state->status = status;
	handler->task->unlock (handler->task);
}

/**
 * Notify the task that a recovery image event needs to be processed.
 *
 * @param handler The handler that received the event.
 * @param action The recovery image action that needs to be performed.
 * @param data Data associated with the event.  Null if there is no data.
 * @param length Length of the event data.
 *
 * @return 0 if the task was notified successfully or an error code.
 */
static int recovery_image_cmd_handler_submit_event (
	const struct recovery_image_cmd_handler *handler, uint32_t action, const uint8_t *data,
	size_t length)
{
	int status;

	status = event_task_submit_event (handler->task, &handler->base_event, action, data, length,
		RECOVERY_IMAGE_CMD_STATUS_STARTING, &handler->state->status);
	if (status != 0) {
		if (status == EVENT_TASK_BUSY) {
			/* Do not change the command status when the task is busy.  Something is running, which
			 * could be using the status. */
			status = RECOVERY_IMAGE_MANAGER_TASK_BUSY;
		}
		else if (status == EVENT_TASK_TOO_MUCH_DATA) {
			/* Do not change the command status, since we don't know that state of the task. */
			return RECOVERY_IMAGE_MANAGER_TOO_MUCH_DATA;
		}
		else if (status == EVENT_TASK_NO_TASK) {
			handler->state->status = RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING;
			status = RECOVERY_IMAGE_MANAGER_NO_TASK;
		}
		else {
			recovery_image_cmd_handler_set_status (handler,
				RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR);
		}
	}

	return status;
}

int recovery_image_cmd_handler_prepare_recovery_image (
	const struct recovery_image_cmd_interface *cmd, uint32_t image_size)
{
	const struct recovery_image_cmd_handler *handler =
		(const struct recovery_image_cmd_handler*) cmd;

	if (handler == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	return recovery_image_cmd_handler_submit_event (handler,
		RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE, (uint8_t*) &image_size, sizeof (image_size));
}

int recovery_image_cmd_handler_update_recovery_image (
	const struct recovery_image_cmd_interface *cmd, const uint8_t *data, size_t length)
{
	const struct recovery_image_cmd_handler *handler =
		(const struct recovery_image_cmd_handler*) cmd;

	if ((handler == NULL) || (data == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	return recovery_image_cmd_handler_submit_event (handler,
		RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE, data, length);
}

int recovery_image_cmd_handler_activate_recovery_image (
	const struct recovery_image_cmd_interface *cmd)
{
	const struct recovery_image_cmd_handler *handler =
		(const struct recovery_image_cmd_handler*) cmd;

	if (handler == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	return recovery_image_cmd_handler_submit_event (handler,
		RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE, NULL, 0);
}

int recovery_image_cmd_handler_get_status (const struct recovery_image_cmd_interface *cmd)
{
	const struct recovery_image_cmd_handler *handler =
		(const struct recovery_image_cmd_handler*) cmd;
	int status;

	if (handler == NULL) {
		return RECOVERY_IMAGE_CMD_STATUS_UNKNOWN;
	}

	handler->task->lock (handler->task);
	status = handler->state->status;
	handler->task->unlock (handler->task);

	return status;
}

void recovery_image_cmd_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct recovery_image_cmd_handler *recovery_handler = TO_DERIVED_TYPE (handler,
		const struct recovery_image_cmd_handler, base_event);
	int status = RECOVERY_IMAGE_MANAGER_UNSUPPORTED_OP;

	UNUSED (reset);

	switch (context->action) {
		case RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE:
			recovery_image_cmd_handler_set_status (recovery_handler,
				RECOVERY_IMAGE_CMD_STATUS_PREPARE);

			status = recovery_handler->manager->clear_recovery_image_region (
				recovery_handler->manager, *((uint32_t*) context->event_buffer));
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
					RECOVERY_LOGGING_ERASE_FAIL,
					recovery_image_manager_get_port (recovery_handler->manager), status);

				status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL, status);
			}
			break;

		case RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE:
			recovery_image_cmd_handler_set_status (recovery_handler,
				RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA);

			status = recovery_handler->manager->write_recovery_image_data (
				recovery_handler->manager, context->event_buffer, context->buffer_length);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
					RECOVERY_LOGGING_WRITE_FAIL,
					recovery_image_manager_get_port (recovery_handler->manager), status);

				status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL, status);
			}
			break;

		case RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE:
			recovery_image_cmd_handler_set_status (recovery_handler,
				RECOVERY_IMAGE_CMD_STATUS_ACTIVATING);

			status = recovery_handler->manager->activate_recovery_image (recovery_handler->manager);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
					RECOVERY_LOGGING_ACTIVATION_FAIL,
					recovery_image_manager_get_port (recovery_handler->manager), status);

				status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL,
					status);
			}
			break;

		default:
			debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_RECOVERY,
				RECOVERY_LOGGING_NOTIFICATION_ERROR,
				recovery_image_manager_get_port (recovery_handler->manager), context->action);

			status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);
			break;
	}

	recovery_handler->task->lock (recovery_handler->task);
	recovery_handler->state->status = status;
	recovery_handler->task->unlock (recovery_handler->task);
}

/**
 * Initialize a handler for recovery image commands.
 *
 * @param handler The recovery image handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param recovery The recovery image manager to use during command processing.
 * @param task The task that will be used to execute recovery image operations.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int recovery_image_cmd_handler_init (struct recovery_image_cmd_handler *handler,
	struct recovery_image_cmd_handler_state *state, struct recovery_image_manager *recovery,
	const struct event_task *task)
{
	if (handler == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct recovery_image_cmd_handler));

	handler->base_cmd.prepare_recovery_image = recovery_image_cmd_handler_prepare_recovery_image;
	handler->base_cmd.update_recovery_image = recovery_image_cmd_handler_update_recovery_image;
	handler->base_cmd.activate_recovery_image = recovery_image_cmd_handler_activate_recovery_image;
	handler->base_cmd.get_status = recovery_image_cmd_handler_get_status;

	handler->base_event.execute = recovery_image_cmd_handler_execute;

	handler->state = state;
	handler->manager = recovery;
	handler->task = task;

	return recovery_image_cmd_handler_init_state (handler);
}

/**
 * Initialize only the variable state for a recovery image handler.  The rest of the handler is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The recovery image handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int recovery_image_cmd_handler_init_state (const struct recovery_image_cmd_handler *handler)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->manager == NULL) ||
		(handler->task == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (struct recovery_image_cmd_handler_state));

	handler->state->status = RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED;

	return 0;
}

/**
 * Release the resources used by a recovery image handler.
 *
 * @param handler The recovery image handler to release.
 */
void recovery_image_cmd_handler_release (const struct recovery_image_cmd_handler *handler)
{
	UNUSED (handler);
}
