// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_cmd_handler.h"
#include "host_logging.h"
#include "common/type_cast.h"
#include "common/unused.h"


/**
 * Set the current host operation status.
 *
 * @param handler The command handler instance to update.
 * @param status The status value to set.
 */
static void host_cmd_handler_set_status (const struct host_cmd_handler *handler, int status)
{
	handler->task->lock (handler->task);
	handler->state->status = status;
	handler->task->unlock (handler->task);
}

/**
 * Notify the task that a host event needs to be processed.
 *
 * @param handler The handler that received the event.
 * @param action The host action that needs to be performed.
 * @param data Data associated with the event.  Null if there is no data.
 * @param length Length of the event data.
 *
 * @return 0 if the task was notified successfully or an error code.
 */
static int host_cmd_handler_submit_event (const struct host_cmd_handler *handler, uint32_t action,
	const uint8_t *data, size_t length)
{
	int status;

	status = event_task_submit_event (handler->task, &handler->base_event, action, data, length,
		HOST_CMD_STATUS_STARTING, &handler->state->status);
	if (status != 0) {
		if (status == EVENT_TASK_BUSY) {
			/* Do not change the command status when the task is busy.  Something is running, which
			 * could be using the status. */
			status = HOST_PROCESSOR_TASK_BUSY;
		}
		else if (status == EVENT_TASK_NO_TASK) {
			handler->state->status = HOST_CMD_STATUS_TASK_NOT_RUNNING;
			status = HOST_PROCESSOR_NO_TASK;
		}
		else {
			host_cmd_handler_set_status (handler, HOST_CMD_STATUS_INTERNAL_ERROR);
		}
	}

	return status;
}

int host_cmd_handler_get_next_host_verification (const struct host_cmd_interface *cmd,
	enum host_processor_reset_actions *action)
{
	const struct host_cmd_handler *handler =
		TO_DERIVED_TYPE (cmd, const struct host_cmd_handler, base_cmd);
	int status;

	if ((cmd == NULL) || (action == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	status = handler->host->get_next_reset_verification_actions (handler->host);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	*action = status;

	return 0;
}

int host_cmd_handler_get_flash_configuration (const struct host_cmd_interface *cmd,
	spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
	enum host_read_only_activation *apply_next_ro)
{
	const struct host_cmd_handler *handler =
		TO_DERIVED_TYPE (cmd, const struct host_cmd_handler, base_cmd);

	if (cmd == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	return handler->host->get_flash_config (handler->host, mode, current_ro, next_ro,
		apply_next_ro);
}

int host_cmd_handler_set_flash_configuration (const struct host_cmd_interface *cmd,
	int8_t current_ro, int8_t next_ro, int8_t apply_next_ro)
{
	const struct host_cmd_handler *handler =
		TO_DERIVED_TYPE (cmd, const struct host_cmd_handler, base_cmd);
	int8_t flash_config[3];

	if (cmd == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	flash_config[0] = current_ro;
	flash_config[1] = next_ro;
	flash_config[2] = apply_next_ro;

	return host_cmd_handler_submit_event (handler, HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG,
		(uint8_t*) flash_config, sizeof (flash_config));
}

int host_cmd_handler_get_status (const struct host_cmd_interface *cmd)
{
	const struct host_cmd_handler *handler =
		TO_DERIVED_TYPE (cmd, const struct host_cmd_handler, base_cmd);
	int status;

	if (cmd == NULL) {
		return HOST_CMD_STATUS_UNKNOWN;
	}

	handler->task->lock (handler->task);
	status = handler->state->status;
	handler->task->unlock (handler->task);

	return status;
}

void host_cmd_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct host_cmd_handler *host_handler =
		TO_DERIVED_TYPE (handler, const struct host_cmd_handler, base_event);
	int status = HOST_PROCESSOR_UNSUPPORTED_CMD;

	UNUSED (reset);

	if (context->action == HOST_CMD_HANDLER_ACTION_SET_FLASH_CONFIG) {
		spi_filter_cs current_ro;
		spi_filter_cs *new_current_ro = NULL;
		spi_filter_cs next_ro;
		spi_filter_cs *new_next_ro = NULL;
		enum host_read_only_activation apply_next_ro;
		enum host_read_only_activation *new_apply_next_ro = NULL;

		host_cmd_handler_set_status (host_handler, HOST_CMD_STATUS_START_FLASH_CONFIG);

		if ((int8_t) context->event_buffer[0] >= 0) {
			current_ro = (spi_filter_cs) context->event_buffer[0];
			new_current_ro = &current_ro;
		}

		if ((int8_t) context->event_buffer[1] >= 0) {
			next_ro = (spi_filter_cs) context->event_buffer[1];
			new_next_ro = &next_ro;
		}

		if ((int8_t) context->event_buffer[2] >= 0) {
			apply_next_ro = (enum host_read_only_activation) context->event_buffer[2];
			new_apply_next_ro = &apply_next_ro;
		}

		status = host_handler->host->config_read_only_flash (host_handler->host, new_current_ro,
			new_next_ro, new_apply_next_ro);
		if (status != 0) {
			status = HOST_CMD_STATUS (HOST_CMD_STATUS_FLASH_CONFIG_FAILED, status);
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_HOST_FW,
			HOST_LOGGING_NOTIFICATION_ERROR, host_processor_get_port (host_handler->host),
			context->action);

		status = HOST_CMD_STATUS (HOST_CMD_STATUS_INTERNAL_ERROR, status);
	}

	host_cmd_handler_set_status (host_handler, status);
}

/**
 * Initialize a handler for host commands.
 *
 * @param handler The host command handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param host The host processor to use during command processing.
 * @param task The task that will be used to execute host operations.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int host_cmd_handler_init (struct host_cmd_handler *handler, struct host_cmd_handler_state *state,
	const struct host_processor *host, const struct event_task *task)
{
	if (handler == NULL) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (*handler));

	handler->base_cmd.get_next_host_verification = host_cmd_handler_get_next_host_verification;
	handler->base_cmd.get_flash_configuration = host_cmd_handler_get_flash_configuration;
	handler->base_cmd.set_flash_configuration = host_cmd_handler_set_flash_configuration;
	handler->base_cmd.get_status = host_cmd_handler_get_status;

	handler->base_event.prepare = NULL;
	handler->base_event.execute = host_cmd_handler_execute;

	handler->state = state;
	handler->host = host;
	handler->task = task;

	return host_cmd_handler_init_state (handler);
}

/**
 * Initialize only the variable state for a host command handler.  The rest of the handler is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The host command handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int host_cmd_handler_init_state (const struct host_cmd_handler *handler)
{
	if ((handler == NULL) || (handler->state == NULL) || (handler->host == NULL) ||
		(handler->task == NULL)) {
		return HOST_PROCESSOR_INVALID_ARGUMENT;
	}

	memset (handler->state, 0, sizeof (*handler->state));

	handler->state->status = HOST_CMD_STATUS_NONE_STARTED;

	return 0;
}

/**
 * Release the resources used by a host command handler.
 *
 * @param handler The host command handler to release.
 */
void host_cmd_handler_release (const struct host_cmd_handler *handler)
{
	UNUSED (handler);
}
