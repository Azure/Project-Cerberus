// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "common/type_cast.h"
#include "manifest_cmd_handler.h"
#include "fsl_common.h"
#include "manifest/manifest_logging.h"


#define	MANIFEST_RUN_PREPARE_BIT	(1U << 0)
#define	MANIFEST_RUN_STORE_BIT		(1U << 1)
#define	MANIFEST_RUN_FINALIZE_BIT	(1U << 2)
#define MANIFEST_RUN_ACTIVATION_BIT	(1U << 3)


/**
 * Set the current manifest operation status.
 *
 * @param handler The command handler instance to update.
 * @param status The status value to set.
 */
void manifest_cmd_handler_set_status (struct manifest_cmd_handler *handler, int status)
{
	xSemaphoreTake (handler->task->lock, portMAX_DELAY);
	handler->status = status;
	xSemaphoreGive (handler->task->lock);
}

static void manifest_cmd_handler_execute (struct config_cmd_task_handler *handler, uint32_t action,
	bool *reset)
{
	struct manifest_cmd_handler *manifest_handler = TO_DERIVED_TYPE (handler,
		struct manifest_cmd_handler, cmd_base);
	int status = MANIFEST_MANAGER_UNSUPPORTED_OP;

	if (action & MANIFEST_RUN_PREPARE_BIT) {
		manifest_cmd_handler_set_status (manifest_handler, MANIFEST_CMD_STATUS_PREPARE);

		status = manifest_handler->manifest->clear_pending_region (manifest_handler->manifest,
			manifest_handler->task->prepare_size);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_ERASE_FAIL, manifest_manager_get_port (manifest_handler->manifest),
				status);

			status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_PREPARE_FAIL, status);
		}
	}
	else if (action & MANIFEST_RUN_STORE_BIT) {
		manifest_cmd_handler_set_status (manifest_handler, MANIFEST_CMD_STATUS_STORE_DATA);

		status = manifest_handler->manifest->write_pending_data (manifest_handler->manifest,
			manifest_handler->task->buffer, manifest_handler->task->buffer_len);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MANIFEST,
				MANIFEST_LOGGING_WRITE_FAIL, manifest_manager_get_port (manifest_handler->manifest),
				status);

			status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_STORE_FAIL, status);
		}
	}
	else if (action & MANIFEST_RUN_FINALIZE_BIT) {
		manifest_cmd_handler_set_status (manifest_handler, MANIFEST_CMD_STATUS_VALIDATION);

		status = manifest_handler->manifest->verify_pending_manifest (manifest_handler->manifest);
		if (action & MANIFEST_RUN_ACTIVATION_BIT) {
			if ((status == 0) || (status == MANIFEST_MANAGER_HAS_PENDING) ||
				(status == MANIFEST_MANAGER_NONE_PENDING)) {
				if (manifest_handler->activation) {
					manifest_cmd_handler_set_status (manifest_handler,
						MANIFEST_CMD_STATUS_ACTIVATING);
					status = manifest_handler->activation (manifest_handler, reset);
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
			manifest_manager_get_port (manifest_handler->manifest), action);

		status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_INTERNAL_ERROR, status);
	}

	xSemaphoreTake (manifest_handler->task->lock, portMAX_DELAY);
	manifest_handler->status = status;
	manifest_handler->task->running = (*reset) ? 1 : 0;
	xSemaphoreGive (manifest_handler->task->lock);
}

static int manifest_cmd_handler_prepare_manifest (struct manifest_cmd_interface *cmd,
	uint32_t manifest_size)
{
	struct manifest_cmd_handler *handler = (struct manifest_cmd_handler*) cmd;
	int status = 0;

	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (handler->task->task) {
		xSemaphoreTake (handler->task->lock, portMAX_DELAY);
		if (!handler->task->running) {
			handler->status = MANIFEST_CMD_STATUS_STARTING;
			handler->task->running = 1;
			handler->task->prepare_size = manifest_size;
			xSemaphoreGive (handler->task->lock);
			config_cmd_task_notify (handler->task, handler->id, MANIFEST_RUN_PREPARE_BIT);
		}
		else {
			handler->status = MANIFEST_CMD_STATUS_REQUEST_BLOCKED;
			status = MANIFEST_MANAGER_TASK_BUSY;
			xSemaphoreGive (handler->task->lock);
		}
	}
	else {
		handler->status = MANIFEST_CMD_STATUS_TASK_NOT_RUNNING;
		status = MANIFEST_MANAGER_NO_TASK;
	}

	return status;
}

static int manifest_cmd_handler_store_manifest (struct manifest_cmd_interface *cmd,
	const uint8_t *data, size_t length)
{
	struct manifest_cmd_handler *handler = (struct manifest_cmd_handler*) cmd;
	int status = 0;

	if ((handler == NULL) || (data == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (handler->task->task) {
		xSemaphoreTake (handler->task->lock, portMAX_DELAY);
		if (!handler->task->running) {
			handler->status = MANIFEST_CMD_STATUS_STARTING;
			memcpy (handler->task->buffer, data, length);
			handler->task->buffer_len = length;
			handler->task->running = 1;
			xSemaphoreGive (handler->task->lock);
			config_cmd_task_notify (handler->task, handler->id, MANIFEST_RUN_STORE_BIT);
		}
		else {
			handler->status = MANIFEST_CMD_STATUS_REQUEST_BLOCKED;
			status = MANIFEST_MANAGER_TASK_BUSY;
			xSemaphoreGive (handler->task->lock);
		}
	}
	else {
		handler->status = MANIFEST_CMD_STATUS_TASK_NOT_RUNNING;
		status = MANIFEST_MANAGER_NO_TASK;
	}

	return status;
}

static int manifest_cmd_handler_finish_manifest (struct manifest_cmd_interface *cmd, bool activate)
{
	struct manifest_cmd_handler *handler = (struct manifest_cmd_handler*) cmd;
	int status = 0;
	uint32_t activation = (activate) ? MANIFEST_RUN_ACTIVATION_BIT : 0;

	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	if (handler->task->task) {
		xSemaphoreTake (handler->task->lock, portMAX_DELAY);
		if (!handler->task->running) {
			handler->status = MANIFEST_CMD_STATUS_STARTING;
			handler->task->running = 1;
			xSemaphoreGive (handler->task->lock);
			config_cmd_task_notify (handler->task, handler->id,
				MANIFEST_RUN_FINALIZE_BIT | activation);
		}
		else {
			handler->status = MANIFEST_CMD_STATUS_REQUEST_BLOCKED;
			status = MANIFEST_MANAGER_TASK_BUSY;
			xSemaphoreGive (handler->task->lock);
		}
	}
	else {
		handler->status = MANIFEST_CMD_STATUS_TASK_NOT_RUNNING;
		status = MANIFEST_MANAGER_NO_TASK;
	}

	return status;
}

static int manifest_cmd_handler_get_status (struct manifest_cmd_interface *cmd)
{
	struct manifest_cmd_handler *handler = (struct manifest_cmd_handler*) cmd;
	int status;

	if (handler == NULL) {
		return MANIFEST_CMD_STATUS_UNKNOWN;
	}

	xSemaphoreTake (handler->task->lock, portMAX_DELAY);
	status = handler->status;
	xSemaphoreGive (handler->task->lock);

	return status;
}

void manifest_cmd_handler_bind (struct config_cmd_task_handler *handler,
	struct config_cmd_task *task, uint8_t handler_id)
{
	struct manifest_cmd_handler *manifest_handler = TO_DERIVED_TYPE (handler,
		struct manifest_cmd_handler, cmd_base);

	manifest_handler->task = task;
	manifest_handler->id = handler_id;
}

/**
 * Initialize the command handler for executing manifest commands.
 *
 * @param handler The command handler to initialize.
 * @param manifest The manifest manager to execute commands against.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int manifest_cmd_handler_init (struct manifest_cmd_handler *handler,
	struct manifest_manager *manifest)
{
	if ((handler == NULL) || (manifest == NULL)) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct manifest_cmd_handler));

	handler->manifest = manifest;
	handler->status = MANIFEST_CMD_STATUS_NONE_STARTED;

	handler->base.prepare_manifest = manifest_cmd_handler_prepare_manifest;
	handler->base.store_manifest = manifest_cmd_handler_store_manifest;
	handler->base.finish_manifest = manifest_cmd_handler_finish_manifest;
	handler->base.get_status = manifest_cmd_handler_get_status;

	handler->cmd_base.bind = manifest_cmd_handler_bind;
	handler->cmd_base.execute = manifest_cmd_handler_execute;

	return 0;
}
