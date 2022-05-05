// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "recovery_image_cmd_handler.h"
#include "common/type_cast.h"
#include "logging/debug_log.h"
#include "recovery/recovery_logging.h"


#define	RECOVERY_IMAGE_RUN_PREPARE_BIT		(1U << 0)
#define	RECOVERY_IMAGE_RUN_STORE_BIT		(1U << 1)
#define RECOVERY_IMAGE_RUN_ACTIVATION_BIT	(1U << 2)


/**
 * Set the current recovery image operation status.
 *
 * @param handler The task handler instance to update.
 * @param status The status value to set.
 */
static void recovery_image_cmd_handler_set_status (struct recovery_image_cmd_handler *handler,
	int status)
{
	xSemaphoreTake (handler->task->lock, portMAX_DELAY);
	handler->status = status;
	xSemaphoreGive (handler->task->lock);
}

static int recovery_image_cmd_handler_get_status (struct recovery_image_cmd_interface *cmd)
{
	struct recovery_image_cmd_handler *handler = (struct recovery_image_cmd_handler*) cmd;
	int status;

	if (handler == NULL) {
		return RECOVERY_IMAGE_CMD_STATUS_UNKNOWN;
	}

	xSemaphoreTake (handler->task->lock, portMAX_DELAY);
	status = handler->status;
	xSemaphoreGive (handler->task->lock);

	return status;
}

static void recovery_image_cmd_handler_execute (struct config_cmd_task_handler *handler,
	uint32_t action, bool *reset)
{
	struct recovery_image_cmd_handler *recovery_handler = TO_DERIVED_TYPE (handler,
		struct recovery_image_cmd_handler, cmd_base);
	int status = RECOVERY_IMAGE_MANAGER_UNSUPPORTED_OP;

	if (action & RECOVERY_IMAGE_RUN_PREPARE_BIT) {
		recovery_image_cmd_handler_set_status (recovery_handler, RECOVERY_IMAGE_CMD_STATUS_PREPARE);

		status = recovery_handler->manager->clear_recovery_image_region (recovery_handler->manager,
			recovery_handler->task->prepare_size);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
				RECOVERY_LOGGING_ERASE_FAIL,
				recovery_image_manager_get_port (recovery_handler->manager), status);

			status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_PREPARE_FAIL, status);
		}
	}
	else if (action & RECOVERY_IMAGE_RUN_STORE_BIT) {
		recovery_image_cmd_handler_set_status (recovery_handler,
			RECOVERY_IMAGE_CMD_STATUS_UPDATE_DATA);

		status = recovery_handler->manager->write_recovery_image_data (recovery_handler->manager,
			recovery_handler->task->buffer, recovery_handler->task->buffer_len);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
				RECOVERY_LOGGING_WRITE_FAIL,
				recovery_image_manager_get_port (recovery_handler->manager), status);

			status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_UPDATE_FAIL, status);
		}
	}
	else if (action & RECOVERY_IMAGE_RUN_ACTIVATION_BIT) {
		recovery_image_cmd_handler_set_status (recovery_handler,
			RECOVERY_IMAGE_CMD_STATUS_ACTIVATING);

		status = recovery_handler->manager->activate_recovery_image (recovery_handler->manager);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_RECOVERY,
				RECOVERY_LOGGING_ACTIVATION_FAIL,
				recovery_image_manager_get_port (recovery_handler->manager), status);

			status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_ACTIVATION_FAIL, status);
		}
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_RECOVERY,
			RECOVERY_LOGGING_NOTIFICATION_ERROR,
			recovery_image_manager_get_port (recovery_handler->manager), action);

		status = RECOVERY_IMAGE_CMD_STATUS (RECOVERY_IMAGE_CMD_STATUS_INTERNAL_ERROR, status);
	}

	xSemaphoreTake (recovery_handler->task->lock, portMAX_DELAY);
	recovery_handler->status = status;
	recovery_handler->task->running = (*reset) ? 1 : 0;
	xSemaphoreGive (recovery_handler->task->lock);
}

static int recovery_image_cmd_handler_prepare_recovery_image (
	struct recovery_image_cmd_interface *cmd, uint32_t image_size)
{
	struct recovery_image_cmd_handler *handler = (struct recovery_image_cmd_handler*) cmd;
	int status = 0;

	if (handler == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	if (handler->task->task) {
		xSemaphoreTake (handler->task->lock, portMAX_DELAY);
		if (!handler->task->running) {
			handler->status = RECOVERY_IMAGE_CMD_STATUS_STARTING;
			handler->task->running = 1;
			handler->task->prepare_size = image_size;
			xSemaphoreGive (handler->task->lock);
			config_cmd_task_notify (handler->task, handler->id, RECOVERY_IMAGE_RUN_PREPARE_BIT);
		}
		else {
			handler->status = RECOVERY_IMAGE_CMD_STATUS_REQUEST_BLOCKED;
			status = RECOVERY_IMAGE_MANAGER_TASK_BUSY;
			xSemaphoreGive (handler->task->lock);
		}
	}
	else {
		handler->status = RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING;
		status = RECOVERY_IMAGE_MANAGER_NO_TASK;
	}

	return status;
}

static int recovery_image_cmd_handler_update_recovery_image (
	struct recovery_image_cmd_interface *cmd, const uint8_t *data, size_t length)
{
	struct recovery_image_cmd_handler *handler = (struct recovery_image_cmd_handler*) cmd;
	int status = 0;

	if ((handler == NULL) || (data == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	if (handler->task) {
		xSemaphoreTake (handler->task->lock, portMAX_DELAY);
		if (!handler->task->running) {
			handler->status = RECOVERY_IMAGE_CMD_STATUS_STARTING;
			memcpy (handler->task->buffer, data, length);
			handler->task->buffer_len = length;
			handler->task->running = 1;
			xSemaphoreGive (handler->task->lock);
			config_cmd_task_notify (handler->task, handler->id, RECOVERY_IMAGE_RUN_STORE_BIT);
		}
		else {
			handler->status = RECOVERY_IMAGE_CMD_STATUS_REQUEST_BLOCKED;
			status = RECOVERY_IMAGE_MANAGER_TASK_BUSY;
			xSemaphoreGive (handler->task->lock);
		}
	}
	else {
		handler->status = RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING;
		status = RECOVERY_IMAGE_MANAGER_NO_TASK;
	}

	return status;
}

static int recovery_image_cmd_handler_activate_recovery_image (
	struct recovery_image_cmd_interface *cmd)
{
	struct recovery_image_cmd_handler *handler = (struct recovery_image_cmd_handler*) cmd;
	int status = 0;

	if (handler == NULL) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	if (handler->task->task) {
		xSemaphoreTake (handler->task->lock, portMAX_DELAY);
		if (!handler->task->running) {
			handler->status = RECOVERY_IMAGE_CMD_STATUS_STARTING;
			handler->task->running = 1;
			xSemaphoreGive (handler->task->lock);
			config_cmd_task_notify (handler->task, handler->id, RECOVERY_IMAGE_RUN_ACTIVATION_BIT);
		}
		else {
			handler->status = RECOVERY_IMAGE_CMD_STATUS_REQUEST_BLOCKED;
			status = RECOVERY_IMAGE_MANAGER_TASK_BUSY;
			xSemaphoreGive (handler->task->lock);
		}
	}
	else {
		handler->status = RECOVERY_IMAGE_CMD_STATUS_TASK_NOT_RUNNING;
		status = RECOVERY_IMAGE_MANAGER_NO_TASK;
	}

	return status;
}

void recovery_image_cmd_handler_bind (struct config_cmd_task_handler *handler,
	struct config_cmd_task *task, uint8_t handler_id)
{
	struct recovery_image_cmd_handler *recovery_handler = TO_DERIVED_TYPE (handler,
		struct recovery_image_cmd_handler, cmd_base);

	recovery_handler->task = task;
	recovery_handler->id = handler_id;
}

/**
 * Initialize the task handler for executing recovery image commands.
 *
 * @param handler The task handler to initialize.
 * @param manager The recovery image manager to execute commands against.
 *
 * @return 0 if the task handler was successfully initialized or an error code.
 */
int recovery_image_cmd_handler_init (struct recovery_image_cmd_handler *handler,
	struct recovery_image_manager *manager)
{
	if ((handler == NULL) || (manager == NULL)) {
		return RECOVERY_IMAGE_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct recovery_image_cmd_handler));

	handler->manager = manager;
	handler->status = RECOVERY_IMAGE_CMD_STATUS_NONE_STARTED;

	handler->base.prepare_recovery_image = recovery_image_cmd_handler_prepare_recovery_image;
	handler->base.update_recovery_image = recovery_image_cmd_handler_update_recovery_image;
	handler->base.get_status = recovery_image_cmd_handler_get_status;
	handler->base.activate_recovery_image = recovery_image_cmd_handler_activate_recovery_image;

	handler->cmd_base.bind = recovery_image_cmd_handler_bind;
	handler->cmd_base.execute = recovery_image_cmd_handler_execute;

	return 0;
}
