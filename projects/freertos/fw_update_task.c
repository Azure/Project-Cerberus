// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "fw_update_task.h"
#include "firmware/firmware_logging.h"


#define RUN_UPDATE_BIT			(1 << 0)
#define PREP_STAGING_BIT		(1 << 1)
#define WRITE_TO_STAGING_BIT	(1 << 2)


/**
 * The task function that will run the firmware update.
 *
 * @param task The updater task instance.
 */
static void fw_update_task_updater (struct fw_update_task *task)
{
	uint32_t notification;
	bool reset = false;
	int status;

	if (task->running == 2) {
		/* The system is running from the recovery image, so mark that image as good and restore the
		 * active image to a functional state. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_ACTIVE_RESTORE_START, 0, 0);

		firmware_update_set_recovery_good (task->updater, true);
		status = firmware_update_restore_active_image (task->updater);

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
			FIRMWARE_LOGGING_ACTIVE_RESTORE_DONE, status, 0);
	}
	else {
		/* Ensure the recovery image is in a good state. */
		if (firmware_update_is_recovery_good (task->updater)) {
			firmware_update_validate_recovery_image (task->updater);
		}

		status = firmware_update_restore_recovery_image (task->updater);
		if (status == 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_IMAGE, 0, 0);
		}
		else if (status != FIRMWARE_UPDATE_RESTORE_NOT_NEEDED) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_RESTORE_FAIL, status, 0);
		}
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	task->running = 0;
	xSemaphoreGive (task->lock);

	do {
		/* Wait for a signal to perform update action. */
		status = 1;
		xTaskNotifyWait (pdFALSE, ULONG_MAX, &notification, portMAX_DELAY);

		if (notification & RUN_UPDATE_BIT) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_UPDATE_START, 0, 0);
			debug_log_flush ();

			status = firmware_update_run_update (task->updater, &task->notify.base);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_UPDATE_FAIL, task->update_status, status);
			}
#ifndef SWD_DEBUG
			else {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_UPDATE_COMPLETE, 0, 0);

				reset = true;
			}
#endif
		}
		else if (notification & PREP_STAGING_BIT) {
			status = firmware_update_prepare_staging (task->updater, &task->notify.base,
				task->staging_size);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_ERASE_FAIL, task->update_status, status);
			}
		}
		else if (notification & WRITE_TO_STAGING_BIT) {
			status = firmware_update_write_to_staging (task->updater, &task->notify.base,
				task->staging_buf, task->staging_buf_len);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_WRITE_FAIL, task->update_status, status);
			}
		}

		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (status != 1) {
			if (status == 0) {
				task->update_status = 0;
			}
			else {
				task->update_status |= (status << 8);
			}
		}
		task->running = (reset) ? 1 : 0;
		xSemaphoreGive (task->lock);

		if (reset) {
			/* After a successful FW update, reset the system.  We need to wait a bit before
			 * triggering the reset to give time for the application that started the update to
			 * know that it was successful. */
			platform_msleep (5000);
			system_reset (task->system);
			reset = false;	/* We should never get here, but clear the flag if the reset fails. */
		}
	} while (1);
}

static int fw_update_task_start_update (struct firmware_update_control *update)
{
	struct fw_update_task *task = (struct fw_update_task*) update;
	int status = 0;

	if (task == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			task->update_status = UPDATE_STATUS_STARTING;
			task->running = 1;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, RUN_UPDATE_BIT, eSetBits);
		}
		else {
			task->update_status = UPDATE_STATUS_REQUEST_BLOCKED;
			status = FIRMWARE_UPDATE_TASK_BUSY;
			xSemaphoreGive (task->lock);
		}
	}
	else {
		task->update_status = UPDATE_STATUS_TASK_NOT_RUNNING;
		status = FIRMWARE_UPDATE_NO_TASK;
	}

	return status;
}

static int fw_update_task_get_status (struct firmware_update_control *update)
{
	struct fw_update_task *task = (struct fw_update_task*) update;
	int status;

	if (task == NULL) {
		return UPDATE_STATUS_UNKNOWN;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	status = task->update_status;
	xSemaphoreGive (task->lock);

	return status;
}

static int32_t fw_update_task_get_remaining_len (struct firmware_update_control *update)
{
	struct fw_update_task *task = (struct fw_update_task*) update;
	int32_t bytes;

	if (task == NULL) {
		return 0;
	}

	xSemaphoreTake (task->lock, portMAX_DELAY);
	bytes = firmware_update_get_update_remaining (task->updater);
	xSemaphoreGive (task->lock);

	return bytes;
}

static int fw_update_task_prepare_staging (struct firmware_update_control *update, size_t size)
{
	struct fw_update_task *task = (struct fw_update_task*) update;
	int status = 0;

	if (task == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			task->update_status = UPDATE_STATUS_STARTING;
			task->staging_size = size;
			task->running = 1;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, PREP_STAGING_BIT, eSetBits);
		}
		else {
			task->update_status = UPDATE_STATUS_REQUEST_BLOCKED;
			status = FIRMWARE_UPDATE_TASK_BUSY;
			xSemaphoreGive (task->lock);
		}
	}
	else {
		task->update_status = UPDATE_STATUS_TASK_NOT_RUNNING;
		status = FIRMWARE_UPDATE_NO_TASK;
	}

	return status;
}

static int fw_update_task_write_staging (struct firmware_update_control *update, uint8_t* buf,
	size_t buf_len)
{
	struct fw_update_task *task = (struct fw_update_task*) update;
	int status = 0;

	if ((task == NULL) || (buf == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	if (task->task) {
		xSemaphoreTake (task->lock, portMAX_DELAY);
		if (!task->running) {
			task->update_status = UPDATE_STATUS_STARTING;
			memcpy (task->staging_buf, buf, buf_len);
			task->staging_buf_len = buf_len;
			task->running = 1;
			xSemaphoreGive (task->lock);
			xTaskNotify (task->task, WRITE_TO_STAGING_BIT, eSetBits);
		}
		else {
			task->update_status = UPDATE_STATUS_REQUEST_BLOCKED;
			status = FIRMWARE_UPDATE_TASK_BUSY;
			xSemaphoreGive (task->lock);
		}
	}
	else {
		task->update_status = UPDATE_STATUS_TASK_NOT_RUNNING;
		status = FIRMWARE_UPDATE_NO_TASK;
	}

	return status;
}

static void fw_update_task_status_change (struct firmware_update_notification *context,
	enum firmware_update_status status)
{
	struct fw_update_task_notify *notify = (struct fw_update_task_notify*) context;

	if (notify != NULL) {
		xSemaphoreTake (notify->task->lock, portMAX_DELAY);
		notify->task->update_status = status;
		xSemaphoreGive (notify->task->lock);
	}
}

/**
 * Initialize the task interface for controlling the firmware update.
 *
 * @param task The task interface to initialize.
 * @param updater The updater instance to use in the task.
 * @param system The manager for system operations.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int fw_update_task_init (struct fw_update_task *task, struct firmware_update *updater,
	struct system *system)
{
	if ((task == NULL) || (updater == NULL) || (system == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct fw_update_task));

	task->lock = xSemaphoreCreateMutex ();
	if (task->lock == NULL) {
		return FIRMWARE_UPDATE_NO_MEMORY;
	}

	task->updater = updater;
	task->system = system;
	task->update_status = UPDATE_STATUS_NONE_STARTED;

	task->base.start_update = fw_update_task_start_update;
	task->base.get_status = fw_update_task_get_status;
	task->base.get_remaining_len = fw_update_task_get_remaining_len;
	task->base.prepare_staging = fw_update_task_prepare_staging;
	task->base.write_staging = fw_update_task_write_staging;

	task->notify.base.status_change = fw_update_task_status_change;
	task->notify.task = task;

	return 0;
}

/**
 * Start running the firmware update task.  This doesn't start an update process, just starts the
 * task that will run the update.  No update can be run until the update task has been started.
 *
 * @param task The update task to start.
 * @param stack_words The size of the update task stack.  The stack size is measured in words.
 * @param running_recovery Indicate that the system is running from the recovery image.
 *
 * @return 0 if the task was started or an error code.
 */
int fw_update_task_start (struct fw_update_task *task, uint16_t stack_words, bool running_recovery)
{
	int status;

	if (task == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	/* The task will clear the running flag after it has finished initializing the updater. */
	task->running = (running_recovery) ? 2 : 1;

	status = xTaskCreate ((TaskFunction_t) fw_update_task_updater, "FW Update", stack_words, task,
		CERBERUS_PRIORITY_NORMAL, &task->task);
	if (status != pdPASS) {
		task->task = NULL;
		return FIRMWARE_UPDATE_NO_MEMORY;
	}

	return 0;
}
