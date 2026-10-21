// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_logging.h"
#include "restore_active_handler.h"
#include "common/unused.h"


void restore_active_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct restore_active_handler *restore = (const struct restore_active_handler*) handler;
	int status;

	if (context->action != RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE) {
		return;
	}

	status = firmware_update_recovery_matches_active_image (restore->updater);
	if (status != 0) {
		if (status != 1) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
				FIRMWARE_LOGGING_RECOVERY_COMPARE_FAIL, status, 0);
		}

		firmware_update_restore_active_image (restore->updater);
	}
}

/**
 * Initialize a handler to restore the active firmware image in flash from the recovery image.  This
 * handler must be run from the same task context as the firmware updater.
 *
 * @param handler The handler to initialize.
 * @param updater The firmware updater managing the flash containing firmware images.
 * @param task The task context for running firmware image management operations.
 *
 * @return 0 if the handler was successfully initialized or an error code.
 */
int restore_active_handler_init (struct restore_active_handler *handler,
	const struct firmware_update *updater, const struct event_task *task)
{
	if ((handler == NULL) || (updater == NULL) || (task == NULL)) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (*handler));

	handler->base.execute = restore_active_handler_execute;

	handler->updater = updater;
	handler->task = task;

	return 0;
}

/**
 * Release the resources used by a handler for restoring the active firmware image on flash.
 *
 * @param handler The handler to release.
 */
void restore_active_handler_release (const struct restore_active_handler *handler)
{
	UNUSED (handler);
}

/**
 * Trigger restoration of the active firmware image on flash from the recovery image.  Only if the
 * active image is different from the recovery image will any flash operations be performed.
 * Otherwise, all flash will remain unchanged.
 *
 * Execution of the image restore process will be asynchronous to this call.  The result of the
 * restore process will be logged but is not exposed by this handler.
 *
 * @param handler The handler to use for restoring the active image.
 *
 * @return 0 if the image restoration was triggered successfully or an error code.
 */
int restore_active_handler_restore_from_recovery_flash (
	const struct restore_active_handler *handler)
{
	if (handler == NULL) {
		return FIRMWARE_UPDATE_INVALID_ARGUMENT;
	}

	return event_task_submit_event (handler->task, &handler->base,
		RESTORE_ACTIVE_HANDLER_ACTION_RESTORE_ACTIVE, NULL, 0, 0, NULL);
}

/**
 * Trigger restoration of the active firmware image on flash from the recovery image.  Only if the
 * active image is different from the recovery image will any flash operations be performed.
 * Otherwise, all flash will remain unchanged.
 *
 * If there is an error triggering the start of the restore process, a log message will be
 * generated.
 *
 * Execution of the image restore process will be asynchronous to this call.  The result of the
 * restore process will be logged but is not exposed by this handler.
 *
 * @param handler The handler to use for restoring the active image.
 */
void restore_active_handler_restore_from_recovery_flash_and_log_error (
	const struct restore_active_handler *handler)
{
	int status;

	status = restore_active_handler_restore_from_recovery_flash (handler);
	if (status != 0) {
		restore_active_handler_log_start_restore_error (status);
	}
}

/**
 * Log a message for an error when triggering the restore process.
 *
 * @param error_code The error code to log.
 */
void restore_active_handler_log_start_restore_error (int error_code)
{
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_CERBERUS_FW,
		FIRMWARE_LOGGING_ACTIVE_RESTORE_START, error_code, 0);
}
