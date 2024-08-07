// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "firmware_logging.h"
#include "impactful_update_handler.h"
#include "common/type_cast.h"
#include "common/unused.h"


int impactful_update_handler_start_update (const struct firmware_update_control *update)
{
	const struct impactful_update_handler *handler =
		TO_DERIVED_TYPE (update, const struct impactful_update_handler, base_ctrl);

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	/* In order for this instance to get called by the event task, it needs to submit the event
	 * notification directly.  Otherwise, the contained firmware_update_handler instance would be
	 * provided as part of the notification.
	 *
	 * Since this is bypassing the start_update call of the contained instance, it will not work as
	 * expected with firmware_update_handler implementations that need to do more than just schedule
	 * the event. */
	return firmware_update_handler_submit_event (handler->update, &handler->base_event,
		FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE, NULL, 0);
}

int impactful_update_handler_get_status (const struct firmware_update_control *update)
{
	const struct impactful_update_handler *handler =
		TO_DERIVED_TYPE (update, const struct impactful_update_handler, base_ctrl);

	if (update == NULL) {
		return UPDATE_STATUS_UNKNOWN;
	}

	return handler->update->base_ctrl.get_status (&handler->update->base_ctrl);
}

int32_t impactful_update_handler_get_remaining_len (const struct firmware_update_control *update)
{
	const struct impactful_update_handler *handler =
		TO_DERIVED_TYPE (update, const struct impactful_update_handler, base_ctrl);

	if (update == NULL) {
		return 0;
	}

	return handler->update->base_ctrl.get_remaining_len (&handler->update->base_ctrl);
}

int impactful_update_handler_prepare_staging (const struct firmware_update_control *update,
	size_t size)
{
	const struct impactful_update_handler *handler =
		TO_DERIVED_TYPE (update, const struct impactful_update_handler, base_ctrl);

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	return handler->update->base_ctrl.prepare_staging (&handler->update->base_ctrl, size);
}

int impactful_update_handler_write_staging (const struct firmware_update_control *update,
	uint8_t *buf, size_t buf_len)
{
	const struct impactful_update_handler *handler =
		TO_DERIVED_TYPE (update, const struct impactful_update_handler, base_ctrl);

	if (update == NULL) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	return handler->update->base_ctrl.write_staging (&handler->update->base_ctrl, buf, buf_len);
}

void impactful_update_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	const struct impactful_update_handler *fw =
		TO_DERIVED_TYPE (handler, const struct impactful_update_handler, base_event);
	int status;

	fw->update->base_event.execute (&fw->update->base_event, context, reset);

	/* Impactful operations only get executed after a firmware update has been executed.  Ignore
	 * any other events that may come here. */
	if (context->action == FIRMWARE_UPDATE_HANDLER_ACTION_RUN_UPDATE) {
		/* Only run impactful operations if the firmware update was successful.  This can be
		 * determined by checking getting the current update status. */
		status = fw->update->base_ctrl.get_status (&fw->update->base_ctrl);
		if (status == 0) {
			/* Impactful authorization is only valid for a single update.  If this fails,
			 * authorization will eventually time out, if configured to do so. */
			status = fw->impactful->reset_authorization (fw->impactful);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_IMPACTFUL_RESET_AUTH_FAIL, status, 0);
			}

			status = fw->impactful->is_update_not_impactful (fw->impactful);
			if (status != 0) {
				/* The update has been determined to be impactful, so disable the device reset that
				 * would normally apply the new firmware image. */
				firmware_update_handler_set_update_status_with_error (fw->update,
					UPDATE_STATUS_SUCCESS_NO_RESET, status);

				debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CERBERUS_FW,
					FIRMWARE_LOGGING_IMPACTFUL_UPDATE, status, 0);

				*reset = false;
			}
		}
	}
}

/**
 * Initialize a firmware update handler with support for handling updates that are impactful.
 *
 * @param handler The update handler to initialize.
 * @param state Variable context for the impactful handler.  THis must be uninitialized.
 * @param update The firmware update handler that will be used to execute firmware updates.
 * @param impactful An extension to the firmware update flow to handle impactful updates.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int impactful_update_handler_init (struct impactful_update_handler *handler,
	const struct firmware_update_handler *update,
	const struct impactful_update_interface *impactful)
{
	if ((handler == NULL) || (update == NULL) || (impactful == NULL)) {
		return IMPACTFUL_UPDATE_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (*handler));

	handler->base_ctrl.start_update = impactful_update_handler_start_update;
	handler->base_ctrl.get_status = impactful_update_handler_get_status;
	handler->base_ctrl.get_remaining_len = impactful_update_handler_get_remaining_len;
	handler->base_ctrl.prepare_staging = impactful_update_handler_prepare_staging;
	handler->base_ctrl.write_staging = impactful_update_handler_write_staging;

	handler->base_event.execute = impactful_update_handler_execute;

	handler->update = update;
	handler->impactful = impactful;

	return 0;
}

/**
 * Release the resources used by an impactful firmware update handler.
 *
 * @param handler The update handler to release.
 */
void impactful_update_handler_release (const struct impactful_update_handler *handler)
{
	UNUSED (handler);
}
