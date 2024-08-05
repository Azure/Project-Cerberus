// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef IMPACTFUL_UPDATE_HANDLER_STATIC_H_
#define IMPACTFUL_UPDATE_HANDLER_STATIC_H_

#include "impactful_update_handler.h"


/* Internal functions declared to allow for static initialization. */
int impactful_update_handler_start_update (const struct firmware_update_control *update);
int impactful_update_handler_get_status (const struct firmware_update_control *update);
int32_t impactful_update_handler_get_remaining_len (const struct firmware_update_control *update);
int impactful_update_handler_prepare_staging (const struct firmware_update_control *update,
	size_t size);
int impactful_update_handler_write_staging (const struct firmware_update_control *update,
	uint8_t *buf, size_t buf_len);

void impactful_update_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset);


/**
 * Constant initializer for the firmware update control API.
 */
#define	IMPACTFUL_UPDATE_HANDLER_CONTROL_API_INIT  { \
		.start_update = impactful_update_handler_start_update, \
		.get_status = impactful_update_handler_get_status, \
		.get_remaining_len = impactful_update_handler_get_remaining_len, \
		.prepare_staging = impactful_update_handler_prepare_staging, \
		.write_staging = impactful_update_handler_write_staging \
	}

/**
 * Constant initializer for the impactful update task API.
 */
#define	IMPACTFUL_UPDATE_HANDLER_EVENT_API_INIT  { \
		.prepare = NULL, \
		.execute = impactful_update_handler_execute \
	}


/**
 * Initialize a static instance of a firmware update handler with support for handling updates that
 * are impactful.  This does not initialize the handler state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param update_ptr The firmware update handler that will be used to execute firmware updates.
 * @param impactful_ptr An extension to the firmware update flow to handle impactful updates.
 */
#define	impactful_update_handler_static_init(update_ptr, impactful_ptr)	{ \
		.base_ctrl = IMPACTFUL_UPDATE_HANDLER_CONTROL_API_INIT, \
		.base_event = IMPACTFUL_UPDATE_HANDLER_EVENT_API_INIT, \
		.update = update_ptr, \
		.impactful = impactful_ptr, \
	}


#endif	/* IMPACTFUL_UPDATE_HANDLER_STATIC_H_ */
