// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_CMD_HANDLER_STATIC_H_
#define RECOVERY_IMAGE_CMD_HANDLER_STATIC_H_

#include "recovery_image_cmd_handler.h"


/* Internal functions declared to allow for static initialization. */
int recovery_image_cmd_handler_prepare_recovery_image (
	const struct recovery_image_cmd_interface *cmd, uint32_t image_size);
int recovery_image_cmd_handler_update_recovery_image (
	const struct recovery_image_cmd_interface *cmd, const uint8_t *data, size_t length);
int recovery_image_cmd_handler_activate_recovery_image (
	const struct recovery_image_cmd_interface *cmd);
int recovery_image_cmd_handler_get_status (const struct recovery_image_cmd_interface *cmd);

void recovery_image_cmd_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset);


/**
 * Constant initializer for the recovery image command API.
 */
#define	RECOVERY_IMAGE_CMD_HANDLER_COMMAND_API_INIT  { \
		.prepare_recovery_image = recovery_image_cmd_handler_prepare_recovery_image, \
		.update_recovery_image = recovery_image_cmd_handler_update_recovery_image, \
		.activate_recovery_image = recovery_image_cmd_handler_activate_recovery_image, \
		.get_status = recovery_image_cmd_handler_get_status \
	}

/**
 * Constant initializer for the recovery image task API.
 */
#define	RECOVERY_IMAGE_CMD_HANDLER_EVENT_API_INIT  { \
		.execute = recovery_image_cmd_handler_execute \
	}


/**
 * Initialize a static instance of a recovery image handler.  This does not initialize the handler
 * state. This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the recovery image handler.
 * @param recovery_ptr The recovery image manager to use during command processing.
 * @param task_ptr The task that will be used to execute recovery image operations.
 */
#define	recovery_image_cmd_handler_static_init(state_ptr, recovery_ptr, task_ptr)	{ \
		.base_cmd = RECOVERY_IMAGE_CMD_HANDLER_COMMAND_API_INIT, \
		.base_event = RECOVERY_IMAGE_CMD_HANDLER_EVENT_API_INIT, \
		.state = state_ptr, \
		.manager = recovery_ptr, \
		.task = task_ptr \
	}


#endif	/* RECOVERY_IMAGE_CMD_HANDLER_STATIC_H_ */
