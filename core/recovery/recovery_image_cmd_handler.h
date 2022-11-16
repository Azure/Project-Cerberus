// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_CMD_HANDLER_H_
#define RECOVERY_IMAGE_CMD_HANDLER_H_

#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"
#include "system/event_task.h"


/**
 * Action identifiers for the recovery image command handler.
 */
enum {
	RECOVERY_IMAGE_CMD_HANDLER_ACTION_PREPARE = 1,	/**< Prepare the flash to receive a new image. */
	RECOVERY_IMAGE_CMD_HANDLER_ACTION_UPDATE = 2,	/**< Write image data to flash. */
	RECOVERY_IMAGE_CMD_HANDLER_ACTION_ACTIVATE = 4,	/**< Verify and enable a received recovery image. */
};

/**
 * Variable context for the recovery image command handler.
 */
struct recovery_image_cmd_handler_state {
	int status;									/**< The recovery image operation status. */
};


/**
 * The context for executing requests on a single recovery image.
 */
struct recovery_image_cmd_handler {
	struct recovery_image_cmd_interface base_cmd;	/**< The base interface for command handling. */
	struct event_task_handler base_event;			/**< THe base interface for task integration. */
	struct recovery_image_cmd_handler_state *state;	/**< Variable context for the handler. */
	struct recovery_image_manager *manager;			/**< The manager for the recovery image. */
	const struct event_task *task;					/**< The task context executing the handler. */
};


int recovery_image_cmd_handler_init (struct recovery_image_cmd_handler *handler,
	struct recovery_image_cmd_handler_state *state, struct recovery_image_manager *recovery,
	const struct event_task *task);
int recovery_image_cmd_handler_init_state (const struct recovery_image_cmd_handler *handler);
void recovery_image_cmd_handler_release (const struct recovery_image_cmd_handler *handler);


/* This module will be treated as an extension of the recovery image manager and use
 * RECOVERY_IMAGE_MANAGER_* error codes. */


#endif /* RECOVERY_IMAGE_CMD_HANDLER_H_ */
