// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RECOVERY_IMAGE_CMD_HANDLER_H_
#define RECOVERY_IMAGE_CMD_HANDLER_H_

#include "recovery/recovery_image_cmd_interface.h"
#include "recovery/recovery_image_manager.h"
#include "config_cmd_task.h"


/**
 * The context for executing requests on a single recovery image.
 */
struct recovery_image_cmd_handler {
	struct recovery_image_cmd_interface base;	/**< The base API for interfacing with the handler. */
	struct config_cmd_task_handler cmd_base;	/**< THe base API for interfacing with the task. */
	struct recovery_image_manager *manager;		/**< The manager for the recovery image. */
	struct config_cmd_task *task;				/**< The task context executing the handler. */
	int status;									/**< The recovery image operation status. */
	uint8_t id;									/**< The recovery image task ID. */
};


int recovery_image_cmd_handler_init (struct recovery_image_cmd_handler *handler,
	struct recovery_image_manager *recovery);


#endif /* RECOVERY_IMAGE_CMD_HANDLER_H_ */
