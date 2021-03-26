// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_H_
#define MANIFEST_CMD_HANDLER_H_

#include "manifest/manifest_cmd_interface.h"
#include "manifest/manifest_manager.h"
#include "config_cmd_task.h"


/**
 * The context for handling requests on a single manifest.
 */
struct manifest_cmd_handler {
	struct manifest_cmd_interface base;			/**< The base API for interfacing with the handler. */
	struct config_cmd_task_handler cmd_base;	/**< THe base API for interfacing with the task. */
	struct manifest_manager *manifest;			/**< The manager for the manifest. */
	struct config_cmd_task *task;				/**< The task context executing the handler. */
	int status;									/**< The manifest operation status. */
	uint8_t id;									/**< The manifest task ID. */

	/**
	 * Internal call to use when activation of a manifest is requested.
	 *
	 * @param handler The manifest handler context.
	 * @param reset Output to indicate a device reset is needed as part of activation.  It is only
	 * necessary to update this value if a reset is required.
	 *
	 * @return Raw value to report as the manifest operation status.
	 */
	int (*activation) (struct manifest_cmd_handler *handler, bool *reset);
};


int manifest_cmd_handler_init (struct manifest_cmd_handler *handler,
	struct manifest_manager *manifest);

/* Internal functions for use by derived types. */
void manifest_cmd_handler_set_status (struct manifest_cmd_handler *handler, int status);


#endif /* MANIFEST_CMD_HANDLER_H_ */
