// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_pcd.h"


static int manifest_cmd_handler_pcd_activation (struct manifest_cmd_handler *task)
{
	int status;

	status = task->manifest->activate_pending_manifest (task->manifest);
	if (status != 0) {
		status = MANIFEST_CMD_STATUS (MANIFEST_CMD_STATUS_ACTIVATION_FAIL, status);
	}

	return status;
}

/**
 * Initialize the task interface for executing PCD commands.
 *
 * @param task The task interface to initialize.
 * @param manifest The manifest manager to execute commands against.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int manifest_cmd_handler_pcd_init (struct manifest_cmd_handler_pcd *task,
	struct manifest_manager *manifest)
{
	int status;

	if (task == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct manifest_cmd_handler_pcd));

	status = manifest_cmd_handler_init (&task->base, manifest);
	if (status != 0) {
		return status;
	}

	task->base.activation = manifest_cmd_handler_pcd_activation;

	return 0;
}
