// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_pcd.h"
#include "manifest/manifest_logging.h"


static int manifest_cmd_handler_pcd_activation (struct manifest_cmd_handler *task, bool *reset)
{
	/* Do not actually activate the PCD here.  PCDs require a device reset for the new settings to
	 * get applied, so leave the current settings active.  The new PCD will automatically get
	 * activated after the reset.  Schedule a device reset to activate the PCD. */
	*reset = true;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MANIFEST,
		MANIFEST_LOGGING_PCD_UPDATE, 0, 0);

	return 0;
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
