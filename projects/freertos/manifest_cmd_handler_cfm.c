// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_cfm.h"
#include "manifest/manifest_logging.h"


static int manifest_cmd_handler_cfm_activation (struct manifest_cmd_handler *task, bool *reset)
{
	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MANIFEST,
		MANIFEST_LOGGING_CFM_ACTIVATION, 0, 0);

	// No additional checking needed, activate pending CFM.
	task->manifest->activate_pending_manifest (task->manifest);

	return 0;
}

/**
 * Initialize the task interface for executing CFM commands.
 *
 * @param task The task interface to initialize.
 * @param manifest The manifest manager to execute commands against.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int manifest_cmd_handler_cfm_init (struct manifest_cmd_handler_cfm *task,
	struct manifest_manager *manifest)
{
	int status;

	if (task == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (task, 0, sizeof (struct manifest_cmd_handler_cfm));

	status = manifest_cmd_handler_init (&task->base, manifest);
	if (status != 0) {
		return status;
	}

	task->base.activation = manifest_cmd_handler_cfm_activation;

	return 0;
}
