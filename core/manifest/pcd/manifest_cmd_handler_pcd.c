// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_pcd.h"
#include "common/unused.h"
#include "manifest/manifest_logging.h"


int manifest_cmd_handler_pcd_activation (const struct manifest_cmd_handler *handler, bool *reset)
{
	UNUSED (handler);

	/* Do not actually activate the PCD here.  PCDs require a device reset for the new settings to
	 * get applied, so leave the current settings active.  The new PCD will automatically get
	 * activated after the reset.  Schedule a device reset to activate the PCD. */
	*reset = true;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MANIFEST,
		MANIFEST_LOGGING_PCD_UPDATE, 0, 0);

	return 0;
}

/**
 * Initialize a handler for executing PCD commands.
 *
 * @param handler The PCD handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param manifest The manifest manager to use during command processing.
 * @param task The task that will be used to execute PCD operations.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int manifest_cmd_handler_pcd_init (struct manifest_cmd_handler_pcd *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task)
{
	int status;

	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct manifest_cmd_handler_pcd));

	status = manifest_cmd_handler_init (&handler->base, state, manifest, task);
	if (status != 0) {
		return status;
	}

	handler->base.activation = manifest_cmd_handler_pcd_activation;

	return 0;
}

/**
 * Initialize only the variable state for a PCD handler.  The rest of the handler is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The manifest handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_cmd_handler_pcd_init_state (const struct manifest_cmd_handler_pcd *handler)
{
	return manifest_cmd_handler_init_state (&handler->base);
}

/**
 * Release the resources used by a PCD handler.
 *
 * @param handler The manifest handler to release.
 */
void manifest_cmd_handler_pcd_release (const struct manifest_cmd_handler_pcd *handler)
{
	if (handler) {
		manifest_cmd_handler_release (&handler->base);
	}
}
