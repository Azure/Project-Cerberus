// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "manifest_cmd_handler_cfm.h"
#include "common/unused.h"
#include "manifest/manifest_logging.h"


int manifest_cmd_handler_cfm_activation (const struct manifest_cmd_handler *handler, bool *reset)
{
	UNUSED (reset);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MANIFEST,
		MANIFEST_LOGGING_CFM_ACTIVATION, 0, 0);

	// No additional checking needed, activate pending CFM.
	handler->manifest->activate_pending_manifest (handler->manifest);

	return 0;
}

/**
 * Initialize a handler for executing CFM commands.
 *
 * @param handler The CFM handler to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param manifest The manifest manager to use during command processing.
 * @param task The task that will be used to execute CFM operations.
 *
 * @return 0 if the task was successfully initialized or an error code.
 */
int manifest_cmd_handler_cfm_init (struct manifest_cmd_handler_cfm *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task)
{
	int status;

	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (handler, 0, sizeof (struct manifest_cmd_handler_cfm));

	status = manifest_cmd_handler_init (&handler->base, state, manifest, task);
	if (status != 0) {
		return status;
	}

	handler->base.activation = manifest_cmd_handler_cfm_activation;

	return 0;
}

/**
 * Initialize only the variable state for a CFM handler.  The rest of the handler is assumed to
 * have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param handler The manifest handler that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int manifest_cmd_handler_cfm_init_state (const struct manifest_cmd_handler_cfm *handler)
{
	if (handler == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return manifest_cmd_handler_init_state (&handler->base);
}

/**
 * Release the resources used by a CFM handler.
 *
 * @param handler The manifest handler to release.
 */
void manifest_cmd_handler_cfm_release (const struct manifest_cmd_handler_cfm *handler)
{
	if (handler) {
		manifest_cmd_handler_release (&handler->base);
	}
}
