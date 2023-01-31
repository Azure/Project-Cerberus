// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_STATIC_H_
#define MANIFEST_CMD_HANDLER_STATIC_H_

#include "manifest_cmd_handler.h"


/* Internal functions declared to allow for static initialization. */
int manifest_cmd_handler_prepare_manifest (const struct manifest_cmd_interface *cmd,
	uint32_t manifest_size);
int manifest_cmd_handler_store_manifest (const struct manifest_cmd_interface *cmd,
	const uint8_t *data, size_t length);
int manifest_cmd_handler_finish_manifest (const struct manifest_cmd_interface *cmd, bool activate);
int manifest_cmd_handler_get_status (const struct manifest_cmd_interface *cmd);

void manifest_cmd_handler_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset);


/**
 * Constant initializer for the manifest command API.
 */
#define	MANIFEST_CMD_HANDLER_COMMAND_API_INIT  { \
		.prepare_manifest = manifest_cmd_handler_prepare_manifest, \
		.store_manifest = manifest_cmd_handler_store_manifest, \
		.finish_manifest = manifest_cmd_handler_finish_manifest, \
		.get_status = manifest_cmd_handler_get_status \
	}

/**
 * Constant initializer for the manifest task API.
 */
#define	MANIFEST_CMD_HANDLER_EVENT_API_INIT  { \
		.execute = manifest_cmd_handler_execute \
	}


/**
 * Initialize a static instance of a manifest handler.  This does not initialize the handler state.
 * This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the manifest handler.
 * @param manifest_ptr The manifest manager to use during command processing.
 * @param task_ptr The task that will be used to execute manifest operations.
 */
#define	manifest_cmd_handler_static_init(state_ptr, manifest_ptr, task_ptr)	{ \
		.base_cmd = MANIFEST_CMD_HANDLER_COMMAND_API_INIT, \
		.base_event = MANIFEST_CMD_HANDLER_EVENT_API_INIT, \
		.state = state_ptr, \
		.manifest = manifest_ptr, \
		.task = task_ptr \
	}

/**
 * Initializer for a base static instance of a manifest handler that can be used by derived types.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the manifest handler.
 * @param manifest_ptr The manifest manager to use during command processing.
 * @param task_ptr The task that will be used to execute manifest operations.
 * @param activate Function to use for activation.
 */
#define	manifest_cmd_handler_internal_static_init(state_ptr, manifest_ptr, task_ptr, activate)	{ \
		.base_cmd = MANIFEST_CMD_HANDLER_COMMAND_API_INIT, \
		.base_event = MANIFEST_CMD_HANDLER_EVENT_API_INIT, \
		.state = state_ptr, \
		.manifest = manifest_ptr, \
		.task = task_ptr, \
		.activation = activate \
	}


#endif /* MANIFEST_CMD_HANDLER_STATIC_H_ */
