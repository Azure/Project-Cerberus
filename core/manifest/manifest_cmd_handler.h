// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_H_
#define MANIFEST_CMD_HANDLER_H_

#include "manifest/manifest_cmd_interface.h"
#include "manifest/manifest_manager.h"
#include "system/event_task.h"


/**
 * Action identifiers for the manifest command handler.
 */
enum {
	MANIFEST_CMD_HANDLER_ACTION_PREPARE = 1,	/**< Prepare the pending region to receive a new manifest. */
	MANIFEST_CMD_HANDLER_ACTION_STORE = 2,		/**< Write manifest data into the pending region. */
	MANIFEST_CMD_HANDLER_ACTION_FINALIZE = 4,	/**< Verify a received manifest. */
	MANIFEST_CMD_HANDLER_ACTION_ACTIVATE = 8,	/**< Activate the manifest after verification. */
};

/**
 * Variable context for the manifest command handler.
 */
struct manifest_cmd_handler_state {
	int status;	/**< The manifest operation status. */
};

/**
 * A handler for requests on a single manifest.
 */
struct manifest_cmd_handler {
	struct manifest_cmd_interface base_cmd;		/**< The base interface for command handling. */
	struct event_task_handler base_event;		/**< THe base interface for task integration. */
	struct manifest_cmd_handler_state *state;	/**< Variable context for the handler. */
	const struct manifest_manager *manifest;	/**< The manager for the manifest. */
	const struct event_task *task;				/**< The task context executing the handler. */

	/**
	 * Internal call to use when activation of a manifest is requested.
	 *
	 * @param handler The manifest handler context.
	 * @param reset Output to indicate a device reset is needed as part of activation.  It is only
	 * necessary to update this value if a reset is required.
	 *
	 * @return Raw value to report as the manifest operation status.
	 */
	int (*activation) (const struct manifest_cmd_handler *handler, bool *reset);
};


int manifest_cmd_handler_init (struct manifest_cmd_handler *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task);
int manifest_cmd_handler_init_state (const struct manifest_cmd_handler *handler);
void manifest_cmd_handler_release (const struct manifest_cmd_handler *handler);

/* Internal functions for use by derived types. */
void manifest_cmd_handler_set_status (const struct manifest_cmd_handler *handler, int status);


/* This module will be treated as an extension of the manifest manager and use MANIFEST_MANAGER_*
 * error codes. */


#endif	/* MANIFEST_CMD_HANDLER_H_ */
