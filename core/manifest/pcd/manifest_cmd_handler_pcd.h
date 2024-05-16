// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_PCD_H_
#define MANIFEST_CMD_HANDLER_PCD_H_

#include "manifest/manifest_cmd_handler.h"


/**
 * A handler for executing requests for a single PCD.
 */
struct manifest_cmd_handler_pcd {
	struct manifest_cmd_handler base;	/**< Base manifest handler. */
};


int manifest_cmd_handler_pcd_init (struct manifest_cmd_handler_pcd *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task);
int manifest_cmd_handler_pcd_init_state (const struct manifest_cmd_handler_pcd *handler);
void manifest_cmd_handler_pcd_release (const struct manifest_cmd_handler_pcd *handler);


#endif	/* MANIFEST_CMD_HANDLER_PCD_H_ */
