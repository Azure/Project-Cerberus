// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_CFM_H_
#define MANIFEST_CMD_HANDLER_CFM_H_

#include "manifest/manifest_cmd_handler.h"


/**
 * A handler for executing requests for a single CFM.
 */
struct manifest_cmd_handler_cfm {
	struct manifest_cmd_handler base;		/**< Base manifest handler. */
};


int manifest_cmd_handler_cfm_init (struct manifest_cmd_handler_cfm *handler,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task);
int manifest_cmd_handler_cfm_init_state (const struct manifest_cmd_handler_cfm *handler);
void manifest_cmd_handler_cfm_release (const struct manifest_cmd_handler_cfm *handler);


#endif /* MANIFEST_CMD_HANDLER_CFM_H_ */
