// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_CFM_H_
#define MANIFEST_CMD_HANDLER_CFM_H_

#include "manifest_cmd_handler.h"


/**
 * Task context for executing requests for a single CFM.
 */
struct manifest_cmd_handler_cfm {
	struct manifest_cmd_handler base;		/**< Base command task. */
};


int manifest_cmd_handler_cfm_init (struct manifest_cmd_handler_cfm *task,
	struct manifest_manager *manifest);


#endif /* MANIFEST_CMD_HANDLER_CFM_H_ */
