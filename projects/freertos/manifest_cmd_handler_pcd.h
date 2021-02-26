// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_PCD_H_
#define MANIFEST_CMD_HANDLER_PCD_H_

#include "manifest_cmd_handler.h"


/**
 * Task context for executing requests for a single PCD.
 */
struct manifest_cmd_handler_pcd {
	struct manifest_cmd_handler base;		/**< Base command task. */
};


int manifest_cmd_handler_pcd_init (struct manifest_cmd_handler_pcd *task,
	struct manifest_manager *manifest);


#endif /* MANIFEST_CMD_HANDLER_PCD_H_ */
