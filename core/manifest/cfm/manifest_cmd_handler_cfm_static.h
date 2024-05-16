// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_CFM_STATIC_H_
#define MANIFEST_CMD_HANDLER_CFM_STATIC_H_

#include "manifest/cfm/manifest_cmd_handler_cfm.h"
#include "manifest/manifest_cmd_handler_static.h"


/* Internal functions declared to allow for static initialization. */
int manifest_cmd_handler_cfm_activation (const struct manifest_cmd_handler *handler, bool *reset);


/**
 * Initialize a static instance of a CFM handler.  This does not initialize the handler state.
 * This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the manifest handler.
 * @param manifest_ptr The manifest manager to use during command processing.
 * @param task_ptr The task that will be used to execute manifest operations.
 */
#define	manifest_cmd_handler_cfm_static_init(state_ptr, manifest_ptr, task_ptr)	{ \
		.base = manifest_cmd_handler_internal_static_init (state_ptr, manifest_ptr, task_ptr, \
			manifest_cmd_handler_cfm_activation), \
	}


#endif	/* MANIFEST_CMD_HANDLER_CFM_STATIC_H_ */
