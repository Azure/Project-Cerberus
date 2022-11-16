// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_CMD_HANDLER_PFM_STATIC_H_
#define MANIFEST_CMD_HANDLER_PFM_STATIC_H_

#include "manifest/manifest_cmd_handler_static.h"
#include "manifest/pfm/manifest_cmd_handler_pfm.h"


/* Internal functions declared to allow for static initialization. */
int manifest_cmd_handler_pfm_activation (const struct manifest_cmd_handler *handler, bool *reset);


/**
 * Initialize a static instance of a PFM handler.  This does not initialize the handler state.
 * This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the manifest handler.
 * @param manifest_ptr The manifest manager to use during command processing.
 * @param task_ptr The task that will be used to execute manifest operations.
 * @param host_ptr The host instance for the PFM.
 * @param host_state_ptr Manager of host state information.
 * @param hash_ptr Hash engine to use with run-time PFM activation.
 * @param rsa_ptr RSA engine to use with run-time PFM activation.
 * @param filter_ptr SPI filter for the host.
 */
#define	manifest_cmd_handler_pfm_static_init(state_ptr, manifest_ptr, task_ptr, host_ptr, \
	host_state_ptr, hash_ptr, rsa_ptr, filter_ptr)	{ \
		.base = manifest_cmd_handler_internal_static_init (state_ptr, manifest_ptr, task_ptr, \
			manifest_cmd_handler_pfm_activation), \
		.host = host_ptr, \
		.host_state = host_state_ptr, \
		.hash = hash_ptr, \
		.rsa = rsa_ptr, \
		.filter = filter_ptr, \
	}


#endif /* MANIFEST_CMD_HANDLER_PFM_STATIC_H_ */
