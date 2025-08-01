// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_TDISP_RESPONDER_STATIC_H_
#define CMD_INTERFACE_TDISP_RESPONDER_STATIC_H_

#include "cmd_interface_tdisp_responder.h"


/* Internal function declared to allow for static initialization. */
int cmd_interface_tdisp_responder_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_tdisp_responder_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_TDISP_RESPONDER_RESPONSE_API  \
	.process_response = cmd_interface_tdisp_responder_process_response,
#else
#define	CMD_INTERFACE_TDISP_RESPONDER_RESPONSE_API
#endif

/**
 * Constant initializer for the TDISP Responder API.
 */
#define	CMD_INTERFACE_TDISP_RESPONDER_API_INIT	{ \
		.process_request = cmd_interface_tdisp_responder_process_request, \
		CMD_INTERFACE_TDISP_RESPONDER_RESPONSE_API \
	}


/**
 * TDISP responder static initialization.
 *
 * There is no validation done on the arguments.
 *
 * @param tdi_context_manager_ptr TDI context manager
 * @param tdisp_driver_ptr TDISP driver interface pointer.
 * @param version_num_ptr Array of supported version numbers.
 * @param version_num_count_arg Number of supported version numbers.
 * @param rng_engine_ptr Random number generator engine.
 */
#define	cmd_interface_tdisp_responder_static_init(tdi_context_manager_ptr, tdisp_driver_ptr, \
	version_num_ptr, version_num_count_arg, rng_engine_ptr)	{ \
		.base = CMD_INTERFACE_TDISP_RESPONDER_API_INIT, \
		.tdi_context_manager = tdi_context_manager_ptr, \
		.tdisp_driver = tdisp_driver_ptr, \
		.version_num = version_num_ptr, \
		.version_num_count = version_num_count_arg, \
		.rng_engine = rng_engine_ptr \
	}


#endif	/* CMD_INTERFACE_TDISP_RESPONDER_STATIC_H_ */
