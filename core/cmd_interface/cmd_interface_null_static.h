// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_NULL_STATIC_H_
#define CMD_INTERFACE_NULL_STATIC_H_

#include "cmd_interface_null.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_null_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);


/**
 * Constant initializer for the command interface API.
 */
#define	CMD_INTERFACE_NULL_API_INIT { \
		.process_request = cmd_interface_null_process_request, \
		.session = NULL, \
	}


/**
 * Initialize a static instance of a command handler that will drop any received request/response
 * messages while providing the ability to generate valid error messages.
 */
#define	cmd_interface_null_static_init { \
		.base = CMD_INTERFACE_NULL_API_INIT, \
	}


#endif	/* CMD_INTERFACE_NULL_STATIC_H_ */
