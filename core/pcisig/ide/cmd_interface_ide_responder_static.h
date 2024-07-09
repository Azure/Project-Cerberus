// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_IDE_RESPONDER_STATIC_H_
#define CMD_INTERFACE_IDE_RESPONDER_STATIC_H_

#include "cmd_interface_ide_responder.h"


/* Internal function declared to allow for static initialization. */
int cmd_interface_ide_responder_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_ide_responder_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_IDE_RESPONDER_RESPONSE_API    \
	.process_response = cmd_interface_ide_responder_process_response,
#else
#define	CMD_INTERFACE_IDE_RESPONDER_RESPONSE_API
#endif

/**
 * Constant initializer for the IDE Responder API.
 */
#define	CMD_INTERFACE_IDE_RESPONDER_API_INIT	{ \
		.process_request = cmd_interface_ide_responder_process_request, \
		CMD_INTERFACE_IDE_RESPONDER_RESPONSE_API \
	}


/**
 * IDE responder static initialization
 *
 * There is no validation done on the arguments.
 *
 * @param ide_driver_ptr IDE driver interface pointer.
 */
#define	cmd_interface_ide_responder_static_init(ide_driver_ptr)	{ \
		.base = CMD_INTERFACE_IDE_RESPONDER_API_INIT, \
		.ide_driver = ide_driver_ptr, \
	}


#endif	/* CMD_INTERFACE_IDE_RESPONDER_STATIC_H_ */
