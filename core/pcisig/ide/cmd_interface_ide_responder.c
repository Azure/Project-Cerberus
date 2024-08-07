// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_interface_ide_responder.h"
#include "ide_commands.h"
// #include "cmd_interface/cmd_interface.h"
#include "common/unused.h"


int cmd_interface_ide_responder_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	int status = 0;
	const struct ide_km_header *ide_km_request;
	const struct cmd_interface_ide_responder *ide_responder =
		(const struct cmd_interface_ide_responder*) intf;

	if ((ide_responder == NULL) || (request == NULL)) {
		status = CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	if (request->is_encrypted == false) {
		status = CMD_INTERFACE_IDE_RESPONDER_SECURE_SPDM_REQUIRED;
		goto exit;
	}

	if (request->payload_length < sizeof (struct ide_km_header)) {
		status = CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE;
		goto exit;
	}
	ide_km_request = (const struct ide_km_header*) request->payload;

	switch (ide_km_request->object_id) {
		case IDE_KM_OBJECT_ID_QUERY:
			status = ide_km_query (ide_responder->ide_driver, request);
			break;

		case IDE_KM_OBJECT_ID_KEY_PROG:
			status = ide_km_key_prog (ide_responder->ide_driver, request);
			break;

		case IDE_KM_OBJECT_ID_K_SET_GO:
			status = ide_km_key_set_go (ide_responder->ide_driver, request);
			break;

		case IDE_KM_OBJECT_ID_K_SET_STOP:
			status = ide_km_key_set_stop (ide_responder->ide_driver, request);
			break;

		default:
			status = CMD_INTERFACE_IDE_RESPONDER_UNKNOWN_COMMAND;
			break;
	}

exit:

	return status;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_ide_responder_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	UNUSED (intf);
	UNUSED (response);

	return CMD_INTERFACE_IDE_RESPONDER_UNSUPPORTED_OPERATION;
}
#endif

/**
 * Initialize the IDE responder instance.
 *
 * @param ide_responder The IDE responder instance to initialize.
 * @param ide_driver IDE driver interface to use for programming the IDE registers.
 *
 * @return 0 if the IDE responder instance was successfully initialized or an error code.
 */
int cmd_interface_ide_responder_init (struct cmd_interface_ide_responder *ide_responder,
	struct ide_driver *ide_driver)
{
	int status = 0;

	if ((ide_responder == NULL) || (ide_driver == NULL)) {
		status = CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (ide_responder, 0, sizeof (struct cmd_interface_ide_responder));
	ide_responder->ide_driver = ide_driver;

	ide_responder->base.process_request = cmd_interface_ide_responder_process_request;
	ide_responder->base.process_response = cmd_interface_ide_responder_process_response;

exit:

	return status;
}

/**
 * Release the resources used by the IDE responder instance.
 *
 * @param ide_interface IDE responder instance to release.
 */
void cmd_interface_ide_responder_release (const struct cmd_interface_ide_responder *ide_responder)
{
	UNUSED (ide_responder);
}
