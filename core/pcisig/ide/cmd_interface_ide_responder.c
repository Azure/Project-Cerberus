// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface_ide_responder.h"
#include "ide_commands.h"
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

	if (request->payload_length < sizeof (struct ide_km_header)) {
		status = CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE;
		goto exit;
	}
	ide_km_request = (const struct ide_km_header*) request->payload;

	switch (ide_km_request->object_id) {
		case IDE_KM_OBJECT_ID_QUERY:
			status = ide_km_query (ide_responder->ide_driver, request);
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

int cmd_interface_ide_responder_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	UNUSED (intf);
	UNUSED (request);
	UNUSED (error_code);
	UNUSED (error_data);
	UNUSED (cmd_set);

	return CMD_INTERFACE_IDE_RESPONDER_UNSUPPORTED_OPERATION;
}

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
	ide_responder->base.generate_error_packet =
		cmd_interface_ide_responder_generate_error_packet;

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