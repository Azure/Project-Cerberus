// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface_ide_responder.h"
#include "ide_commands.h"
#include "common/unused.h"


/**
 * Process an IDE_KM QUERY message.
 *
 * @param ide_driver The IDE driver to query.
 * @param request The IDE_KM QUERY request to process.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
int ide_km_query (const struct ide_driver *ide_driver, struct cmd_interface_msg *request)
{
	int status = 0;
	const struct ide_km_query *ide_km_request;
	struct ide_km_query_resp *ide_km_response;
	uint8_t port_index;
	struct ide_capability_register *capability_register;
	uint8_t* ptr;
	uint8_t block_idx;
	size_t ide_addr_assoc_reg_block_length;
	size_t available_payload_length;
	size_t incr_length;

	if ((ide_driver == NULL) || (request == NULL)) {
		status = CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	/* As per the IDE specification, a strict size check is required. */
	if (request->payload_length != sizeof (struct ide_km_query)) {
		status = CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE;
		goto exit;
	}
	ide_km_request = (const struct ide_km_query*) request->payload;
	port_index = ide_km_request->port_index;

	/* Construct the response. */
	ide_km_response = (struct ide_km_query_resp*) request->payload;
	memset (ide_km_response, 0, sizeof (struct ide_km_query_resp));

	ide_km_response->header.object_id = IDE_KM_OBJECT_ID_QUERY_RESP;
	ide_km_response->port_index = port_index;

	/* Get the bus, device func and segment info. */
	status = ide_driver->get_bus_device_segment_info (ide_driver, port_index,
		&ide_km_response->bus_num, &ide_km_response->dev_func_num, &ide_km_response->segment,
		&ide_km_response->max_port_index);
	if (status != 0) {
		goto exit;
	}

	/* Add the capability register value. */
	capability_register = (struct ide_capability_register*) &ide_km_response->capability_register;
	status = ide_driver->get_capability_register (ide_driver, port_index, capability_register);
	if (status != 0) {
		goto exit;
	}

	/* Add the control register value. */
	status = ide_driver->get_control_register (ide_driver, port_index,
		(struct ide_control_register*) &ide_km_response->control_register);
	if (status != 0) {
		goto exit;
	}

	/* Add the Link IDE Stream Register block(s). */
	available_payload_length = cmd_interface_msg_get_max_response (request);
	if (available_payload_length < sizeof (struct ide_km_query_resp)) {
		status = CMD_INTERFACE_IDE_RESPONDER_OUT_OF_BUFFER_SPACE;
		goto exit;
	}

	ptr = (uint8_t*) (ide_km_response + 1);
	available_payload_length -= sizeof (struct ide_km_query_resp);
	if (capability_register->link_ide_stream_supported == 1) {

		for (block_idx = 0;
			block_idx < (capability_register->number_of_tcs_supported_for_link_ide + 1);
			block_idx++) {

			if (available_payload_length < sizeof (struct ide_link_ide_stream_register_block)) {
				status = CMD_INTERFACE_IDE_RESPONDER_OUT_OF_BUFFER_SPACE;
				goto exit;
			}

			/* Add the Link IDE Stream Register Block. */
			status = ide_driver->get_link_ide_register_block (ide_driver, port_index, block_idx,
				(struct ide_link_ide_stream_register_block*) ptr);
			if (status != 0) {
				goto exit;
			}

			incr_length = sizeof (struct ide_link_ide_stream_register_block);
			ptr += incr_length;
			available_payload_length -= incr_length;
		}
	}

	/* Add the Selective IDE Stream Register block(s). */
	if (capability_register->selective_ide_streams_supported == 1) {

		for (block_idx = 0;
			block_idx < (capability_register->number_of_selective_ide_streams_supported + 1);
			block_idx++) {

			if (available_payload_length < sizeof (struct ide_selective_ide_stream_register_block)) {
				status = CMD_INTERFACE_IDE_RESPONDER_OUT_OF_BUFFER_SPACE;
				goto exit;
			}

			/* Add the Selective IDE Stream Register Block. */
			status = ide_driver->get_selective_ide_stream_register_block (ide_driver, port_index,
				block_idx, (struct ide_selective_ide_stream_register_block*) ptr);
			if (status != 0) {
				goto exit;
			}

			ide_addr_assoc_reg_block_length = 
			((struct ide_selective_ide_stream_capability_register*)
				ptr)->number_of_address_association_register_blocks *
			(sizeof (struct ide_selective_ide_address_association_register_block));

			incr_length = 
				(offsetof (struct ide_selective_ide_stream_register_block, addr_assoc_reg_block) +
				ide_addr_assoc_reg_block_length);
			ptr += incr_length;
			available_payload_length -= incr_length;
		}
	}

	cmd_interface_msg_set_message_payload_length (request,
		((size_t) ptr - (size_t) (ide_km_response)));

exit:
	return status;
}

