// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "cmd_interface_mctp_control.h"
#include "mctp_base_protocol.h"
#include "mctp_control_protocol.h"
#include "mctp_control_protocol_commands.h"
#include "mctp_logging.h"
#include "cmd_interface/cmd_interface.h"
#include "common/unused.h"

/**
 * Pre-process received MCTP control protocol message.
 *
 * @param intf The command interface that will process the message.
 * @param message The message being processed.
 * @param command_id Pointer to hold command ID of incoming message.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
static int cmd_interface_mctp_control_process_mctp_protocol_message (
	const struct cmd_interface_mctp_control *intf, struct cmd_interface_msg *message,
	uint8_t *command_id)
{
	struct mctp_control_protocol_header *header;
	struct mctp_control_protocol_resp_header *rsp_header;

	UNUSED (intf);

	message->crypto_timeout = false;

	if (message->payload_length < MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_MCTP_CTRL_PAYLOAD_TOO_SHORT;
	}

	header = (struct mctp_control_protocol_header*) message->payload;

	if (header->d_bit != 0) {
		return CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG;
	}

	if (header->rsvd != 0) {
		return CMD_HANDLER_MCTP_CTRL_RSVD_NOT_ZERO;
	}

	*command_id = header->command_code;

	if (header->rq == 0) {
		rsp_header = (struct mctp_control_protocol_resp_header*) message->payload;

		if (rsp_header->completion_code != MCTP_CONTROL_PROTOCOL_SUCCESS) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
				MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL, rsp_header->completion_code,
				(message->source_eid << 8) | *command_id);

			return CMD_HANDLER_ERROR_MESSAGE;
		}
	}
	else {
		header->rq = 0;
	}

	return 0;
}

/**
 * Generate MCTP control error response.
 *
 * @param message Message containing the request payload buffer to update.
 * @param command_id Command code to include in the response header.
 * @param completion_code Completion code to return in the response.
 */
static void cmd_interface_mctp_control_generate_error_response (struct cmd_interface_msg *message,
	uint8_t command_id, uint8_t completion_code)
{
	struct mctp_control_protocol_resp_header *rsp_header;

	rsp_header = (struct mctp_control_protocol_resp_header*) message->payload;

	rsp_header->header.d_bit = 0;
	rsp_header->header.rq = 0;
	rsp_header->header.rsvd = 0;
	rsp_header->header.command_code = command_id;
	rsp_header->completion_code = completion_code;

	cmd_interface_msg_set_message_payload_length (message, MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
}

static int cmd_interface_mctp_control_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct cmd_interface_mctp_control *interface = (struct cmd_interface_mctp_control*) intf;
	uint8_t command_id;
	int notify_status;
	int status;

	if (request == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	status = cmd_interface_mctp_control_process_mctp_protocol_message (interface, request,
		&command_id);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case MCTP_CONTROL_PROTOCOL_SET_EID:
			status = mctp_control_protocol_set_eid (interface->device_manager, request);
			if (status == 0) {
				notify_status = observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct mctp_control_protocol_observer, on_set_eid_request), NULL);

				if (notify_status != 0) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
						MCTP_LOGGING_SET_EID_NOTIFY_FAIL, notify_status, request->channel_id);
				}
			}
			break;

		case MCTP_CONTROL_PROTOCOL_GET_EID:
			status = mctp_control_protocol_get_eid (interface->device_manager, request);
			break;

		case MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION:
			status = mctp_control_protocol_get_mctp_version_support (request);
			break;

		case MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE:
			status = mctp_control_protocol_get_message_type_support (request);
			break;

		case MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT:
			status = mctp_control_protocol_get_vendor_def_msg_support (interface->pci_vendor_id,
				interface->protocol_version, request);
			break;

		default:
			/*
			 * As per MCTP Base Spec DSP0236_1.3.3, Section 12.6 and section 12.3
			 * completion shall be returned for any unsupported command values received
			 * in MCTP control Request messages.
			 */
			status = mctp_control_protocol_unsupported_cmd (request);
	}

	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL, status, request->channel_id);

		cmd_interface_mctp_control_generate_error_response (request, command_id,
			MCTP_CONTROL_PROTOCOL_ERROR);
	}

	return 0;
}

/**
 * Initialize MCTP control command interface instance
 *
 * @param intf The MCTP control command interface instance to initialize
 * @param device_manager Device manager instance to utilize
 * @param pci_vendor_id Cerberus protocol PCI vendor ID
 * @param protocol_version Cerberus protocol version
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_mctp_control_init (struct cmd_interface_mctp_control *intf,
	struct device_manager *device_manager, uint16_t pci_vendor_id, uint16_t protocol_version)
{
	int status;

	if ((intf == NULL) || (device_manager == NULL)) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_mctp_control));

	status = observable_init (&intf->observable);
	if (status != 0) {
		return status;
	}

	intf->device_manager = device_manager;

	intf->pci_vendor_id = pci_vendor_id;
	intf->protocol_version = protocol_version;

	intf->base.process_request = cmd_interface_mctp_control_process_request;

	return 0;
}

/**
 * Deinitialize MCTP control command interface instance
 *
 * @param intf The MCTP control command interface instance to deinitialize
 */
void cmd_interface_mctp_control_deinit (struct cmd_interface_mctp_control *intf)
{
	if (intf != NULL) {
		observable_release (&intf->observable);
		memset (intf, 0, sizeof (struct cmd_interface_mctp_control));
	}
}

/**
 * Add an observer for MCTP control notifications.
 *
 * @param intf The MCTP control interface instance to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int cmd_interface_mctp_control_add_mctp_control_protocol_observer (
	struct cmd_interface_mctp_control *intf, const struct mctp_control_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	return observable_add_observer (&intf->observable, (void*) observer);
}

/**
 * Remove an observer from MCTP control notifications.
 *
 * @param intf The MCTP control interface instance to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int cmd_interface_mctp_control_remove_mctp_control_protocol_observer (
	struct cmd_interface_mctp_control *intf, const struct mctp_control_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&intf->observable, (void*) observer);
}
