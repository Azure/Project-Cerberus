// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "common/unused.h"
#include "cmd_interface/cmd_interface.h"
#include "mctp_base_protocol.h"
#include "mctp_control_protocol.h"
#include "mctp_control_protocol_commands.h"
#include "cmd_interface_mctp_control.h"


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
	struct cmd_interface_mctp_control *intf, struct cmd_interface_msg *message, uint8_t *command_id)
{
	struct mctp_control_protocol_header *header;

	message->crypto_timeout = false;

	if (message->length < MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_MCTP_CTRL_PAYLOAD_TOO_SHORT;
	}

	header = (struct mctp_control_protocol_header*) message->data;

	if ((header->msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG) ||
		(header->integrity_check != 0) || (header->d_bit != 0)) {
		return CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_MSG;
	}

	if (header->rsvd != 0) {
		return CMD_HANDLER_MCTP_CTRL_RSVD_NOT_ZERO;
	}

	header->rq = 0;

	*command_id = header->command_code;

	return 0;
}

static int cmd_interface_mctp_control_process_request (struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct cmd_interface_mctp_control *interface = (struct cmd_interface_mctp_control*) intf;
	uint8_t command_id;
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
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct mctp_control_protocol_observer, on_set_eid_request), NULL);
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
			status = CMD_HANDLER_MCTP_CTRL_UNKNOWN_REQUEST;
	}

	return status;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
static int cmd_interface_mctp_control_process_response (struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	struct cmd_interface_mctp_control *interface = (struct cmd_interface_mctp_control*) intf;
	uint8_t command_id;
	int status;

	if (response == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	status = cmd_interface_mctp_control_process_mctp_protocol_message (interface, response,
		&command_id);
	if (status != 0) {
		return status;
	}

	switch (command_id) {
		case MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE:
			status = mctp_control_protocol_process_get_message_type_support_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct mctp_control_protocol_observer, on_get_message_type_response),
						response);
			}

		case MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT:
			status = mctp_control_protocol_process_get_vendor_def_msg_support_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct mctp_control_protocol_observer,
						on_get_vendor_def_msg_response), response);
			}

		case MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES:
			status = mctp_control_protocol_process_get_routing_table_entries_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct mctp_control_protocol_observer,
						on_get_routing_table_entries_response), response);
			}

		default:
			return CMD_HANDLER_MCTP_CTRL_UNKNOWN_RESPONSE;
	}
}
#endif

static int cmd_interface_mctp_control_generate_error_packet (struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	UNUSED (intf);
	UNUSED (request);
	UNUSED (error_code);
	UNUSED (error_data);
	UNUSED (cmd_set);

    return CMD_HANDLER_MCTP_CTRL_UNSUPPORTED_OPERATION;
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
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_mctp_control_process_response;
#endif
	intf->base.generate_error_packet = cmd_interface_mctp_control_generate_error_packet;

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
	struct cmd_interface_mctp_control *intf, struct mctp_control_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	return observable_add_observer (&intf->observable, observer);
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
	struct cmd_interface_mctp_control *intf, struct mctp_control_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&intf->observable, observer);
}
