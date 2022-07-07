// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common/unused.h"
#include "cmd_interface/cmd_logging.h"
#include "logging/debug_log.h"
#include "spdm_protocol.h"
#include "spdm_protocol_observer.h"
#include "spdm_commands.h"
#include "cmd_interface_spdm.h"


/**
 * Pre-process received SPDM protocol message.
 *
 * @param intf The command interface that will process the message.
 * @param message The message being processed.
 * @param command_id Pointer to hold command ID of incoming message.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
static int cmd_interface_spdm_process_spdm_protocol_message (struct cmd_interface_spdm *intf,
	struct cmd_interface_msg *message, uint8_t *command_id)
{
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) message->data;

	message->crypto_timeout = false;

	if (message->length < SPDM_PROTOCOL_MIN_MSG_LEN) {
		return CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT;
	}

	if ((header->msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM)) {
		return CMD_HANDLER_SPDM_UNSUPPORTED_MSG;
	}

	if (header->spdm_major_version != SPDM_MAJOR_VERSION) {
		return CMD_HANDLER_SPDM_NOT_INTEROPERABLE;
	}

	*command_id = header->req_rsp_code;

	return 0;
}

static int cmd_interface_spdm_process_request (struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	UNUSED (intf);
	UNUSED (request);

	return CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION;
}

static int cmd_interface_spdm_process_response (struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	struct cmd_interface_spdm *interface = (struct cmd_interface_spdm*) intf;
	uint8_t rsp_code;
	int status;

	if ((interface == NULL) || (response == NULL)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	status = cmd_interface_spdm_process_spdm_protocol_message (interface, response, &rsp_code);
	if (status != 0) {
		return status;
	}

	switch (rsp_code) {
		case SPDM_RESPONSE_GET_VERSION:
			status = spdm_process_get_version_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_get_version_response),
					response);
			}

		case SPDM_RESPONSE_GET_CAPABILITIES:
			status = spdm_process_get_capabilities_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_get_capabilities_response),
					response);
			}

		case SPDM_RESPONSE_NEGOTIATE_ALGORITHMS:
			status = spdm_process_negotiate_algorithms_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_negotiate_algorithms_response),
					response);
			}

		case SPDM_RESPONSE_GET_DIGESTS:
			status = spdm_process_get_digests_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_get_digests_response),
					response);
			}

		case SPDM_RESPONSE_GET_CERTIFICATE:
			status = spdm_process_get_certificate_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_get_certificate_response),
					response);
			}

		case SPDM_RESPONSE_CHALLENGE:
			status = spdm_process_challenge_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_challenge_response),
					response);
			}

		case SPDM_RESPONSE_GET_MEASUREMENTS:
			status = spdm_process_get_measurements_response (response);
			if (status != 0) {
				return status;
			}
			else {
				return observable_notify_observers_with_ptr (&interface->observable,
					offsetof (struct spdm_protocol_observer, on_spdm_get_measurements_response),
					response);
			}

		case SPDM_RESPONSE_ERROR:
			if (response->length >= sizeof (struct spdm_error_response)) {
				struct spdm_error_response *error_msg =
					(struct spdm_error_response*) response->data;

				if (error_msg->error_code == SPDM_ERROR_RESPONSE_NOT_READY) {
					return observable_notify_observers_with_ptr (&interface->observable,
						offsetof (struct spdm_protocol_observer, on_spdm_response_not_ready),
						response);
				}
				else {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
						DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_ERROR_MESSAGE,
						(error_msg->error_code << 24 | response->source_eid << 16 |
						response->target_eid << 8),	error_msg->error_data);
				}
			}

			return CMD_HANDLER_ERROR_MESSAGE;

		default:
			return CMD_HANDLER_SPDM_UNKNOWN_COMMAND;
	}
}

static int cmd_interface_spdm_generate_error_packet (struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	UNUSED (intf);
	UNUSED (request);
	UNUSED (error_code);
	UNUSED (error_data);
	UNUSED (cmd_set);

	return CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION;
}

/**
 * Initialize SPDM command interface instance
 *
 * @param intf The SPDM command interface instance to initialize
 *
 * @return Initialization status, 0 if success or an error code.
 */
int cmd_interface_spdm_init (struct cmd_interface_spdm *intf)
{
	int status;

	if (intf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	memset (intf, 0, sizeof (struct cmd_interface_spdm));

	status = observable_init (&intf->observable);
	if (status != 0) {
		return status;
	}

	intf->base.process_request = cmd_interface_spdm_process_request;
	intf->base.process_response = cmd_interface_spdm_process_response;
	intf->base.generate_error_packet = cmd_interface_spdm_generate_error_packet;

	return 0;
}

/**
 * Deinitialize SPDM command interface instance
 *
 * @param intf The SPDM command interface instance to deinitialize
 */
void cmd_interface_spdm_deinit (struct cmd_interface_spdm *intf)
{
	if (intf != NULL) {
		observable_release (&intf->observable);
		memset (intf, 0, sizeof (struct cmd_interface_spdm));
	}
}

/**
 * Add an observer for SPDM protocol notifications.
 *
 * @param intf The SPDM interface instance to register with.
 * @param observer The observer to add.
 *
 * @return 0 if the observer was successfully added or an error code.
 */
int cmd_interface_spdm_add_spdm_protocol_observer (struct cmd_interface_spdm *intf,
	struct spdm_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	return observable_add_observer (&intf->observable, observer);
}

/**
 * Remove an observer from SPDM protocol notifications.
 *
 * @param intf The SPDM interface instance to deregister from.
 * @param observer The observer to remove.
 *
 * @return 0 if the observer was successfully removed or an error code.
 */
int cmd_interface_spdm_remove_spdm_protocol_observer (struct cmd_interface_spdm *intf,
	struct spdm_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&intf->observable, observer);
}
