// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_spdm.h"
#include "spdm_commands.h"
#include "spdm_protocol.h"
#include "spdm_protocol_observer.h"
#include "cmd_interface/cmd_logging.h"
#include "common/unused.h"
#include "logging/debug_log.h"


static int cmd_interface_spdm_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	UNUSED (intf);
	UNUSED (request);

	return CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
static int cmd_interface_spdm_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	struct cmd_interface_spdm *interface = (struct cmd_interface_spdm*) intf;
	uint8_t rsp_code;
	int status;

	if ((interface == NULL) || (response == NULL)) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	status = spdm_get_command_id (response, &rsp_code);
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
					offsetof (struct spdm_protocol_observer, on_spdm_challenge_response), response);
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
			if (response->payload_length >= sizeof (struct spdm_error_response)) {
				struct spdm_error_response *error_msg =
					(struct spdm_error_response*) response->payload;

				if (error_msg->error_code == SPDM_ERROR_RESPONSE_NOT_READY) {
					return observable_notify_observers_with_ptr (&interface->observable,
						offsetof (struct spdm_protocol_observer, on_spdm_response_not_ready),
						response);
				}
				else {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR,
						DEBUG_LOG_COMPONENT_CMD_INTERFACE, CMD_LOGGING_ERROR_MESSAGE,
						((error_msg->error_code << 24) | (response->source_eid << 16) |
									(response->target_eid << 8)), error_msg->error_data);
				}
			}

			return CMD_HANDLER_ERROR_MESSAGE;

		default:
			return CMD_HANDLER_SPDM_UNKNOWN_COMMAND;
	}
}
#endif

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
#ifdef CMD_ENABLE_ISSUE_REQUEST
	intf->base.process_response = cmd_interface_spdm_process_response;
#endif

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
	const struct spdm_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	return observable_add_observer (&intf->observable, (void*) observer);
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
	const struct spdm_protocol_observer *observer)
{
	if (intf == NULL) {
		return CMD_HANDLER_SPDM_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&intf->observable, (void*) observer);
}
