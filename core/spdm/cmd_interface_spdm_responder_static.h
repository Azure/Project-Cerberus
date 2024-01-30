// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_SPDM_RESPONDER_STATIC_H_
#define CMD_INTERFACE_SPDM_RESPONDER_STATIC_H_

#include "cmd_interface_spdm_responder.h"


/* Internal function declarations to allow for static initialization. */
int cmd_interface_spdm_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);

int cmd_interface_spdm_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);

int cmd_interface_spdm_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set);

/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_SPDM_RESPONDER_RESPONSE_API	\
	.process_response = cmd_interface_spdm_process_response,
#else
#define	CMD_INTERFACE_SPDM_RESPONDER_RESPONSE_API
#endif

/**
 * Constant initializer for the SPDM Responder API.
 */
#define	CMD_INTERFACE_SPDM_RESPONDER_API_INIT { \
	.process_request = cmd_interface_spdm_process_request, \
	CMD_INTERFACE_SPDM_RESPONDER_RESPONSE_API \
	.generate_error_packet = cmd_interface_spdm_generate_error_packet \
	}

/**
 * SPDM Responder Static Initialization.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr SPDM Responder state pointer.
 * @param transcript_manager_ptr Transcript Manager instance pointer.
 * @param hash_engine_ptr Hash Engine instance pointer.
 * @param version_num_ptr Array of supported version numbers.
 * @param version_num_count_arg Number of supported version numbers.
 */
#define	cmd_interface_spdm_responder_static_init(state_ptr, transcript_manager_ptr, hash_engine_ptr, \
		version_num_ptr, version_num_count_arg) { \
		.base = CMD_INTERFACE_SPDM_RESPONDER_API_INIT, \
		.state = state_ptr, \
		.transcript_manager = transcript_manager_ptr, \
		.hash_engine = hash_engine_ptr, \
		.version_num = version_num_ptr, \
		.version_num_count = version_num_count_arg \
	}

#endif /* CMD_INTERFACE_SPDM_RESPONDER_STATIC_H_ */