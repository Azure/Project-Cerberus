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


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_SPDM_RESPONDER_RESPONSE_API   \
	.process_response = cmd_interface_spdm_process_response,
#else
#define	CMD_INTERFACE_SPDM_RESPONDER_RESPONSE_API
#endif

/**
 * Constant initializer for the SPDM Responder API.
 */
#define	CMD_INTERFACE_SPDM_RESPONDER_API_INIT	{ \
	.process_request = cmd_interface_spdm_process_request, \
	CMD_INTERFACE_SPDM_RESPONDER_RESPONSE_API \
	}


/**
 * SPDM Responder Static Initialization.
 *
 * There is no validation done on the arguments.
 *
 * @param transcript_manager_ptr Transcript Manager instance pointer.
 * @param hash_engine_ptr Hash Engine instances array.
 * @param hash_engine_count_arg Number of Hash Engine instances.
 * @param version_num_ptr Array of supported version numbers.
 * @param version_num_count_arg Number of supported version numbers.
 * @param secured_message_version_num_ptr Supported secured message version numbers array.
 * @param secured_message_version_num_count_arg Number of supported secured message version numbers.
 * @param local_capabilities_ptr Local SPDM capabilities.
 * @param local_algorithms_ptr Local SPDM algorithms.
 * @param key_manager_ptr Key Manager instance pointer.
 * @param measurements_ptr Measurements instance pointer.
 * @param ecc_engine_ptr ECC Engine instance pointer.
 * @param rng_engine_ptr RNG Engine instance pointer.
 * @param session_manager_ptr Secure Session Manager instance pointer.
 * @param vdm_handler_ptr VDM command handler instance pointer.
 * @param spdm_context_ptr Persistent context for SPDM.
 */
#define	cmd_interface_spdm_responder_static_init(transcript_manager_ptr, \
	hash_engine_ptr, hash_engine_count_arg, version_num_ptr, version_num_count_arg, \
	secured_message_version_num_ptr, secured_message_version_num_count_arg, \
	local_capabilities_ptr, local_algorithms_ptr, key_manager_ptr, measurements_ptr, \
	ecc_engine_ptr, rng_engine_ptr, session_manager_ptr, vdm_handler_ptr, spdm_context_ptr)	{ \
		.base = CMD_INTERFACE_SPDM_RESPONDER_API_INIT, \
		.transcript_manager = transcript_manager_ptr, \
		.hash_engine = hash_engine_ptr, \
		.hash_engine_count = hash_engine_count_arg, \
		.version_num = version_num_ptr, \
		.version_num_count = version_num_count_arg, \
		.secure_message_version_num = secured_message_version_num_ptr, \
		.secure_message_version_num_count = secured_message_version_num_count_arg, \
		.local_capabilities = local_capabilities_ptr, \
		.local_algorithms = local_algorithms_ptr, \
		.key_manager = key_manager_ptr, \
		.measurements = measurements_ptr, \
		.ecc_engine = ecc_engine_ptr, \
		.rng_engine = rng_engine_ptr, \
		.session_manager = session_manager_ptr, \
		.vdm_handler = vdm_handler_ptr, \
		.spdm_context = spdm_context_ptr \
	}


#endif	/* CMD_INTERFACE_SPDM_RESPONDER_STATIC_H_ */
