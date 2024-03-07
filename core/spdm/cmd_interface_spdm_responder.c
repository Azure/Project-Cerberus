// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_interface_spdm_responder.h"
#include "spdm_commands.h"
#include "common/unused.h"


/**
 * Process an SPDM protocol message.
 *
 * @param intf SPDM command responder interface.
 * @param request SPDM request message.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
int cmd_interface_spdm_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	const struct cmd_interface_spdm_responder *spdm_responder =
		(const struct cmd_interface_spdm_responder*) intf;
	uint8_t req_code;
	int status = 0;

	if ((spdm_responder == NULL) || (request == NULL)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	/* Pre-process the request and get the command Id. */
	status = spdm_get_command_id (request, &req_code);
	if (status != 0) {
		goto exit;
	}

	switch (req_code) {
		case SPDM_REQUEST_GET_VERSION:
			status = spdm_get_version (spdm_responder, request);
			break;

		case SPDM_REQUEST_GET_CAPABILITIES:
			status = spdm_get_capabilities (spdm_responder, request);
			break;

		case SPDM_REQUEST_NEGOTIATE_ALGORITHMS:
			status = spdm_negotiate_algorithms (spdm_responder, request);
			break;

		default:
			spdm_generate_error_response (request, 0, SPDM_ERROR_UNSUPPORTED_REQUEST, 0x00, NULL, 0,
				req_code, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION);
			break;
	}

exit:
	return status;
}

/**
 * Process an SPDM protocol response.
 *
 * @param intf SPDM command responder interface.
 * @param response SPDM response message.
 *
 * @return 0 if the message was successfully processed or an error code.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
int cmd_interface_spdm_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	UNUSED (intf);
	UNUSED (response);

	return CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION;
}
#endif

/**
 * Generate an SPDM error packet.
 *
 * @param intf SPDM command responder interface.
 * @param request SPDM request message.
 * @param error_code SPDM error code.
 * @param error_data SPDM error data.
 * @param cmd_set SPDM command set.
 *
 * @return 0 if the packet was generated successfully or an error code.
 */
int cmd_interface_spdm_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set)
{
	UNUSED (intf);
	UNUSED (request);
	UNUSED (error_code);
	UNUSED (error_data);
	UNUSED (cmd_set);

	return CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION;
}

/**
 * Initialize the SPDM responder instance.
 *
 * @param spdm_responder SPDM responder instance.
 * @param state SPDM state.
 * @param transcript_manager SPDM transcript manager.
 * @param hash_engine Hash engine instance.
 * @param version_num Supported SPDM version number entries.
 * @param version_num_count Number of version numbers entries.
 * @param local_capabilities Local SPDM capabilities.
 * @param local_algorithms Local SPDM algorithms.
 *
 * @return 0 if the SPDM responder instance was initialized successfully or an error code.
 */
int cmd_interface_spdm_responder_init (struct cmd_interface_spdm_responder *spdm_responder,
	struct spdm_state *state, struct spdm_transcript_manager *transcript_manager,
	struct hash_engine *hash_engine, const struct spdm_version_num_entry *version_num,
	uint8_t version_num_count, const struct spdm_device_capability *local_capabilities,
	const struct spdm_local_device_algorithms *local_algorithms)
{
	int status;

	if (spdm_responder == NULL) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	memset (spdm_responder, 0, sizeof (struct cmd_interface_spdm_responder));

	spdm_responder->state = state;
	spdm_responder->hash_engine = hash_engine;
	spdm_responder->transcript_manager = transcript_manager;
	spdm_responder->version_num = version_num;
	spdm_responder->version_num_count = version_num_count;
	spdm_responder->local_capabilities = local_capabilities;
	spdm_responder->local_algorithms = local_algorithms;

	spdm_responder->base.process_request = cmd_interface_spdm_process_request;
	spdm_responder->base.process_response = cmd_interface_spdm_process_response;
	spdm_responder->base.generate_error_packet = cmd_interface_spdm_generate_error_packet;

	status = cmd_interface_spdm_responder_init_state (spdm_responder);
	if (status != 0) {
		goto exit;
	}

exit:
	return status;
}

/**
 * Get the maximum supported version from the version number table.
 *
 * @param version_num Version number table.
 * @param version_num_count Number of entries in the version number table.
 *
 * @return Maximum supported version.
 */
static uint8_t cmd_interface_spdm_responder_get_max_supported_version (
	const struct spdm_version_num_entry *version_num, const uint8_t version_num_count) 
{
	uint8_t max_version = 0;
	uint8_t temp_version;
	uint8_t i;

	for (i = 0; i < version_num_count; i++) {
		temp_version = 
			SPDM_MAKE_VERSION (version_num[i].major_version, version_num[i].minor_version);
		if (temp_version > max_version) {
			max_version = temp_version;
		}
	}

	return max_version;
}

/**
 * Validate the capabilites of the local SPDM device.
 *
 * @param local_capabilities Local SPDM device capabilities.
 * @param supported_max_version Maximum supported SPDM version.
 *
 * @return 0 if capabilities are valid or an error code.
 */
static int cmd_interface_spdm_responder_validate_local_capabilities (
	const struct spdm_device_capability *local_capabilities, uint8_t supported_max_version)
{
	int status = 0;

	if (spdm_check_request_flag_compatibility (local_capabilities->flags, 
			supported_max_version) == false) {
		status = CMD_HANDLER_SPDM_RESPONDER_INCOMPATIBLE_CAPABILITIES;
		goto exit;
	}

	if (local_capabilities->ct_exponent > SPDM_MAX_CT_EXPONENT) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		goto exit;
	}

	if ((local_capabilities->data_transfer_size < SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2) ||
		(local_capabilities->data_transfer_size > local_capabilities->max_spdm_msg_size) ||
		((local_capabilities->flags.chunk_cap == 0) &&
		 (local_capabilities->data_transfer_size != local_capabilities->max_spdm_msg_size))) {
		status = CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY;
		goto exit;
	}

exit:
	return status;
}

/**
 * Initialize the SPDM responder state.
 *
 * @param spdm_responder SPDM responder instance.
 *
 * @return 0 if the SPDM responder state was initialized successfully or an error code.
 */
int cmd_interface_spdm_responder_init_state (
	const struct cmd_interface_spdm_responder *spdm_responder)
{
	int status;
	uint8_t supported_max_version;

	if ((spdm_responder == NULL) || (spdm_responder->hash_engine == NULL) ||
		(spdm_responder->transcript_manager == NULL) || (spdm_responder->version_num == NULL) ||
		(spdm_responder->version_num_count == 0) || (spdm_responder->local_capabilities == NULL) ||
		(spdm_responder->local_algorithms == NULL)) {
		status = CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT;
		goto exit;
	}

	/* Validate the local device capabilities. */
	supported_max_version = cmd_interface_spdm_responder_get_max_supported_version (
		spdm_responder->version_num, spdm_responder->version_num_count);

	status = cmd_interface_spdm_responder_validate_local_capabilities (
		spdm_responder->local_capabilities, supported_max_version);
	if (status != 0) {
		goto exit;
	}

	/* Initialize the SPDM state. */
	status = spdm_init_state (spdm_responder->state);
	if (status != 0) {
		goto exit;
	}

exit:
	return status;
}

/**
 * Deinitialize the SPDM responder instance.
 *
 * @param intf SPDM responder instance.
 */
void cmd_interface_spdm_responder_deinit (const struct cmd_interface_spdm_responder *spdm_responder)
{
	UNUSED (spdm_responder);
}
