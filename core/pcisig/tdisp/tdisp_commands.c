// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "cmd_interface_tdisp_responder.h"
#include "tdisp_commands.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_interface.h"
#include "common/buffer_util.h"


/* [TODO] Log the error code generated from internal functions in this file. */

/**
 * Generate a TDISP error response message.
 *
 * @param response The response message to generate.
 * @param version The TDISP version to use for the response.
 * @param function_id The function Id of the request that generated the error.
 * @param error_code The error code to include in the response.
 * @param error_data Additional error data to include in the response.
 */
void tdisp_generate_error_response (struct cmd_interface_msg *response, uint8_t version,
	uint32_t function_id, uint32_t error_code, uint32_t error_data)
{
	struct tdisp_error_response *tdisp_response = (struct tdisp_error_response*) response->payload;

	memset (tdisp_response, 0, sizeof (struct tdisp_error_response));
	tdisp_response->header.version = version;
	tdisp_response->header.message_type = TDISP_ERROR;
	tdisp_response->header.interface_id.function_id.value = function_id;
	tdisp_response->error_code = error_code;
	tdisp_response->error_data = error_data;

	cmd_interface_msg_set_message_payload_length (response, sizeof (struct tdisp_error_response));
}

/**
 * Process the TDISP request and return the response.
 *
 * @param tdisp_state The TDISP state.
 * @param version_num The array of supported version numbers.
 * @param version_num_count The number of supported version numbers.
 * @param request The request to process.
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_get_version (const struct tdisp_driver *tdisp_driver,	const uint8_t *version_num,
	uint8_t version_num_count, struct cmd_interface_msg *request)
{
	uint32_t status = 0;
	const struct tdisp_get_version_request *tdisp_request;
	struct tdisp_version_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	size_t version_array_length;
	size_t response_length;
	size_t available_payload_length;
	uint32_t function_index;

	if ((tdisp_driver == NULL) || (version_num == NULL) || (version_num_count == 0) ||
		(request == NULL)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_get_version_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_get_version_request*) request->payload;
	tdisp_response = (struct tdisp_version_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	version_array_length = version_num_count * sizeof (uint8_t);
	response_length = sizeof (struct tdisp_version_response) + version_array_length;

	/* Check if sufficient buffer is available for the response. */
	available_payload_length = cmd_interface_msg_get_max_response (request);
	if (available_payload_length < response_length) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	status = tdisp_driver->get_function_index (tdisp_driver, function_id.bdf, &function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* Construct the response message. */
	memset (tdisp_response, 0, response_length);

	tdisp_response->version_num_count = version_num_count;
	tdisp_response->header.version = TDISP_VERSION_1_0;
	tdisp_response->header.message_type = TDISP_RESPONSE_GET_VERSION;
	tdisp_response->header.interface_id.function_id = function_id;
	memcpy ((void*) (tdisp_version_response_get_version_num_offset (tdisp_response)), version_num,
		version_array_length);

	cmd_interface_msg_set_message_payload_length (request, response_length);

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}

/**
 * Process the TDISP GET_CAPABILITIES request and return the response.
 *
 * @param tdisp_driver The TDISP driver to use for processing the request.
 * @param request The GET_CAPABILITIES request to process.
 * @param tdisp_messages Array message IDs supported by TDSIP responder
 * @param tdisp_messages_count Number of messages supported by TDISP responder
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_get_capabilities (const struct tdisp_driver *tdisp_driver, const uint8_t *tdisp_messages,
	uint32_t tdisp_messages_count, struct cmd_interface_msg *request)
{
	int status = 0;
	const struct tdisp_get_capabilities_request *tdisp_request;
	struct tdisp_capabilities_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	struct tdisp_responder_capabilities rsp_caps = {0};
	size_t available_payload_length;
	uint32_t bit_index;
	size_t i;

	if ((tdisp_driver == NULL) || (request == NULL) || (tdisp_messages == NULL) ||
		(tdisp_messages_count == 0)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_get_capabilities_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_get_capabilities_request*) request->payload;
	tdisp_response = (struct tdisp_capabilities_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	/* Check if sufficient buffer is available for the response. */
	available_payload_length = cmd_interface_msg_get_max_response (request);
	if (available_payload_length < sizeof (struct tdisp_capabilities_response)) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	/* Provide requester capabilities to the driver. Also get the responder's capabilities. */
	status = tdisp_driver->get_tdisp_capabilities (tdisp_driver, &tdisp_request->req_caps,
		&rsp_caps);
	if (status != 0) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	/* Report supported TDISP messages */
	for (i = 0; i < tdisp_messages_count; i++) {
		bit_index = tdisp_messages[i] - 0x80;
		rsp_caps.req_msg_supported[bit_index / 8] |= (1 << (bit_index % 8));
	}

	/* Construct the response message. */
	tdisp_response->header.version = TDISP_VERSION_1_0;
	tdisp_response->header.message_type = TDISP_RESPONSE_GET_CAPABILITIES;
	tdisp_response->header.interface_id.function_id = function_id;
	tdisp_response->rsp_caps = rsp_caps;

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct tdisp_capabilities_response));

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}

/**
 * Process the TDISP LOCK_INTERFACE request and return the response.
 *
 * @param tdi_context_manager TDI context manager.
 * @param tdisp_driver The TDISP driver to use for processing the request.
 * @param rng_engine The random number generator to use for generating nonces.
 * @param request The LOCK_INTERFACE request to process.
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_lock_interface (const struct tdisp_tdi_context_manager *tdi_context_manager,
	const struct tdisp_driver *tdisp_driver, const struct rng_engine *rng_engine,
	struct cmd_interface_msg *request)
{
	int status = 0;
	const struct tdisp_lock_interface_request *tdisp_request;
	struct tdisp_lock_interface_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	uint32_t function_index;
	size_t available_payload_length;
	struct tdisp_tdi_context tdi_context = {};

	if ((tdi_context_manager == NULL) || (tdisp_driver == NULL) || (rng_engine == NULL) ||
		(request == NULL)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_lock_interface_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_lock_interface_request*) request->payload;
	tdisp_response = (struct tdisp_lock_interface_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	/* Check if sufficient buffer is available for the response. */
	available_payload_length = cmd_interface_msg_get_max_response (request);
	if (available_payload_length < sizeof (struct tdisp_lock_interface_response)) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	status = tdisp_driver->get_function_index (tdisp_driver, function_id.bdf, &function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* TODO: check HW for the interface state */
	status = tdi_context_manager->get_tdi_context (tdi_context_manager, function_index, 0,
		&tdi_context);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	if ((tdi_context.tdi_context_mask & TDISP_TDI_CONTEXT_MASK_NONCE) != 0) {
		/* This means that this TDI was locked before and hasn't been reset since. */
		status = TDISP_ERROR_CODE_INVALID_INTERFACE_STATE;
		goto exit;
	}

	/* Generate the start interface nonce. */
	status = rng_engine->generate_random_buffer (rng_engine,
		sizeof (tdi_context.start_interface_nonce),	tdi_context.start_interface_nonce);
	if (status != 0) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	/* Call the TDISP driver to lock the interface. */
	status = tdisp_driver->lock_interface_request (tdisp_driver, function_index,
		&tdisp_request->lock_interface_param);
	if (status != 0) {
		switch (status) {
			case TDISP_DRIVER_IDE_NOT_SECURE:
				status = TDISP_ERROR_CODE_INVALID_REQUEST;
				break;

			default:
				status = TDISP_ERROR_CODE_UNSPECIFIED;
		}
		goto exit;
	}

	status = tdi_context_manager->set_start_nonce (tdi_context_manager, function_index,
		tdi_context.start_interface_nonce, sizeof (tdi_context.start_interface_nonce));
	if (status != 0) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	/* Construct the response. */
	memset (tdisp_response, 0, sizeof (struct tdisp_lock_interface_response));
	tdisp_response->header.version = TDISP_VERSION_1_0;
	tdisp_response->header.message_type = TDISP_RESPONSE_LOCK_INTERFACE;
	tdisp_response->header.interface_id.function_id = function_id;
	memcpy (tdisp_response->start_interface_nonce, tdi_context.start_interface_nonce,
		sizeof (tdisp_response->start_interface_nonce));

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct tdisp_lock_interface_response));

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}

/**
 * Process the TDISP GET_DEVICE_REPORT request and return the response.
 *
 * @param tdisp_driver The TDISP driver to use for processing the request.
 * @param request The GET_DEVICE_REPORT request to process.
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_get_device_interface_report (const struct tdisp_driver *tdisp_driver,
	struct cmd_interface_msg *request)
{
	uint32_t status;
	const struct tdisp_get_device_interface_report_request *tdisp_request;
	struct tdisp_device_interface_report_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	uint32_t function_index;
	uint16_t report_length;
	uint16_t remainder_length;
	size_t available_payload_length;

	if ((tdisp_driver == NULL) || (request == NULL)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_get_device_interface_report_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_get_device_interface_report_request*) request->payload;
	tdisp_response = (struct tdisp_device_interface_report_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	/* Check if sufficient buffer is available for the response. */
	available_payload_length = cmd_interface_msg_get_max_response (request);
	if (available_payload_length < sizeof (struct tdisp_device_interface_report_response)) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	status = tdisp_driver->get_function_index (tdisp_driver, function_id.bdf, &function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* Account for the response header size.*/
	available_payload_length -= sizeof (struct tdisp_device_interface_report_response);

	/* Report chunk is limited to max. UINT16_MAX. */
	report_length = (available_payload_length > UINT16_MAX) ?
			UINT16_MAX : (uint16_t) available_payload_length;

	/* Call the TDISP driver to get the device interface report. */
	status = tdisp_driver->get_device_interface_report (tdisp_driver, function_index,
		tdisp_request->offset, tdisp_request->length, &report_length,
		tdisp_device_interface_report_resp_report_ptr (tdisp_response), &remainder_length);
	if (status != 0) {
		switch (status) {
			case TDISP_DRIVER_INVALID_ARGUMENT:
				status = TDISP_ERROR_CODE_INVALID_REQUEST;
				break;

			case TDISP_DRIVER_INVALID_INTERFACE:
				status = TDISP_ERROR_CODE_INVALID_INTERFACE;
				break;

			case TDISP_DRIVER_INTERFACE_INVALID_STATE:
				status = TDISP_ERROR_CODE_INVALID_INTERFACE_STATE;
				break;

			default:
				status = TDISP_ERROR_CODE_UNSPECIFIED;
		}
		goto exit;
	}

	/* Construct the response message. */
	memset (tdisp_response, 0, sizeof (struct tdisp_device_interface_report_response));
	tdisp_response->header.version = TDISP_VERSION_1_0;
	tdisp_response->header.message_type = TDISP_RESPONSE_GET_DEVICE_INTERFACE_REPORT;
	tdisp_response->header.interface_id.function_id = function_id;
	tdisp_response->portion_length = report_length;
	tdisp_response->remainder_length = remainder_length;

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct tdisp_device_interface_report_response) + report_length);

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}

/**
 * Process the TDISP GET_DEVICE_INTERFACE_STATE request and return the response.
 *
 * @param tdisp_driver The TDISP driver to use for processing the request.
 * @param request The GET_DEVICE_INTERFACE_STATE request to process.
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_get_device_interface_state (const struct tdisp_driver *tdisp_driver,
	struct cmd_interface_msg *request)
{
	uint32_t status = 0;
	const struct tdisp_get_device_interface_state_request *tdisp_request;
	struct tdisp_device_interface_state_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	uint32_t function_index;
	uint8_t tdi_state;

	if ((tdisp_driver == NULL) || (request == NULL)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_get_device_interface_state_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_get_device_interface_state_request*) request->payload;
	tdisp_response = (struct tdisp_device_interface_state_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	/* Check if sufficient buffer is available for the response. */
	if (cmd_interface_msg_get_max_response (request) <
		sizeof (struct tdisp_device_interface_state_response)) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	status = tdisp_driver->get_function_index (tdisp_driver, function_id.bdf, &function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* Query the driver for the the TDI state. */
	status = tdisp_driver->get_device_interface_state (tdisp_driver, function_index, &tdi_state);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* Construct the response message. */
	memset (tdisp_response, 0, sizeof (struct tdisp_device_interface_state_response));
	tdisp_response->header.version = TDISP_VERSION_1_0;
	tdisp_response->header.message_type = TDISP_RESPONSE_GET_DEVICE_INTERFACE_STATE;
	tdisp_response->header.interface_id.function_id = function_id;
	tdisp_response->tdi_state = tdi_state;

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct tdisp_device_interface_state_response));

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}

/**
 * Process the TDISP START_INTERFACE request and return the response.
 *
 * @param tdi_context_manager The TDISP TDI context manager.
 * @param tdisp_driver The TDISP driver to use for processing the request.
 * @param request The START_INTERFACE request to process.
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_start_interface (const struct tdisp_tdi_context_manager *tdi_context_manager,
	const struct tdisp_driver *tdisp_driver, struct cmd_interface_msg *request)
{
	uint32_t status = 0;
	const struct tdisp_start_interface_request *tdisp_request;
	struct tdisp_start_interface_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	struct tdisp_tdi_context tdi_context = {};
	uint32_t function_index;

	if ((tdi_context_manager == NULL) || (tdisp_driver == NULL) || (request == NULL)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_start_interface_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_start_interface_request*) request->payload;
	tdisp_response = (struct tdisp_start_interface_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	status = tdisp_driver->get_function_index (tdisp_driver, function_id.bdf, &function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* Check the nonce received against the one that was sent in the LOCK_INTERFACE response. */
	status = tdi_context_manager->get_tdi_context (tdi_context_manager, function_index,
		TDISP_TDI_CONTEXT_MASK_NONCE, &tdi_context);
	if (status != 0) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	if ((tdi_context.tdi_context_mask & TDISP_TDI_CONTEXT_MASK_NONCE) == 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE_STATE;
		goto exit;
	}

	if (buffer_compare (tdisp_request->start_interface_nonce, tdi_context.start_interface_nonce,
		TDISP_START_INTERFACE_NONCE_SIZE) != 0) {
		status = TDISP_ERROR_CODE_INVALID_NONCE;
		goto exit;
	}

	/* Clear the stored nonce after successful verification. */
	if (sizeof (*tdisp_request) > sizeof (*tdisp_response)) {
		buffer_zeroize (tdisp_response + 1, sizeof (*tdisp_request) - sizeof (*tdisp_response));
	}

	/* Call the TDISP driver to start the interface. */
	status = tdisp_driver->start_interface_request (tdisp_driver, function_index);
	if (status != 0) {
		switch (status) {
			case TDISP_DRIVER_INTERFACE_INVALID_STATE:
				status = TDISP_ERROR_CODE_INVALID_INTERFACE_STATE;
				break;

			default:
				status = TDISP_ERROR_CODE_UNSPECIFIED;
		}
		goto exit;
	}

	/* Construct the response message.
	 * Response is smaller than the request, so output buffer size check is not needed.*/
	tdisp_response->header.message_type = TDISP_RESPONSE_START_INTERFACE;

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct tdisp_start_interface_response));

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}

/**
 * Process the TDISP STOP_INTERFACE request and return the response.
 *
 * @param tdisp_driver The TDISP driver to use for processing the request.
 * @param request The STOP_INTERFACE request to process.
 *
 * @return 0 if request processed successfully (including TDISP error msg) or an error code.
 */
int tdisp_stop_interface (const struct tdisp_driver *tdisp_driver,
	struct cmd_interface_msg *request)
{
	uint32_t status;
	const struct tdisp_stop_interface_request *tdisp_request;
	struct tdisp_stop_interface_response *tdisp_response;
	union tdisp_function_id function_id = {0};
	uint32_t function_index;

	if ((tdisp_driver == NULL) || (request == NULL)) {
		return CMD_INTERFACE_TDISP_RESPONDER_INVALID_ARGUMENT;
	}

	if (request->payload_length != sizeof (struct tdisp_stop_interface_request)) {
		status = TDISP_ERROR_CODE_INVALID_REQUEST;
		goto exit;
	}
	tdisp_request = (const struct tdisp_stop_interface_request*) request->payload;
	tdisp_response = (struct tdisp_stop_interface_response*) request->payload;
	function_id = tdisp_request->header.interface_id.function_id;

	if (tdisp_request->header.version != TDISP_VERSION_1_0) {
		status = TDISP_ERROR_CODE_VERSION_MISMATCH;
		goto exit;
	}

	status = tdisp_driver->get_function_index (tdisp_driver, function_id.bdf, &function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_INVALID_INTERFACE;
		goto exit;
	}

	/* Call the TDISP driver to stop the interface. */
	status = tdisp_driver->stop_interface_request (tdisp_driver, function_index);
	if (status != 0) {
		status = TDISP_ERROR_CODE_UNSPECIFIED;
		goto exit;
	}

	/* Construct the response message.
	 * Response size is same as that of request, so output buffer size check is not needed.*/
	tdisp_response->header.message_type = TDISP_RESPONSE_STOP_INTERFACE;

	cmd_interface_msg_set_message_payload_length (request,
		sizeof (struct tdisp_stop_interface_response));

exit:
	if (status != 0) {
		tdisp_generate_error_response (request, TDISP_VERSION_1_0, function_id.value, status, 0);
	}

	return 0;
}
