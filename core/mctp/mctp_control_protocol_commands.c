// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mctp_base_protocol.h"
#include "mctp_control_protocol.h"
#include "mctp_control_protocol_commands.h"
#include "mctp_logging.h"
#include "platform_api.h"
#include "cmd_interface/device_manager.h"
#include "spdm/spdm_protocol.h"


/**
 * Populate the protocol header segment of a MCTP control request
 *
 * @param header Buffer to fill with MCTP control header
 * @param command Command ID to utilize in header
 */
static void mctp_control_protocol_populate_header (struct mctp_control_protocol_header *header,
	uint8_t command)
{
	header->instance_id = 0;
	header->rsvd = 0;
	header->d_bit = 0;
	header->rq = 1;
	header->command_code = command;
}

/**
 * Process Set EID request packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Set EID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int mctp_control_protocol_set_eid (struct device_manager *device_mgr,
	struct cmd_interface_msg *request)
{
	struct mctp_control_set_eid *rq;
	struct mctp_control_set_eid_response *response;
	uint8_t eid_assigned;
	int status;

	if ((device_mgr == NULL) || (request == NULL)) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	rq = (struct mctp_control_set_eid*) request->payload;
	response = (struct mctp_control_set_eid_response*) request->payload;

	if (request->payload_length != sizeof (struct mctp_control_set_eid)) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->payload_length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_SET_EID);
	}
	else if ((rq->reserved != 0) || (rq->operation > MCTP_CONTROL_SET_EID_OPERATION_FORCE_ID) ||
		(rq->eid == MCTP_BASE_PROTOCOL_NULL_EID) || (rq->eid == MCTP_BASE_PROTOCOL_BROADCAST_EID)) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_DATA;
	}
	else {
		status = device_manager_update_device_eid (device_mgr, DEVICE_MANAGER_SELF_DEVICE_NUM,
			rq->eid);
		if (status != 0) {
			goto update_device_mgr_fail;
		}

		status = device_manager_update_not_attestable_device_entry (device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, request->source_eid, request->source_addr,
			DEVICE_MANAGER_NOT_PCD_COMPONENT);
		if (status != 0) {
			goto update_device_mgr_fail;
		}

		eid_assigned = rq->eid;

		response->header.completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
		cmd_interface_msg_set_message_payload_length (request,
			sizeof (struct mctp_control_set_eid_response));

		response->eid_setting = eid_assigned;
		response->eid_assignment_status = MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED;
		response->reserved1 = 0;
		response->reserved2 = 0;
		response->eid_allocation_status = MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL;
		response->eid_pool_size = 0;
	}

	return 0;

update_device_mgr_fail:
	cmd_interface_msg_set_message_payload_length (request, MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
	response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
		MCTP_LOGGING_SET_EID_FAIL, status, request->channel_id);

	return 0;
}

/**
 * Process Get EID request packet
 *
 * @param device_mgr Device manager instance to utilize
 * @param request Get EID request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int mctp_control_protocol_get_eid (struct device_manager *device_mgr,
	struct cmd_interface_msg *request)
{
	struct mctp_control_get_eid_response *response;
	int status;

	if ((device_mgr == NULL) || (request == NULL)) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	response = (struct mctp_control_get_eid_response*) request->payload;

	if (request->payload_length != sizeof (struct mctp_control_get_eid)) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);

		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->payload_length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_EID);
	}
	else {
		status = device_manager_get_device_eid (device_mgr, 0);
		if (ROT_IS_ERROR (status)) {
			cmd_interface_msg_set_message_payload_length (request,
				MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
			response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR;

			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
				MCTP_LOGGING_GET_EID_FAIL, status, request->channel_id);

			return 0;
		}

		cmd_interface_msg_set_message_payload_length (request,
			sizeof (struct mctp_control_get_eid_response));

		response->header.completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
		response->eid = status;
		response->eid_type = MCTP_CONTROL_GET_EID_EID_TYPE_STATIC_EID_SUPPORTED;
		response->reserved = 0;
		response->endpoint_type = MCTP_CONTROL_GET_EID_ENDPOINT_TYPE_SIMPLE_ENDPOINT;
		response->reserved2 = 0;
		response->medium_specific_info = 0;
	}

	return 0;
}

/**
 * Process Get MCTP Version Support request packet
 *
 * @param request Get MCTP Version Support request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int mctp_control_protocol_get_mctp_version_support (struct cmd_interface_msg *request)
{
	struct mctp_control_get_mctp_version *rq;
	struct mctp_control_get_mctp_version_response *response;
	struct mctp_control_mctp_version_number_entry *version_entry;

	if (request == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	rq = (struct mctp_control_get_mctp_version*) request->payload;
	response = (struct mctp_control_get_mctp_version_response*) request->payload;

	if (request->payload_length != sizeof (struct mctp_control_get_mctp_version)) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->payload_length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION);

		return 0;
	}

	version_entry = mctp_control_get_mctp_version_response_get_entries (response);

	switch (rq->message_type_num) {
		case MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG:
			response->version_num_entry_count = 1;
			version_entry->alpha = 0;
			version_entry->update = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				MCTP_CONTROL_PROTOCOL_UPDATE_VERSION;
			version_entry->minor = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				MCTP_CONTROL_PROTOCOL_MINOR_VERSION;
			version_entry->major = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				MCTP_CONTROL_PROTOCOL_MAJOR_VERSION;
			break;

		case MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF:
			response->version_num_entry_count = 1;
			version_entry->alpha = 0;
			version_entry->update = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_IGNORE_UPDATE;
			version_entry->minor = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING | 0;
			version_entry->major = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				CERBERUS_PROTOCOL_PROTOCOL_VERSION;
			break;

		case MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM:
			response->version_num_entry_count = 1;
			version_entry->alpha = 0;
			version_entry->update = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_IGNORE_UPDATE;
			version_entry->minor = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				SPDM_MAX_MINOR_VERSION;
			version_entry->major = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				SPDM_MAJOR_VERSION;

			break;

		case 0xFF:
			response->version_num_entry_count = 1;
			version_entry->alpha = 0;
			version_entry->update = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				MCTP_BASE_PROTOCOL_UPDATE_VERSION;
			version_entry->minor = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				MCTP_BASE_PROTOCOL_MINOR_VERSION;
			version_entry->major = MCTP_CONTROL_GET_MCTP_VERSION_VERSION_ENCODING |
				MCTP_BASE_PROTOCOL_MAJOR_VERSION;
			break;

		default:
			cmd_interface_msg_set_message_payload_length (request,
				MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);

			response->header.completion_code = MCTP_CONTROL_GET_MCTP_VERSION_MSG_TYPE_UNSUPPORTED;

			return 0;
	}

	cmd_interface_msg_set_message_payload_length (request,
		mctp_control_get_mctp_version_response_length (response->version_num_entry_count));

	response->header.completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;

	return 0;
}

/**
 * Process Get Message Type Support request packet
 *
 * @param request Get Message Type Support request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int mctp_control_protocol_get_message_type_support (struct cmd_interface_msg *request)
{
	struct mctp_control_get_message_type_response *response;
	uint8_t *message_type_list;

	if (request == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}
	response = (struct mctp_control_get_message_type_response*) request->payload;

	if (request->payload_length != sizeof (struct mctp_control_get_message_type)) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);

		return 0;
	}

	response->message_type_count = 3;

	message_type_list = mctp_control_get_message_type_response_get_entries (response);

	message_type_list[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	message_type_list[1] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	message_type_list[2] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	cmd_interface_msg_set_message_payload_length (request,
		mctp_control_get_message_type_response_length (response->message_type_count));
	response->header.completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;

	return 0;
}

/**
 * Construct Get Message Type Support request.
 *
 * @param buf The buffer containing the generated request.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request if the request was successfully constructed or an
 * error code.
 */
int mctp_control_protocol_generate_get_message_type_support_request (uint8_t *buf, size_t buf_len)
{
	struct mctp_control_get_message_type *rq = (struct mctp_control_get_message_type*) buf;

	if (rq == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct mctp_control_get_message_type)) {
		return CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL;
	}

	mctp_control_protocol_populate_header (&rq->header, MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);

	return sizeof (struct mctp_control_get_message_type);
}

/**
 * Process Get Message Type Support response. This function only ensures the response is valid per
 * MCTP control protocol response definition.
 *
 * @param response Get Message Type Support response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int mctp_control_protocol_process_get_message_type_support_response (
	struct cmd_interface_msg *response)
{
	struct mctp_control_get_message_type_response *rsp;

	if (response == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	rsp = (struct mctp_control_get_message_type_response*) response->payload;

	if ((response->payload_length <= sizeof (struct mctp_control_get_message_type_response)) ||
		(response->payload_length !=
		mctp_control_get_message_type_response_length (rsp->message_type_count))) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	return 0;
}

/**
 * Process vendor defined message support request packet
 *
 * @param interface MCTP interface to utilize
 * @param request Vendor defined message support request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
int mctp_control_protocol_get_vendor_def_msg_support (uint16_t pci_vendor_id,
	uint16_t protocol_version, struct cmd_interface_msg *request)
{
	struct mctp_control_get_vendor_def_msg_support *rq;
	struct mctp_control_get_vendor_def_msg_support_pci_response *response;

	if (request == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	rq = (struct mctp_control_get_vendor_def_msg_support*) request->payload;
	response = (struct mctp_control_get_vendor_def_msg_support_pci_response*) request->payload;

	if (request->payload_length != sizeof (struct mctp_control_get_vendor_def_msg_support)) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->payload_length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);
	}
	else if (rq->vid_set_selector != CERBERUS_VID_SET) {
		cmd_interface_msg_set_message_payload_length (request,
			MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN);
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_DATA;
	}
	else {
		cmd_interface_msg_set_message_payload_length (request,
			sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response));
		response->header.completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
		response->vid_set_selector = CERBERUS_VID_SET_RESPONSE;
		response->vid_format = MCTP_BASE_PROTOCOL_VID_FORMAT_PCI;
		response->vid = platform_htons (pci_vendor_id);
		response->protocol_version = platform_htons (protocol_version);
	}

	return 0;
}

/**
 * Construct Get Vendor Defined Message Support request.
 *
 * @param vendor_id_set Vendor ID set selector to use in request.
 * @param buf The buffer containing the generated request.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request if the request was successfully constructed or an
 * error code.
 */
int mctp_control_protocol_generate_get_vendor_def_msg_support_request (uint8_t vendor_id_set,
	uint8_t *buf, size_t buf_len)
{
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) buf;

	if (rq == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct mctp_control_get_vendor_def_msg_support)) {
		return CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL;
	}

	mctp_control_protocol_populate_header (&rq->header,
		MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT);

	rq->vid_set_selector = vendor_id_set;

	return sizeof (struct mctp_control_get_vendor_def_msg_support);
}

/**
 * Process Get Vendor Defined Message Support response. This function only ensures the response is
 * valid per MCTP control protocol response definition.
 *
 * @param response Get Vendor Defined Message Support response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int mctp_control_protocol_process_get_vendor_def_msg_support_response (
	struct cmd_interface_msg *response)
{
	struct mctp_control_get_vendor_def_msg_support_pci_response *rsp;
	size_t expected_len;

	if (response == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	rsp = (struct mctp_control_get_vendor_def_msg_support_pci_response*) response->payload;

	if (response->payload_length <
		sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response)) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	switch (rsp->vid_format) {
		case MCTP_CONTROL_PCI_VID_FORMAT:
			expected_len = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response);
			break;

		case MCTP_CONTROL_IANA_VID_FORMAT:
			expected_len = sizeof (struct mctp_control_get_vendor_def_msg_support_iana_response);
			break;

		default:
			return CMD_HANDLER_MCTP_CTRL_OUT_OF_RANGE;
	}

	if (response->payload_length != expected_len) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct Get Routing Table Entries request.
 *
 * @param entry_handle Entry handle to use in request.
 * @param buf The buffer containing the generated request.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request if the request was successfully constructed or an
 * error code.
 */
int mctp_control_protocol_generate_get_routing_table_entries_request (uint8_t entry_handle,
	uint8_t *buf, size_t buf_len)
{
	struct mctp_control_get_routing_table_entries *rq =
		(struct mctp_control_get_routing_table_entries*) buf;

	if (rq == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct mctp_control_get_routing_table_entries)) {
		return CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL;
	}

	mctp_control_protocol_populate_header (&rq->header,
		MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES);

	rq->entry_handle = entry_handle;

	return sizeof (struct mctp_control_get_routing_table_entries);
}

/**
 * Process Get Routing Table Entries response. This function only ensures the response is
 * valid per MCTP control protocol response definition.
 *
 * @param response Get Routing Table Entries response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int mctp_control_protocol_process_get_routing_table_entries_response (
	struct cmd_interface_msg *response)
{
	struct mctp_control_get_routing_table_entries_response *rsp;

	if (response == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	rsp = (struct mctp_control_get_routing_table_entries_response*) response->payload;

	if ((response->payload_length <=
		sizeof (struct mctp_control_get_routing_table_entries_response)) ||
		(response->payload_length !=
		mctp_control_get_routing_table_entries_response_length (rsp->num_entries))) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	return 0;
}

/**
 * Construct Discovery Notify request.
 *
 * @param buf The buffer containing the generated request.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request if the request was successfully constructed or an
 * error code.
 */
int mctp_control_protocol_generate_discovery_notify_request (uint8_t *buf, size_t buf_len)
{
	struct mctp_control_discovery_notify *rq = (struct mctp_control_discovery_notify*) buf;

	if (rq == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct mctp_control_discovery_notify)) {
		return CMD_HANDLER_MCTP_CTRL_BUF_TOO_SMALL;
	}

	mctp_control_protocol_populate_header (&rq->header, MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY);

	return sizeof (struct mctp_control_discovery_notify);
}

/**
 * Process Discovery Notify response. This function only ensures the response is valid per MCTP
 * 	control protocol response definition.
 *
 * @param response Discovery Notify response to process
 *
 * @return 0 if response processed successfully or an error code.
 */
int mctp_control_protocol_process_discovery_notify_response (struct cmd_interface_msg *response)
{
	if (response == NULL) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	if (response->payload_length != sizeof (struct mctp_control_discovery_notify_response)) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	return 0;
}

/**
 * Generate and send an MCTP control protocol Discovery Notify request to the MCTP bridge.
 *
 * @param mctp_control MCTP instance that will be processing the request message.
 * @param device_mgr Device manager instance to utilize.
 * @param use_bridge_eid Flag indicating that the request should be sent to the MCTP bridge EID.  If
 * this is false, the request will be sent to the NULL EID.
 * @param timeout_ms The amount of time, in milliseconds, to wait for a response from the bridge.
 * If this is 0, the response will be ignored and the function will return immediately after sending
 * the request.
 * @param response Output for the discovery response message, if one is required.  This must be
 * provided if there is a non-zero timeout.  Otherwise, it can be null.  If provided, it must be
 * initialized per the same parameter in {@link msg_transport.send_request_message}.
 *
 * @return 0 if the request was transmitted successfully or an error code.
 */
int mctp_control_protocol_send_discovery_notify (const struct msg_transport *mctp_control,
	struct device_manager *device_mgr, bool use_bridge_eid,	uint32_t timeout_ms,
	struct cmd_interface_msg *response)
{
	uint8_t request_data[MCTP_BASE_PROTOCOL_MIN_MESSAGE_LEN];
	struct cmd_interface_msg request;
	int bridge_eid = MCTP_BASE_PROTOCOL_NULL_EID;
	int request_len = 0;
	int status;

	if ((mctp_control == NULL) || (device_mgr == NULL)) {
		return CMD_HANDLER_MCTP_CTRL_INVALID_ARGUMENT;
	}

	if (use_bridge_eid) {
		bridge_eid = device_manager_get_device_eid (device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
		if (ROT_IS_ERROR (bridge_eid)) {
			return bridge_eid;
		}
	}
	status = msg_transport_create_empty_request (mctp_control, request_data, sizeof (request_data),
		bridge_eid,	&request);
	if (status != 0) {
		return status;
	}

	request_len = mctp_control_protocol_generate_discovery_notify_request (request.payload,
		request.payload_length);
	if (ROT_IS_ERROR (request_len)) {
		return request_len;
	}

	//Update the payload length and request length after request message is ready
	cmd_interface_msg_set_message_payload_length (&request, request_len);

	status = mctp_control->send_request_message (mctp_control, &request, timeout_ms, response);
	if (status == MSG_TRANSPORT_NO_WAIT_RESPONSE) {
		status = 0;
	}

	return status;
}
