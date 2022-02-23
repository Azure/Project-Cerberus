// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "platform.h"
#include "cmd_interface/device_manager.h"
#include "mctp_base_protocol.h"
#include "mctp_logging.h"
#include "mctp_control_protocol.h"
#include "mctp_control_protocol_commands.h"


/**
 * Populate the protocol header segment of a MCTP control request
 *
 * @param header Buffer to fill with MCTP control header
 * @param command Command ID to utilize in header
 */
static void mctp_control_protocol_populate_header (struct mctp_control_protocol_header *header,
	uint8_t command)
{
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->integrity_check = 0;
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

	rq = (struct mctp_control_set_eid*) request->data;
	response = (struct mctp_control_set_eid_response*) request->data;

	if (request->length != sizeof (struct mctp_control_set_eid)) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_SET_EID);
	}
	else if ((rq->reserved != 0) || (rq->operation > MCTP_CONTROL_SET_EID_OPERATION_FORCE_ID) ||
		(rq->eid == MCTP_BASE_PROTOCOL_NULL_EID) || (rq->eid == MCTP_BASE_PROTOCOL_BROADCAST_EID)) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_DATA;
	}
	else {
		status = device_manager_update_device_eid (device_mgr, DEVICE_MANAGER_SELF_DEVICE_NUM,
			rq->eid);
		if (status != 0) {
			goto update_device_mgr_fail;
		}

		status = device_manager_update_device_entry (device_mgr,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM, request->source_eid, request->source_addr);
		if (status != 0) {
			goto update_device_mgr_fail;
		}

		eid_assigned = rq->eid;

		response->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
		request->length = sizeof (struct mctp_control_set_eid_response);

		response->eid_setting = eid_assigned;
		response->eid_assignment_status = MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED;
		response->reserved1 = 0;
		response->reserved2 = 0;
		response->eid_allocation_status = MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL;
		response->eid_pool_size = 0;
	}

	return 0;

update_device_mgr_fail:
	request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
	response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR;

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

	response = (struct mctp_control_get_eid_response*) request->data;

	if (request->length != sizeof (struct mctp_control_get_eid)) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_EID);
	}
	else {
		status = device_manager_get_device_eid (device_mgr, 0);
		if (ROT_IS_ERROR (status)) {
			request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
			response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR;

			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
				MCTP_LOGGING_GET_EID_FAIL, status, request->channel_id);

			return 0;
		}

		request->length = sizeof (struct mctp_control_get_eid_response);
		response->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
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

	rq = (struct mctp_control_get_mctp_version*) request->data;
	response = (struct mctp_control_get_mctp_version_response*) request->data;

	if (request->length != sizeof (struct mctp_control_get_mctp_version)) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->length,
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
			request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
			response->completion_code = MCTP_CONTROL_GET_MCTP_VERSION_MSG_TYPE_UNSUPPORTED;

			return 0;
	}

	request->length =
		mctp_control_get_mctp_version_response_length (response->version_num_entry_count);
	response->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;

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

	response = (struct mctp_control_get_message_type_response*) request->data;

	if (request->length != sizeof (struct mctp_control_get_message_type)) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);

		return 0;
	}

	response->message_type_count = 2;

	message_type_list = mctp_control_get_message_type_response_get_entries (response);

	message_type_list[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	message_type_list[1] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	request->length = mctp_control_get_message_type_response_length (response->message_type_count);

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

	rsp = (struct mctp_control_get_message_type_response*) response->data;

	if ((response->length <= sizeof (struct mctp_control_get_message_type_response)) ||
		(response->length !=
			mctp_control_get_message_type_response_length (rsp->message_type_count))) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	if (rsp->completion_code != MCTP_CONTROL_PROTOCOL_SUCCESS) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL, rsp->completion_code,
			(response->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);
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

	rq = (struct mctp_control_get_vendor_def_msg_support*) request->data;
	response = (struct mctp_control_get_vendor_def_msg_support_pci_response*) request->data;

	if (request->length != sizeof (struct mctp_control_get_vendor_def_msg_support)) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_INVALID_LEN, request->length,
			(request->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE);
	}
	else if (rq->vid_set_selector != CERBERUS_VID_SET) {
		request->length = MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN;
		response->completion_code = MCTP_CONTROL_PROTOCOL_ERROR_INVALID_DATA;
	}
	else {
		request->length = sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response);
		response->completion_code = MCTP_CONTROL_PROTOCOL_SUCCESS;
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

	rsp = (struct mctp_control_get_vendor_def_msg_support_pci_response*) response->data;

	if (response->length < sizeof (struct mctp_control_get_vendor_def_msg_support_pci_response)) {
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

	if (response->length != expected_len) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	if (rsp->completion_code != MCTP_CONTROL_PROTOCOL_SUCCESS) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL, rsp->completion_code,
			(response->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT);
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

	rsp = (struct mctp_control_get_routing_table_entries_response*) response->data;

	if ((response->length <= sizeof (struct mctp_control_get_routing_table_entries_response)) ||
		(response->length !=
			mctp_control_get_routing_table_entries_response_length (rsp->num_entries))) {
		return CMD_HANDLER_MCTP_CTRL_BAD_LENGTH;
	}

	if (rsp->completion_code != MCTP_CONTROL_PROTOCOL_SUCCESS) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_MCTP_CONTROL_RSP_CC_FAIL, rsp->completion_code,
			(response->source_eid << 8) | MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES);
	}

	return 0;
}
