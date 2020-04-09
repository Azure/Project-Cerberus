// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "mctp_logging.h"
#include "mctp_protocol.h"
#include "mctp_interface.h"
#include "mctp_interface_control.h"


/**
 * Construct get certificate digest request.
 *
 * @param intf The interface that will construct the request.
 * @param eid EID to set
 * @param buf The buffer containing the generated request data.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated request data if the request was successfully constructed or
 * an error code.
 */
static int mctp_interface_control_issue_set_eid (struct mctp_interface *intf, uint8_t *eid,
	uint8_t *buf, size_t buf_len)
{
	struct mctp_control_set_eid_request_packet *request =
		(struct mctp_control_set_eid_request_packet*) buf;
	struct device_manager_full_capabilities capabilities;
	int status;

	status = device_manager_get_device_capabilities (intf->device_manager, 0, &capabilities);
	if (status != 0) {
		return status;
	}

	if (capabilities.request.hierarchy_role != DEVICE_MANAGER_PA_ROT_MODE) {
		return CMD_HANDLER_INVALID_DEVICE_MODE;
	}

	if (buf_len < sizeof (struct mctp_control_set_eid_request_packet)) {
		return CMD_HANDLER_BUF_TOO_SMALL;
	}

	if ((*eid == 0) || (*eid == 0xFF)) {
		return CMD_HANDLER_OUT_OF_RANGE;
	}

	request->reserved = 0;
	request->operation = MCTP_CONTROL_SET_EID_OPERATION_SET_ID;
	request->eid = *eid;

	return 2;
}

/**
 * Process vendor defined message support request packet
 *
 * @param intf MCTP interface to utilize
 * @param request Vendor defined message support request to process
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int mctp_interface_control_set_eid (struct mctp_interface *intf,
	struct cmd_interface_request *request)
{
	struct mctp_control_set_eid_request_packet *rq = (struct mctp_control_set_eid_request_packet*)
		&request->data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
			&request->data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct device_manager_full_capabilities capabilities;
	int status;

	status = device_manager_get_device_capabilities (intf->device_manager, 0, &capabilities);
	if (status != 0) {
		request->length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
			sizeof (struct mctp_control_set_eid_response_packet);
		response->completion_code = MCTP_PROTOCOL_ERROR;

		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_CONTROL_FAIL, status, 0);

		return 0;
	}

	if (request->length != (MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet))) {
		response->completion_code = MCTP_PROTOCOL_ERROR_INVALID_LEN;
	}
	else if ((rq->reserved != 0) || (rq->operation > MCTP_CONTROL_SET_EID_OPERATION_FORCE_ID) ||
			 (rq->eid == 0) || (rq->eid == 0xFF)) {
		response->completion_code = MCTP_PROTOCOL_ERROR_INVALID_DATA;
	}
	else {
		if (capabilities.request.hierarchy_role == DEVICE_MANAGER_PA_ROT_MODE) {
			response->eid_assignment_status = MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_REJECTED;
		}
		else {
			status = device_manager_update_device_eid (intf->device_manager, 0, rq->eid);
			if (status == 0) {
				intf->eid = rq->eid;
				response->eid_assignment_status = MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED;
			}
		}

		if (status != 0) {
			response->completion_code = MCTP_PROTOCOL_ERROR;

			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
				MCTP_LOGGING_CONTROL_FAIL, status, 0);
		}
		else {
			response->completion_code = MCTP_PROTOCOL_SUCCESS;
			response->reserved1 = 0;
			response->reserved2 = 0;
			response->eid_allocation_status = MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL;
			response->eid_setting = intf->eid;
			response->eid_pool_size = 0;
		}
	}

	request->length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);

	return 0;
}

/**
 * Process set EID response packet
 *
 * @param interface MCTP interface to utilize
 * @param request Vendor defined message support request to process
 * @param source_addr Address of device where request originated
 *
 * @return 0 if request processing completed successfully or an error code.
 */
static int mctp_interface_control_process_set_eid_response (struct mctp_interface *intf,
	struct cmd_interface_request *request, uint8_t source_addr)
{
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
			&request->data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct device_manager_full_capabilities capabilities;
	int device_num;
	int device_addr;
	int status;

	if ((request->length != (MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet))) ||
	    (response->completion_code != MCTP_PROTOCOL_SUCCESS) || (response->reserved1 != 0) ||
		(response->eid_assignment_status != MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED) ||
		(response->reserved2 != 0) ||
		(response->eid_allocation_status != MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL) ||
		(response->eid_pool_size != 0)) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_CONTROL_FAIL, request->length,
			*((uint32_t*)&request->data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN]));
	}
	else {
		status = device_manager_get_device_capabilities (intf->device_manager, 0, &capabilities);
		if (status != 0) {
			return status;
		}
		if (capabilities.request.hierarchy_role == DEVICE_MANAGER_PA_ROT_MODE) {
			device_num = device_manager_get_device_num (intf->device_manager,
				response->eid_setting);
			if (ROT_IS_ERROR (device_num)) {
				return device_num;
			}

			device_addr = device_manager_get_device_addr (intf->device_manager, device_num);
			if (ROT_IS_ERROR (device_addr)) {
				return device_addr;
			}

			if (device_addr != source_addr) {
				return MCTP_PROTOCOL_INVALID_EID;
			}

			status = device_manager_update_device_state (intf->device_manager, device_num,
				DEVICE_MANAGER_AVAILABLE);
			if (status != 0) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_CONTROL_FAIL, status, 0);
			}
		}
	}

	request->length = 0;

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
static int mctp_interface_control_get_vendor_def_msg_support (struct mctp_interface *intf,
	struct cmd_interface_request *request)
{
	struct mctp_control_get_vendor_def_msg_support_request_packet *rq =
		(struct mctp_control_get_vendor_def_msg_support_request_packet*)
			&request->data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_get_vendor_def_msg_support_response_packet *response =
		(struct mctp_control_get_vendor_def_msg_support_response_packet*)
			&request->data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];

	if (request->length != (MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_request_packet))) {
		response->completion_code = MCTP_PROTOCOL_ERROR_INVALID_LEN;
	}
	else if (rq->vid_set_selector != CERBERUS_VID_SET) {
		response->completion_code = MCTP_PROTOCOL_ERROR_INVALID_DATA;
	}
	else {
		response->completion_code = MCTP_PROTOCOL_SUCCESS;
		response->vid_set_selector = CERBERUS_VID_SET;
		response->vid_format = MCTP_PROTOCOL_VID_FORMAT_PCI;
		response->vid = platform_htons (intf->pci_vendor_id);
		response->protocol_version = platform_htons (intf->protocol_version);
	}

	request->length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_response_packet);

	return 0;
}

/**
 * Process a received MCTP control request.
 *
 * @param intf MCTP interface to utilize.
 * @param request The request data to process. This will be updated to contain a response, if
 * 	necessary.
 * @param source_addr Address of device where request originated.
 *
 * @return 0 if the request was successfully processed or an error code.
 */
int mctp_interface_control_process_request (struct mctp_interface *intf,
	struct cmd_interface_request *request, uint8_t source_addr)
{
	struct mctp_protocol_control_header *header;

	if ((intf == NULL ) || (request == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	request->new_request = false;
	request->crypto_timeout = false;

	header = (struct mctp_protocol_control_header*) &request->data[0];

	if (request->length < MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN) {
		return CMD_HANDLER_PAYLOAD_TOO_SHORT;
	}

	if ((header->msg_type != (MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG)) ||
		(header->integrity_check != 0) || (header->d_bit != 0) || (header->rsvd != 0)) {
		return CMD_HANDLER_UNSUPPORTED_MSG;
	}

	if (header->rq) {
		header->rq = 0;

		switch (header->command_code) {
			case MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT:
				return mctp_interface_control_get_vendor_def_msg_support (intf, request);

			case MCTP_PROTOCOL_SET_EID:
				return mctp_interface_control_set_eid (intf, request);

			default:
				return CMD_HANDLER_UNKNOWN_COMMAND;
		}
	}
	else {
		switch (header->command_code) {
			case MCTP_PROTOCOL_SET_EID:
				return mctp_interface_control_process_set_eid_response (intf, request, source_addr);

			default:
				return CMD_HANDLER_UNKNOWN_COMMAND;
		}
	}
}

/**
 * Construct MCTP control request.
 *
 * @param intf MCTP interface to utilize.
 * @param command_id Command ID of request to generate.
 * @param request_params Parameters to use when generating request.
 * @param buf The buffer containing the generated request.
 * @param buf_len Maximum size of buffer.
 *
 * @return Length of the generated packet if the request was successfully constructed or an
 * error code.
 */
int mctp_interface_control_issue_request (struct mctp_interface *intf, uint8_t command_id,
	void *request_params, uint8_t *buf, int buf_len)
{
	struct mctp_protocol_control_header *header = (struct mctp_protocol_control_header*) buf;
	int status;

	if ((intf == NULL) || (request_params == NULL) || (buf == NULL) ||
		(buf_len < MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (header, 0, sizeof (struct mctp_protocol_control_header));

	header->command_code = command_id;
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->rq = 1;

	switch (command_id) {
		case MCTP_PROTOCOL_SET_EID:
			status = mctp_interface_control_issue_set_eid (intf, request_params,
				&buf[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN],
				buf_len - MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN);
			break;

		default:
			return CMD_HANDLER_UNKNOWN_COMMAND;
	}

	if ROT_IS_ERROR (status) {
		return status;
	}

	return (MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + status);
}
