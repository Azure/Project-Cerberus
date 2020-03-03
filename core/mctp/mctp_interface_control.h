// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_INTERFACE_CONTROL_H_
#define MCTP_INTERFACE_CONTROL_H_

#include <stdint.h>
#include "mctp_interface.h"


#define CERBERUS_VID_SET									0

#define MCTP_CONTROL_SET_EID_OPERATION_SET_ID				0
#define MCTP_CONTROL_SET_EID_OPERATION_FORCE_ID				1

#define MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_ACCEPTED		0
#define MCTP_CONTROL_SET_EID_ASSIGNMENT_STATUS_REJECTED 	1

#define MCTP_CONTROL_SET_EID_ALLOCATION_STATUS_NO_EID_POOL	0


#pragma pack(push, 1)
/**
 * MCTP control set EID request packet format
 */
struct mctp_control_set_eid_request_packet {
	uint8_t reserved:6;										// Reserved
	uint8_t operation:2;									// Operation
	uint8_t eid;											// EID	
};

/**
 * MCTP control set EID request response format
 */
struct mctp_control_set_eid_response_packet {
	uint8_t completion_code;								// Completion code
	uint8_t reserved1:2;									// Reserved
	uint8_t eid_assignment_status:2;						// EID assignment status
	uint8_t reserved2:2;									// Reserved
	uint8_t eid_allocation_status:2;						// EID allocation status
	uint8_t eid_setting;									// EID setting
	uint8_t eid_pool_size;									// EID pool size
};

/**
 * MCTP control get vendor defined message support request packet format
 */
struct mctp_control_get_vendor_def_msg_support_request_packet {
	uint8_t vid_set_selector;								// Vendor ID set selector
};

/**
 * MCTP control get vendor defined message support response packet format
 */
struct mctp_control_get_vendor_def_msg_support_response_packet {
	uint8_t completion_code;								// Completion code
	uint8_t vid_set_selector;								// Vendor ID set selector
	uint8_t vid_format;										// Vendor ID format
	uint16_t vid;											// Vendor ID
	uint16_t protocol_version;								// Protocol version
};
#pragma pack(pop)


int mctp_interface_control_process_request (struct mctp_interface *intf, 
	struct cmd_interface_request *request, uint8_t source_addr);
int mctp_interface_control_issue_request (struct mctp_interface *intf, uint8_t command_id, 
	void *request_params, uint8_t *buf, int buf_len);


#endif /* MCTP_INTERFACE_CONTROL_H_ */
