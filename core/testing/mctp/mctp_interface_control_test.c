// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/device_manager.h"
#include "cmd_interface/cerberus_protocol.h"
#include "mctp/mctp_protocol.h"
#include "mctp/mctp_interface_control.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("mctp_interface_control");


/**
 * Helper function to setup the MCTP interface and required subcomponents
 *
 * @param test The test framework
 * @param interface The MCTP interface instance to initialize
 * @param device_mgr Device manager to initialize
 * @param cmd_interface Command interface to initialize
 */
static void setup_mctp_interface_control_mock_test (CuTest *test, struct mctp_interface *interface,
	struct device_manager *device_mgr, struct cmd_interface_mock *cmd_interface)
{
	struct device_manager_full_capabilities capabilities;
	int status;

	status = device_manager_init (device_mgr, 3, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (device_mgr, 0, DEVICE_MANAGER_SELF,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (device_mgr, 1, DEVICE_MANAGER_UPSTREAM,
		MCTP_PROTOCOL_BMC_EID, 0x20);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (device_mgr, 2, DEVICE_MANAGER_DOWNSTREAM, 0xAA,
		0x30);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (device_mgr, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;

	status = device_manager_update_device_capabilities (device_mgr, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (cmd_interface);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (interface, &cmd_interface->base, device_mgr,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release cmd interface instance
 *
 * @param test The test framework
 * @param interface The cmd interface instance to release
 * @param device_mgr Device manager to release
 * @param cmd_interface Command interface mock to release
 */
static void complete_mctp_interface_control_mock_test (CuTest *test,
	struct mctp_interface *interface, struct device_manager *device_mgr,
	struct cmd_interface_mock *cmd_interface)
{
	int status;

	device_manager_release (device_mgr);

	status = cmd_interface_mock_validate_and_release (cmd_interface);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_deinit (interface);
}


/*******************
 * Test cases
 *******************/

static void mctp_interface_control_test_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e,0xf5,0xaa
	};
	struct mctp_protocol_control_header *header;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct mctp_protocol_control_header));

	header = (struct mctp_protocol_control_header*) raw_buffer;
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0x7e, header->msg_type);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 1, header->d_bit);
	CuAssertIntEquals (test, 1, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);
	CuAssertIntEquals (test, 0xaa, header->command_code);

	raw_buffer[0] = 0xfe;
	CuAssertIntEquals (test, 1, header->integrity_check);
	CuAssertIntEquals (test, 0x7e, header->msg_type);

	raw_buffer[1] = 0x75;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->d_bit);
	CuAssertIntEquals (test, 1, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);

	raw_buffer[1] = 0x35;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 1, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);

	raw_buffer[1] = 0x15;
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0x15, header->instance_id);
}

static void mctp_interface_control_test_set_eid_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x01,
		0x12,0x34
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x01,
		0x11,0xe1,0x33,0x44
	};
	struct mctp_control_set_eid *req;
	struct mctp_control_set_eid_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct mctp_control_set_eid));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct mctp_control_set_eid_response));

	req = (struct mctp_control_set_eid*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_PROTOCOL_SET_EID, req->header.command_code);

	CuAssertIntEquals (test, 0x04, req->reserved);
	CuAssertIntEquals (test, 0x02, req->operation);
	CuAssertIntEquals (test, 0x34, req->eid);

	resp = (struct mctp_control_set_eid_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_PROTOCOL_SET_EID, resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0x03, resp->reserved2);
	CuAssertIntEquals (test, 0x02, resp->eid_assignment_status);
	CuAssertIntEquals (test, 0x00, resp->reserved1);
	CuAssertIntEquals (test, 0x01, resp->eid_allocation_status);
	CuAssertIntEquals (test, 0x33, resp->eid_setting);
	CuAssertIntEquals (test, 0x44, resp->eid_pool_size);
}

static void mctp_interface_control_test_get_vendor_def_msg_support_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x7e,0x03,0x06,
		0x12
	};
	uint8_t raw_buffer_resp[] = {
		0x7e,0x03,0x06,
		0x11,0x22,0x33,0x44,0x55,0x66,0x77
	};
	struct mctp_control_get_vendor_def_msg_support *req;
	struct mctp_control_get_vendor_def_msg_support_response *resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct mctp_control_get_vendor_def_msg_support));
	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct mctp_control_get_vendor_def_msg_support_response));

	req = (struct mctp_control_get_vendor_def_msg_support*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, req->header.msg_type);
	CuAssertIntEquals (test, 0, req->header.rq);
	CuAssertIntEquals (test, 0, req->header.d_bit);
	CuAssertIntEquals (test, 0, req->header.rsvd);
	CuAssertIntEquals (test, 0x03, req->header.instance_id);
	CuAssertIntEquals (test, MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT, req->header.command_code);

	CuAssertIntEquals (test, 0x12, req->vid_set_selector);

	resp = (struct mctp_control_get_vendor_def_msg_support_response*) raw_buffer_resp;
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x7e, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.rq);
	CuAssertIntEquals (test, 0, resp->header.d_bit);
	CuAssertIntEquals (test, 0, resp->header.rsvd);
	CuAssertIntEquals (test, 0x03, resp->header.instance_id);
	CuAssertIntEquals (test, MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT, resp->header.command_code);

	CuAssertIntEquals (test, 0x11, resp->completion_code);
	CuAssertIntEquals (test, 0x22, resp->vid_set_selector);
	CuAssertIntEquals (test, 0x33, resp->vid_format);
	CuAssertIntEquals (test, 0x5544, resp->vid);
	CuAssertIntEquals (test, 0x7766, resp->protocol_version);
}

static void mctp_interface_control_test_process_payload_too_short (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_unsupported_message (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_protocol_control_header *header = (struct mctp_protocol_control_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	header->msg_type = 0x11;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_DATA, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->integrity_check = 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_DATA, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->integrity_check = 0;
	header->d_bit = 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_DATA, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->d_bit = 0;
	header->rsvd = 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_DATA, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_null (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_process_request (NULL, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_ARGUMENT, status);

	status = mctp_interface_control_process_request (&interface, NULL, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_ARGUMENT, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_unknown_rq_command (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_protocol_control_header *header = (struct mctp_protocol_control_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->rq = 1;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_unknown_resp_command (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_protocol_control_header *header = (struct mctp_protocol_control_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = 0;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_response *response =
		(struct mctp_control_get_vendor_def_msg_support_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->vid_set_selector = CERBERUS_VID_SET;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_vendor_def_msg_support_response),
		request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, CERBERUS_VID_SET_RESPONSE, response->vid_set_selector);
	CuAssertIntEquals (test, 0, response->vid_format);
	CuAssertIntEquals (test, 0x1414, response->vid);
	CuAssertIntEquals (test, 0x0400, response->protocol_version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support_vid_endian_test (
	CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_response *response =
		(struct mctp_control_get_vendor_def_msg_support_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->vid_set_selector = CERBERUS_VID_SET;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	status = device_manager_init (&device_manager, 3, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, 0, DEVICE_MANAGER_SELF,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, 0x41);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, 1, DEVICE_MANAGER_UPSTREAM,
		MCTP_PROTOCOL_BMC_EID, 0x20);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&device_manager, 2, DEVICE_MANAGER_DOWNSTREAM,
		0xAA, 0x30);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd_interface);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&interface, &cmd_interface.base, &device_manager,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, 0xFF, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_vendor_def_msg_support_response),
		request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, CERBERUS_VID_SET_RESPONSE, response->vid_set_selector);
	CuAssertIntEquals (test, 0, response->vid_format);
	CuAssertIntEquals (test, 0xFF00, response->vid);
	CuAssertIntEquals (test, 0x0400, response->protocol_version);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_len (
	CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_response *response =
		(struct mctp_control_get_vendor_def_msg_support_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_CONTROL_FAILURE_REPONSE_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support) - 1;
	request.crypto_timeout = true;
	rq->header.rq = 1;
	response->completion_code = 0;

	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_CONTROL_FAILURE_REPONSE_LEN,	request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_vid_set (
	CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_vendor_def_msg_support *rq =
		(struct mctp_control_get_vendor_def_msg_support*) data;
	struct mctp_control_get_vendor_def_msg_support_response *response =
		(struct mctp_control_get_vendor_def_msg_support_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->vid_set_selector = 0xFF;
	request.length = sizeof (struct mctp_control_get_vendor_def_msg_support);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_CONTROL_FAILURE_REPONSE_LEN,	request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 6, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct device_manager_full_capabilities capabilities;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0xBB;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	device_manager_get_device_capabilities (&device_manager, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_update_device_capabilities (&device_manager, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->reserved1);
	CuAssertIntEquals (test, 0, response->eid_assignment_status);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->eid_allocation_status);
	CuAssertIntEquals (test, 0xBB, response->eid_setting);
	CuAssertIntEquals (test, 0, response->eid_pool_size);
	CuAssertIntEquals (test, 0xBB, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request_invalid_len (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_set_eid) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	response->completion_code = 0;
	request.length = sizeof (struct mctp_control_set_eid) - 1;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request_invalid_data (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0xFF;
	request.length = sizeof (struct mctp_control_set_eid);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	rq->reserved = 0;
	rq->operation = 2;
	rq->eid = 0xAA;
	request.length = sizeof (struct mctp_control_set_eid);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	rq->header.rq = 1;
	rq->reserved = 1;
	rq->operation = 0;
	rq->eid = 0xAA;
	request.length = sizeof (struct mctp_control_set_eid);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request_pa_rot (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid *rq = (struct mctp_control_set_eid*) data;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_SET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0xBB;
	request.length = sizeof (struct mctp_control_set_eid);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid_response), request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 1, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->reserved1);
	CuAssertIntEquals (test, 0, response->eid_assignment_status);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->eid_allocation_status);
	CuAssertIntEquals (test, 0xBB, response->eid_setting);
	CuAssertIntEquals (test, 0, response->eid_pool_size);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0xBB, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_eid_request (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_eid *rq = (struct mctp_control_get_eid*) data;
	struct mctp_control_get_eid_response *response = (struct mctp_control_get_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_GET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_eid);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct mctp_control_get_eid_response), request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 2, response->header.command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, MCTP_PROTOCOL_PA_ROT_CTRL_EID, response->eid);
	CuAssertIntEquals (test, 1, response->eid_type);
	CuAssertIntEquals (test, 0, response->reserved);
	CuAssertIntEquals (test, 0, response->endpoint_type);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->medium_specific_info);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_eid_request_invalid_len (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_get_eid *rq = (struct mctp_control_get_eid*) data;
	struct mctp_control_get_eid_response *response = (struct mctp_control_get_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	rq->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rq->header.command_code = MCTP_PROTOCOL_GET_EID;
	rq->header.rq = 1;
	rq->header.instance_id = 2;

	request.length = sizeof (struct mctp_control_get_eid) + 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN, request.length);
	CuAssertIntEquals (test, 0, response->header.msg_type);
	CuAssertIntEquals (test, 0, response->header.integrity_check);
	CuAssertIntEquals (test, 2, response->header.instance_id);
	CuAssertIntEquals (test, 0, response->header.rsvd);
	CuAssertIntEquals (test, 0, response->header.d_bit);
	CuAssertIntEquals (test, 0, response->header.rq);
	CuAssertIntEquals (test, 2, response->header.command_code);
	CuAssertIntEquals (test, 4, response->completion_code);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	response->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response->header.command_code = MCTP_PROTOCOL_SET_EID;
	response->header.instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = sizeof (struct mctp_control_set_eid_response);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 1, device_manager_get_device_state (&device_manager, 2));
	CuAssertIntEquals (test, 0xAA, device_manager_get_device_eid (&device_manager, 2));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_invalid_len (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	response->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response->header.command_code = MCTP_PROTOCOL_SET_EID;
	response->header.instance_id = 2;

	response->completion_code = 1;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = sizeof (struct mctp_control_set_eid_response) + 1;
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	request.length = sizeof (struct mctp_control_set_eid_response) - 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_invalid_response (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	response->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response->header.command_code = MCTP_PROTOCOL_SET_EID;
	response->header.instance_id = 2;

	response->completion_code = 1;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = sizeof (struct mctp_control_set_eid_response);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->reserved1 = 1;
	request.length = sizeof (struct mctp_control_set_eid_response);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 1;
	request.length = sizeof (struct mctp_control_set_eid_response);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 1;
	request.length = sizeof (struct mctp_control_set_eid_response);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->reserved2 = 0;
	response->eid_pool_size = 1;
	request.length = sizeof (struct mctp_control_set_eid_response);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_invalid_role (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct device_manager_full_capabilities capabilities;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	response->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response->header.command_code = MCTP_PROTOCOL_SET_EID;
	response->header.instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = sizeof (struct mctp_control_set_eid_response);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	device_manager_get_device_capabilities (&device_manager, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_update_device_capabilities (&device_manager, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_unknown_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	response->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response->header.command_code = MCTP_PROTOCOL_SET_EID;
	response->header.instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xBB;
	response->eid_pool_size = 0;
	request.length = sizeof (struct mctp_control_set_eid_response);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_invalid_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t data[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct cmd_interface_msg request;
	struct mctp_control_set_eid_response *response = (struct mctp_control_set_eid_response*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	response->header.msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response->header.command_code = MCTP_PROTOCOL_SET_EID;
	response->header.instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = MCTP_PROTOCOL_BMC_EID;
	response->eid_pool_size = 0;
	request.length = sizeof (struct mctp_control_set_eid_response);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_EID, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_generate_set_eid_request (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct mctp_control_set_eid *request = (struct mctp_control_set_eid*) buf;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_generate_set_eid_request (&interface, 0xBB, buf, sizeof (buf));
	CuAssertIntEquals (test, sizeof (struct mctp_control_set_eid), status);
	CuAssertIntEquals (test, 0, request->header.msg_type);
	CuAssertIntEquals (test, 0, request->header.integrity_check);
	CuAssertIntEquals (test, 0, request->header.instance_id);
	CuAssertIntEquals (test, 0, request->header.rsvd);
	CuAssertIntEquals (test, 0, request->header.d_bit);
	CuAssertIntEquals (test, 1, request->header.rq);
	CuAssertIntEquals (test, 1, request->header.command_code);
	CuAssertIntEquals (test, 0, request->reserved);
	CuAssertIntEquals (test, 0, request->operation);
	CuAssertIntEquals (test, 0xBB, request->eid);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_generate_set_eid_request_invalid_arg (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_generate_set_eid_request (NULL, 0xBB, buf, sizeof (buf));
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_ARGUMENT, status);

	status = mctp_interface_control_generate_set_eid_request (&interface, 0xBB, NULL, sizeof (buf));
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_INVALID_ARGUMENT, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_generate_set_eid_request_invalid_role (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	struct device_manager_full_capabilities capabilities;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	device_manager_get_device_capabilities (&device_manager, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_update_device_capabilities (&device_manager, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_control_generate_set_eid_request (&interface, 0xBB, buf, sizeof (buf));
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_UNSUPPORTED_REQ, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_generate_set_eid_request_buf_too_small (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[sizeof (struct mctp_control_set_eid) - 1];
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_generate_set_eid_request (&interface, 0xBB, buf, sizeof (buf));
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_BUF_TOO_SMALL, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_generate_set_eid_request_invalid_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT];
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_generate_set_eid_request (&interface, 0, buf, sizeof (buf));
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_OUT_OF_RANGE, status);

	status = mctp_interface_control_generate_set_eid_request (&interface, 0xFF, buf, sizeof (buf));
	CuAssertIntEquals (test, MCTP_INTERFACE_CTRL_OUT_OF_RANGE, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}


TEST_SUITE_START (mctp_interface_control);

TEST (mctp_interface_control_test_header_format);
TEST (mctp_interface_control_test_set_eid_format);
TEST (mctp_interface_control_test_get_vendor_def_msg_support_format);
TEST (mctp_interface_control_test_process_payload_too_short);
TEST (mctp_interface_control_test_process_unsupported_message);
TEST (mctp_interface_control_test_process_null);
TEST (mctp_interface_control_test_process_unknown_rq_command);
TEST (mctp_interface_control_test_process_unknown_resp_command);
TEST (mctp_interface_control_test_process_get_vendor_def_msg_support);
TEST (mctp_interface_control_test_process_get_vendor_def_msg_support_vid_endian_test);
TEST (mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_len);
TEST (mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_vid_set);
TEST (mctp_interface_control_test_process_set_eid_request);
TEST (mctp_interface_control_test_process_set_eid_request_invalid_len);
TEST (mctp_interface_control_test_process_set_eid_request_invalid_data);
TEST (mctp_interface_control_test_process_set_eid_request_pa_rot);
TEST (mctp_interface_control_test_process_get_eid_request);
TEST (mctp_interface_control_test_process_get_eid_request_invalid_len);
TEST (mctp_interface_control_test_process_set_eid_response);
TEST (mctp_interface_control_test_process_set_eid_response_invalid_len);
TEST (mctp_interface_control_test_process_set_eid_response_invalid_response);
TEST (mctp_interface_control_test_process_set_eid_response_invalid_role);
TEST (mctp_interface_control_test_process_set_eid_response_unknown_eid);
TEST (mctp_interface_control_test_process_set_eid_response_invalid_eid);
TEST (mctp_interface_control_test_generate_set_eid_request);
TEST (mctp_interface_control_test_generate_set_eid_request_invalid_arg);
TEST (mctp_interface_control_test_generate_set_eid_request_buf_too_small);
TEST (mctp_interface_control_test_generate_set_eid_request_invalid_role);
TEST (mctp_interface_control_test_generate_set_eid_request_invalid_eid);

TEST_SUITE_END;
