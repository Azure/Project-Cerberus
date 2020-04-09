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
#include "mock/cmd_interface_mock.h"


static const char *SUITE = "mctp_interface_control";


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

static void mctp_interface_control_test_process_payload_too_short (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN - 1;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_unsupported_message (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = 0x11;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->integrity_check = 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->integrity_check = 0;
	header->d_bit = 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->d_bit = 0;
	header->rsvd = 1;

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_null (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_process_request (NULL, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp_interface_control_process_request (&interface, NULL, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_unknown_rq_command (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->rq = 1;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_unknown_resp_command (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = 0;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_get_vendor_def_msg_support_request_packet *rq =
		(struct mctp_control_get_vendor_def_msg_support_request_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_get_vendor_def_msg_support_response_packet *response =
		(struct mctp_control_get_vendor_def_msg_support_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	header->rq = 1;
	header->instance_id = 2;

	rq->vid_set_selector = CERBERUS_VID_SET;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 6, header->command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->vid_set_selector);
	CuAssertIntEquals (test, 0, response->vid_format);
	CuAssertIntEquals (test, 0x1414, response->vid);
	CuAssertIntEquals (test, 0x200, response->protocol_version);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support_vid_endian_test (
	CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_get_vendor_def_msg_support_request_packet *rq =
		(struct mctp_control_get_vendor_def_msg_support_request_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_get_vendor_def_msg_support_response_packet *response =
		(struct mctp_control_get_vendor_def_msg_support_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	header->rq = 1;
	header->instance_id = 2;

	rq->vid_set_selector = CERBERUS_VID_SET;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_request_packet);
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

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 6, header->command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->vid_set_selector);
	CuAssertIntEquals (test, 0, response->vid_format);
	CuAssertIntEquals (test, 0xFF00, response->vid);
	CuAssertIntEquals (test, 0x200, response->protocol_version);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_len (
	CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_get_vendor_def_msg_support_response_packet *response =
		(struct mctp_control_get_vendor_def_msg_support_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	header->rq = 1;
	header->instance_id = 2;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + 2;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 6, header->command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN;
	request.new_request = true;
	request.crypto_timeout = true;
	header->rq = 1;

	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 6, header->command_code);
	CuAssertIntEquals (test, 4, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_vid_set (
	CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_get_vendor_def_msg_support_request_packet *rq =
		(struct mctp_control_get_vendor_def_msg_support_request_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_get_vendor_def_msg_support_response_packet *response =
		(struct mctp_control_get_vendor_def_msg_support_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT;
	header->rq = 1;
	header->instance_id = 2;

	rq->vid_set_selector = 0xFF;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_get_vendor_def_msg_support_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 6, header->command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct device_manager_full_capabilities capabilities;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_request_packet *rq = (struct mctp_control_set_eid_request_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->rq = 1;
	header->instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0xBB;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	device_manager_get_device_capabilities (&device_manager, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_update_device_capabilities (&device_manager, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->reserved1);
	CuAssertIntEquals (test, 0, response->eid_assignment_status);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->eid_allocation_status);
	CuAssertIntEquals (test, 0xBB, response->eid_setting);
	CuAssertIntEquals (test, 0, response->eid_pool_size);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0xBB, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request_invalid_len (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->rq = 1;
	header->instance_id = 2;

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + 3;
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 4, request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	header->rq = 1;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + 1;
	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 4, request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request_invalid_data (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_request_packet *rq = (struct mctp_control_set_eid_request_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->rq = 1;
	header->instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	header->rq = 1;
	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0xFF;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet);
	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	header->rq = 1;
	rq->reserved = 0;
	rq->operation = 2;
	rq->eid = 0xAA;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet);
	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	header->rq = 1;
	rq->reserved = 1;
	rq->operation = 0;
	rq->eid = 0xAA;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet);
	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 3, response->completion_code);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_request_invalid_role (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_request_packet *rq = (struct mctp_control_set_eid_request_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->rq = 1;
	header->instance_id = 2;

	rq->reserved = 0;
	rq->operation = 0;
	rq->eid = 0xBB;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet);
	request.source_eid = MCTP_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet), request.length);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 2, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 0, response->reserved1);
	CuAssertIntEquals (test, 1, response->eid_assignment_status);
	CuAssertIntEquals (test, 0, response->reserved2);
	CuAssertIntEquals (test, 0, response->eid_allocation_status);
	CuAssertIntEquals (test, 0x0B, response->eid_setting);
	CuAssertIntEquals (test, 0, response->eid_pool_size);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0x0B, device_manager_get_device_eid (&device_manager, 0));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
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
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->instance_id = 2;

	response->completion_code = 1;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + 5;
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + 3;

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_invalid_response (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->instance_id = 2;

	response->completion_code = 1;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->reserved1 = 1;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 1;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 1;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0,	device_manager_get_device_state (&device_manager, 2));

	response->completion_code = 0;
	response->reserved2 = 0;
	response->eid_pool_size = 1;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x20);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
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
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xAA;
	response->eid_pool_size = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	device_manager_get_device_capabilities (&device_manager, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_update_device_capabilities (&device_manager, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	request.new_request = true;
	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_process_set_eid_response_unknown_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = 0xBB;
	response->eid_pool_size = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);
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
	struct cmd_interface_request request;
	struct mctp_protocol_control_header *header =
		(struct mctp_protocol_control_header*) &request.data[0];
	struct mctp_control_set_eid_response_packet *response =
		(struct mctp_control_set_eid_response_packet*)
		&request.data[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (header, 0, sizeof (struct mctp_protocol_control_header));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	header->command_code = MCTP_PROTOCOL_SET_EID;
	header->instance_id = 2;

	response->completion_code = 0;
	response->reserved1 = 0;
	response->eid_assignment_status = 0;
	response->reserved2 = 0;
	response->eid_allocation_status = 0;
	response->eid_setting = MCTP_PROTOCOL_BMC_EID;
	response->eid_pool_size = 0;
	request.length = MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_response_packet);
	request.source_eid = 0xAA;
	request.target_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	request.crypto_timeout = true;
	status = mctp_interface_control_process_request (&interface, &request, 0x30);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_EID, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_request_null (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t eid;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_issue_request (NULL, MCTP_PROTOCOL_SET_EID, &eid, buf,
		sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, NULL,
		sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_request_buf_too_small (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t eid;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, buf,
		MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN - 1);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_request_unknown_command (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t eid;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_issue_request (&interface, 0xFF, &eid, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_set_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct mctp_protocol_control_header *header = (struct mctp_protocol_control_header*) buf;
	struct mctp_control_set_eid_request_packet *request =
		(struct mctp_control_set_eid_request_packet*) &buf[MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	uint8_t eid = 0xBB;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, buf,
		sizeof (buf));
	CuAssertIntEquals (test, MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN +
		sizeof (struct mctp_control_set_eid_request_packet), status);
	CuAssertIntEquals (test, 0, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->instance_id);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 1, header->command_code);
	CuAssertIntEquals (test, 0, request->reserved);
	CuAssertIntEquals (test, 0, request->operation);
	CuAssertIntEquals (test, eid, request->eid);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_set_eid_invalid_role (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0xBB;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	device_manager_get_device_capabilities (&device_manager, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;

	status = device_manager_update_device_capabilities (&device_manager, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, buf,
		sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_DEVICE_MODE, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_set_eid_buf_too_small (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t eid = 0xBB;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, buf,
		MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN + 1);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}

static void mctp_interface_control_test_issue_set_eid_invalid_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_manager;
	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t eid = 0x00;
	int status;

	TEST_START;

	setup_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, buf,
		sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);

	eid = 0xFF;

	status = mctp_interface_control_issue_request (&interface, MCTP_PROTOCOL_SET_EID, &eid, buf,
		sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_OUT_OF_RANGE, status);

	complete_mctp_interface_control_mock_test (test, &interface, &device_manager, &cmd_interface);
}


CuSuite* get_mctp_interface_control_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_payload_too_short);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_unsupported_message);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_null);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_unknown_rq_command);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_unknown_resp_command);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_get_vendor_def_msg_support);
	SUITE_ADD_TEST (suite,
		mctp_interface_control_test_process_get_vendor_def_msg_support_vid_endian_test);
	SUITE_ADD_TEST (suite,
		mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_len);
	SUITE_ADD_TEST (suite,
		mctp_interface_control_test_process_get_vendor_def_msg_support_invalid_vid_set);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_request);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_request_invalid_len);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_request_invalid_data);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_request_invalid_role);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_response);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_response_invalid_len);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_response_invalid_response);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_response_invalid_role);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_response_unknown_eid);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_process_set_eid_response_invalid_eid);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_request_null);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_request_buf_too_small);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_request_unknown_command);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_set_eid);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_set_eid_invalid_role);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_set_eid_buf_too_small);
	SUITE_ADD_TEST (suite, mctp_interface_control_test_issue_set_eid_invalid_eid);

	return suite;
}
