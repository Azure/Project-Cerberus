// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/cmd_interface_null.h"
#include "cmd_interface/cmd_interface_null_static.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"


TEST_SUITE_LABEL ("cmd_interface_null");


/*******************
 * Test cases
 *******************/

static void cmd_interface_null_test_init (CuTest *test)
{
	struct cmd_interface_null cmd;
	int status;

	TEST_START;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cmd.base.process_request);
	CuAssertPtrNotNull (test, cmd.base.process_response);
	CuAssertPtrNotNull (test, cmd.base.generate_error_packet);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_interface_null_init (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
}

static void cmd_interface_null_test_static_init (CuTest *test)
{
	struct cmd_interface_null cmd = cmd_interface_null_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, cmd.base.process_request);
	CuAssertPtrNotNull (test, cmd.base.process_response);
	CuAssertPtrNotNull (test, cmd.base.generate_error_packet);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_null_release (NULL);
}

static void cmd_interface_null_test_init_process_request (CuTest *test)
{
	struct cmd_interface_null cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = cmd.base.process_request (&cmd.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_process_request_static_init (CuTest *test)
{
	struct cmd_interface_null cmd = cmd_interface_null_static_init;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd.base.process_request (&cmd.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_process_request_null (CuTest *test)
{
	struct cmd_interface_null cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_get_fw_version *req = (struct cerberus_protocol_get_fw_version*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	req->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	req->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	req->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	req->area = 0;
	request.length = sizeof (struct cerberus_protocol_get_fw_version);
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = cmd.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.base.process_request (&cmd.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_process_response (CuTest *test)
{
	struct cmd_interface_null cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_get_fw_version_response *resp =
		(struct cerberus_protocol_get_fw_version_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	response.length = sizeof (struct cerberus_protocol_get_fw_version_response);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = cmd.base.process_response (&cmd.base, &response);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_process_response_static_init (CuTest *test)
{
	struct cmd_interface_null cmd = cmd_interface_null_static_init;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_get_fw_version_response *resp =
		(struct cerberus_protocol_get_fw_version_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	response.length = sizeof (struct cerberus_protocol_get_fw_version_response);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd.base.process_response (&cmd.base, &response);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_process_response_null (CuTest *test)
{
	struct cmd_interface_null cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_get_fw_version_response *resp =
		(struct cerberus_protocol_get_fw_version_response*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	resp->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	resp->header.command = CERBERUS_PROTOCOL_GET_FW_VERSION;

	response.length = sizeof (struct cerberus_protocol_get_fw_version_response);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = cmd.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.base.process_response (&cmd.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_generate_error_packet (CuTest *test)
{
	struct cmd_interface_null cmd;
	int status;

	TEST_START;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_generate_error_packet (test, &cmd.base);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_generate_error_packet_static_init (CuTest *test)
{
	struct cmd_interface_null cmd = cmd_interface_null_static_init;

	TEST_START;

	cerberus_protocol_required_commands_testing_generate_error_packet (test, &cmd.base);

	cmd_interface_null_release (&cmd);
}

static void cmd_interface_null_test_init_generate_error_packet_null (CuTest *test)
{
	struct cmd_interface_null cmd;
	int status;

	TEST_START;

	status = cmd_interface_null_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (test, &cmd.base);

	cmd_interface_null_release (&cmd);
}


TEST_SUITE_START (cmd_interface_null);

TEST (cmd_interface_null_test_init);
TEST (cmd_interface_null_test_init_null);
TEST (cmd_interface_null_test_static_init);
TEST (cmd_interface_null_test_release_null);
TEST (cmd_interface_null_test_init_process_request);
TEST (cmd_interface_null_test_init_process_request_static_init);
TEST (cmd_interface_null_test_init_process_request_null);
TEST (cmd_interface_null_test_init_process_response);
TEST (cmd_interface_null_test_init_process_response_static_init);
TEST (cmd_interface_null_test_init_process_response_null);
TEST (cmd_interface_null_test_init_generate_error_packet);
TEST (cmd_interface_null_test_init_generate_error_packet_static_init);
TEST (cmd_interface_null_test_init_generate_error_packet_null);

TEST_SUITE_END;
