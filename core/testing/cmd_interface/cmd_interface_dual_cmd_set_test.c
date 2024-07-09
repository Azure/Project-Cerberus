// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "cmd_interface/cmd_interface_dual_cmd_set.h"
#include "cmd_interface/cmd_interface_dual_cmd_set_static.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("cmd_interface_dual_cmd_set");


/**
 * Dependencies for testing the dual command set interface.
 */
struct cmd_interface_dual_cmd_set_testing {
	struct cmd_interface_mock primary_handler;		/**< Primary command handler instance. */
	struct cmd_interface_mock secondary_handler;	/**< Secondary command handler instance. */
	struct cmd_interface_dual_cmd_set interface;	/**< Dual command set handler instance. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to initialize.
 */
static void cmd_interface_dual_cmd_set_testing_init_dependencies (CuTest *test,
	struct cmd_interface_dual_cmd_set_testing *cmd)
{
	int status;

	status = cmd_interface_mock_init (&cmd->primary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd->secondary_handler);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to release.
 */
static void cmd_interface_dual_cmd_set_testing_release_dependencies (CuTest *test,
	struct cmd_interface_dual_cmd_set_testing *cmd)
{
	int status;

	status = cmd_interface_mock_validate_and_release (&cmd->primary_handler);
	status |= cmd_interface_mock_validate_and_release (&cmd->secondary_handler);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to setup the dual command set interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 */
static void setup_cmd_interface_dual_cmd_set_test (CuTest *test,
	struct cmd_interface_dual_cmd_set_testing *cmd)
{
	int status;

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, cmd);

	status = cmd_interface_dual_cmd_set_init (&cmd->interface, &cmd->primary_handler.base,
		&cmd->secondary_handler.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release cmd interface instance
 *
 * @param test The test framework
 * @param cmd The testing instance to release
 */
static void complete_cmd_interface_dual_cmd_set_test (CuTest *test,
	struct cmd_interface_dual_cmd_set_testing *cmd)
{
	cmd_interface_dual_cmd_set_testing_release_dependencies (test, cmd);

	cmd_interface_dual_cmd_set_deinit (&cmd->interface);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_dual_cmd_set_test_init (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	int status;

	TEST_START;

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, &cmd);

	status = cmd_interface_dual_cmd_set_init (&cmd.interface, &cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cmd.interface.base.process_request);
	CuAssertPtrNotNull (test, cmd.interface.base.process_response);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_init_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	int status;

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, &cmd);

	status = cmd_interface_dual_cmd_set_init (NULL, &cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_dual_cmd_set_init (&cmd.interface, NULL, &cmd.secondary_handler.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_dual_cmd_set_init (&cmd.interface, &cmd.primary_handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_dual_cmd_set_testing_release_dependencies (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_static_init (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_dual_cmd_set test_static =
		cmd_interface_dual_cmd_set_static_init (&cmd.primary_handler.base,
		&cmd.secondary_handler.base);

	TEST_START;

	CuAssertPtrNotNull (test, test_static.base.process_request);
	CuAssertPtrNotNull (test, test_static.base.process_response);

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, &cmd);

	cmd_interface_dual_cmd_set_testing_release_dependencies (test, &cmd);
	cmd_interface_dual_cmd_set_deinit (&test_static);
}

static void cmd_interface_dual_cmd_set_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_dual_cmd_set_deinit (NULL);
}

static void cmd_interface_dual_cmd_set_test_process_request_payload_too_short (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = 0xAA;
	request.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_unsupported_message (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	header->msg_type = 0x11;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = 0xAA;
	request.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = 0xAA;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.data[0] = 0;
	request.length = 1;
	request.source_eid = 0xAA;
	request.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.interface.base.process_request (&cmd.interface.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_0 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.primary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_encrypted (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_msg request;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.primary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_static_init (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_dual_cmd_set test_static =
		cmd_interface_dual_cmd_set_static_init (&cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.primary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = test_static.base.process_request (&test_static.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	cmd_interface_dual_cmd_set_testing_release_dependencies (test, &cmd);
	cmd_interface_dual_cmd_set_deinit (&test_static);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_1 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.secondary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_encrypted (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.secondary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_static_init (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_dual_cmd_set test_static =
		cmd_interface_dual_cmd_set_static_init (&cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.secondary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = test_static.base.process_request (&test_static.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	cmd_interface_dual_cmd_set_testing_release_dependencies (test, &cmd);
	cmd_interface_dual_cmd_set_deinit (&test_static);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_reserved_fields_not_zero (
	CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 1;
	header->integrity_check = 0;
	header->reserved1 = 1;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 1;
	header->integrity_check = 0;
	header->reserved1 = 1;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.primary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 1, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 1, header->reserved1);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_reserved_fields_not_zero (
	CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 1;
	header->integrity_check = 0;
	header->reserved1 = 1;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response_data;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 1;
	header->integrity_check = 0;
	header->reserved1 = 1;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.secondary_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 1, header->reserved2);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 1, header->reserved1);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.payload = request.data;
	request.payload_length = request.length;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_payload_too_short (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	response.source_eid = 0xAA;
	response.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_unsupported_message (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	header->msg_type = 0x11;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;

	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = 0xAA;
	response.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = 0xAA;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_error_packet (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_ERROR;

	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xAA;
	response.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_response,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.data[0] = 0;
	response.length = 1;
	response.source_eid = 0xAA;
	response.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	status = cmd.interface.base.process_response (&cmd.interface.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_0 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_response,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_0_encrypted (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_response,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_1 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_response,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_1_encrypted (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_response,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_static_init (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_dual_cmd_set test_static =
		cmd_interface_dual_cmd_set_static_init (&cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	cmd_interface_dual_cmd_set_testing_init_dependencies (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_response,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = test_static.base.process_response (&test_static.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	cmd_interface_dual_cmd_set_testing_release_dependencies (test, &cmd);
	cmd_interface_dual_cmd_set_deinit (&test_static);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_0_reserved_fields_not_zero (
	CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 1;
	header->integrity_check = 0;
	header->reserved1 = 1;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_response,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_1_reserved_fields_not_zero (
	CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 1;
	header->integrity_check = 0;
	header->reserved1 = 1;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_response,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) response.data;

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_0_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_response,
		&cmd.primary_handler, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_response_cmd_set_1_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.payload = response.data;
	response.payload_length = response.length;
	response.source_eid = 0xCC;
	response.target_eid = 0xDD;
	response.channel_id = 0;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->reserved2 = 0;
	header->integrity_check = 0;
	header->reserved1 = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_response,
		&cmd.secondary_handler, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	response.crypto_timeout = true;
	status = cmd.interface.base.process_response (&cmd.interface.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, response.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_dual_cmd_set);

TEST (cmd_interface_dual_cmd_set_test_init);
TEST (cmd_interface_dual_cmd_set_test_init_null);
TEST (cmd_interface_dual_cmd_set_test_static_init);
TEST (cmd_interface_dual_cmd_set_test_deinit_null);
TEST (cmd_interface_dual_cmd_set_test_process_request_payload_too_short);
TEST (cmd_interface_dual_cmd_set_test_process_request_unsupported_message);
TEST (cmd_interface_dual_cmd_set_test_process_request_null);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_0);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_encrypted);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_static_init);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_1);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_encrypted);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_static_init);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_reserved_fields_not_zero);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_reserved_fields_not_zero);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_0_fail);
TEST (cmd_interface_dual_cmd_set_test_process_request_cmd_set_1_fail);
TEST (cmd_interface_dual_cmd_set_test_process_response_payload_too_short);
TEST (cmd_interface_dual_cmd_set_test_process_response_unsupported_message);
TEST (cmd_interface_dual_cmd_set_test_process_response_error_packet);
TEST (cmd_interface_dual_cmd_set_test_process_response_null);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_0);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_0_encrypted);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_1);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_1_encrypted);
TEST (cmd_interface_dual_cmd_set_test_process_response_static_init);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_0_reserved_fields_not_zero);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_1_reserved_fields_not_zero);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_0_fail);
TEST (cmd_interface_dual_cmd_set_test_process_response_cmd_set_1_fail);

TEST_SUITE_END;
// *INDENT-ON*
