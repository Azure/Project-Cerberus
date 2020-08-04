// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "testing.h"
#include "platform.h"
#include "mock/cmd_interface_mock.h"
#include "mock/cmd_interface_mock.h"
#include "cmd_interface/cmd_interface_dual_cmd_set.h"


static const char *SUITE = "cmd_interface_dual_cmd_set";


/**
 * Dependencies for testing the dual command set interface.
 */
struct cmd_interface_dual_cmd_set_testing {
	struct cmd_interface_mock primary_handler;			/**< Primary command handler instance. */
	struct cmd_interface_mock secondary_handler;		/**< Secondary command handler instance. */
	struct cmd_interface_dual_cmd_set interface;		/**< Dual command set handler instance. */
};

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

	status = cmd_interface_mock_init (&cmd->primary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd->secondary_handler);
	CuAssertIntEquals (test, 0, status);

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
	int status;

	status = cmd_interface_mock_validate_and_release (&cmd->primary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd->secondary_handler);
	CuAssertIntEquals (test, 0, status);

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

	status = cmd_interface_mock_init (&cmd.primary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd.secondary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_dual_cmd_set_init (&cmd.interface, &cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cmd.interface.base.process_request);
	CuAssertPtrNotNull (test, cmd.interface.base.issue_request);
	CuAssertPtrNotNull (test, cmd.interface.base.generate_error_packet);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_init_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	int status;

	status = cmd_interface_mock_init (&cmd.primary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd.secondary_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_dual_cmd_set_init (NULL, &cmd.primary_handler.base,
		&cmd.secondary_handler.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_dual_cmd_set_init (&cmd.interface, NULL, &cmd.secondary_handler.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_dual_cmd_set_init (&cmd.interface, &cmd.primary_handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_deinit_null (CuTest *test)
{
	TEST_START;

	cmd_interface_dual_cmd_set_deinit (NULL);
}

static void cmd_interface_dual_cmd_set_test_process_payload_too_short (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
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

static void cmd_interface_dual_cmd_set_test_process_unsupported_message (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = 0x11;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = 0xAA;
	request.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = 0xAA;

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_error_packet (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = CERBERUS_PROTOCOL_ERROR;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = 0xAA;
	request.target_eid = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_ERROR_MESSAGE_ESCAPE_SEQ, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
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

static void cmd_interface_dual_cmd_set_test_process_cmd_set_0 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct cerberus_protocol_header* header =
		(struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response.data;

	memset (&response, 0, sizeof (response));
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_TMP (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.primary_handler.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_cmd_set_0_encrypted (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct cerberus_protocol_header* header =
		(struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response.data;

	memset (&response, 0, sizeof (response));
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, 0,
		MOCK_ARG_VALIDATOR_TMP (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.primary_handler.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_cmd_set_1 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct cerberus_protocol_header* header =
		(struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response.data;

	memset (&response, 0, sizeof (response));
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_TMP (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.secondary_handler.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_cmd_set_1_encrypted (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct cerberus_protocol_header* header =
		(struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	header = (struct cerberus_protocol_header*) response.data;

	memset (&response, 0, sizeof (response));
	response.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	response.source_eid = 0xDD;
	response.target_eid = 0xCC;
	response.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 1;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 1;
	header->command = 0x04;
	response.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xBB;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, 0,
		MOCK_ARG_VALIDATOR_TMP (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.secondary_handler.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	header = (struct cerberus_protocol_header*) request.data;

	request.new_request = true;
	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MIN_MSG_LEN + 1, request.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->d_bit);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, 0, header->seq_num);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x04, header->command);
	CuAssertIntEquals (test, 0xBB, request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN]);
	CuAssertIntEquals (test, false, request.new_request);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_cmd_set_0_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header* header =
		(struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 0;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.process_request,
		&cmd.primary_handler, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_TMP (cmd_interface_mock_validate_request, &request, sizeof (request)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_process_cmd_set_1_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request request;
	struct cerberus_protocol_header* header =
		(struct cerberus_protocol_header*) request.data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN + 1;
	request.source_eid = 0xCC;
	request.target_eid = 0xDD;
	request.channel_id = 0;

	header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->crypt = 0;
	header->d_bit = 0;
	header->integrity_check = 0;
	header->seq_num = 0;
	header->rq = 1;
	header->command = 0x04;
	request.data[CERBERUS_PROTOCOL_MIN_MSG_LEN] = 0xAA;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock, cmd.secondary_handler.base.process_request,
		&cmd.secondary_handler, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_TMP (cmd_interface_mock_validate_request, &request, sizeof (request)));

	CuAssertIntEquals (test, 0, status);

	request.crypto_timeout = true;
	status = cmd.interface.base.process_request (&cmd.interface.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_issue_request_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = cmd.interface.base.issue_request (NULL,
		CERBERUS_PROTOCOL_GET_DEVICE_CAPABILITIES, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_issue_request (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t buf[3] = {0};
	uint8_t ex_buf[3];
	int status;

	TEST_START;

	ex_buf[0] = 1;
	ex_buf[1] = 2;
	ex_buf[2] = 3;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.issue_request,
		&cmd.primary_handler, 3, MOCK_ARG (1), MOCK_ARG (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (buf)));
	status |= mock_expect_output (&cmd.primary_handler.mock, 2, ex_buf, sizeof (ex_buf), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd.interface.base.issue_request (&cmd.interface.base, 1, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, 3, status);

	status = testing_validate_array (ex_buf, buf, sizeof (ex_buf));
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_issue_request_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	uint8_t buf[3] = {0};
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.issue_request,
		&cmd.primary_handler, CMD_HANDLER_NO_MEMORY, MOCK_ARG (1), MOCK_ARG (NULL),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (buf)));

	CuAssertIntEquals (test, 0, status);

	status = cmd.interface.base.issue_request (&cmd.interface.base, 1, NULL, buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_generate_error_packet_set_0 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request error_packet;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_packet.data;
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	memset (&error_packet, 0, sizeof (error_packet));

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.d_bit = 0;
	error->header.integrity_check = 0;
	error->header.seq_num = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	error_packet.length = sizeof (struct cerberus_protocol_error);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.generate_error_packet,
		&cmd.primary_handler, 0, MOCK_ARG (&error_packet), MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&cmd.primary_handler.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = cmd.interface.base.generate_error_packet (&cmd.interface.base, &error_packet,
		CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_error), error_packet.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.d_bit);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.seq_num);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_generate_error_packet_set_1 (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request error_packet;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_packet.data;
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	memset (&error_packet, 0, sizeof (error_packet));

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.d_bit = 0;
	error->header.integrity_check = 0;
	error->header.seq_num = 0;
	error->header.rq = 1;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	error_packet.length = sizeof (struct cerberus_protocol_error);

	status = mock_expect (&cmd.secondary_handler.mock,
		cmd.secondary_handler.base.generate_error_packet, &cmd.secondary_handler, 0,
		MOCK_ARG (&error_packet), MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (1));
	status |= mock_expect_output (&cmd.secondary_handler.mock, 0, &error_packet,
		sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd.interface.base.generate_error_packet (&cmd.interface.base, &error_packet,
		CERBERUS_PROTOCOL_NO_ERROR, 0, 1);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct cerberus_protocol_error), error_packet.length);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.d_bit);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.seq_num);
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_generate_error_packet_null (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request error_packet;
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = cmd.interface.base.generate_error_packet (NULL, &error_packet,
		CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_generate_error_packet_set_0_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request error_packet;
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.primary_handler.mock, cmd.primary_handler.base.generate_error_packet,
		&cmd.primary_handler, CMD_HANDLER_NO_MEMORY, MOCK_ARG (&error_packet),
		MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = cmd.interface.base.generate_error_packet (&cmd.interface.base, &error_packet,
		CERBERUS_PROTOCOL_NO_ERROR, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}

static void cmd_interface_dual_cmd_set_test_generate_error_packet_set_1_fail (CuTest *test)
{
	struct cmd_interface_dual_cmd_set_testing cmd;
	struct cmd_interface_request error_packet;
	int status;

	TEST_START;

	setup_cmd_interface_dual_cmd_set_test (test, &cmd);

	status = mock_expect (&cmd.secondary_handler.mock,
		cmd.secondary_handler.base.generate_error_packet, &cmd.secondary_handler,
		CMD_HANDLER_NO_MEMORY, MOCK_ARG (&error_packet), MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = cmd.interface.base.generate_error_packet (&cmd.interface.base, &error_packet,
		CERBERUS_PROTOCOL_NO_ERROR, 0, 1);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);

	complete_cmd_interface_dual_cmd_set_test (test, &cmd);
}


CuSuite* get_cmd_interface_dual_cmd_set_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_init);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_init_null);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_deinit_null);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_payload_too_short);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_unsupported_message);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_error_packet);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_null);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_cmd_set_0);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_cmd_set_0_encrypted);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_cmd_set_1);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_cmd_set_1_encrypted);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_cmd_set_0_fail);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_process_cmd_set_1_fail);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_issue_request_null);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_issue_request);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_issue_request_fail);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_generate_error_packet_set_0);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_generate_error_packet_set_1);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_generate_error_packet_null);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_generate_error_packet_set_0_fail);
	SUITE_ADD_TEST (suite, cmd_interface_dual_cmd_set_test_generate_error_packet_set_1_fail);

	return suite;
}
