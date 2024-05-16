// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "cmd_interface/device_manager.h"
#include "mctp/mctp_base_protocol.h"
#include "rma/cmd_interface_rma.h"
#include "rma/cmd_interface_rma_static.h"
#include "testing/cmd_interface/cerberus_protocol_required_commands_testing.h"


TEST_SUITE_LABEL ("cmd_interface_rma");


/**
 * Dependencies for testing the slave command interface.
 */
struct cmd_interface_rma_testing {
	struct device_manager device_manager;	/**< Device manager. */
	struct cmd_interface_rma handler;		/**< Command handler instance. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to initialize.
 */
static void cmd_interface_rma_testing_init_dependencies (CuTest *test,
	struct cmd_interface_rma_testing *cmd)
{
	int status;

	status = device_manager_init (&cmd->device_manager, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&cmd->device_manager, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&cmd->device_manager, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0, 1);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to release.
 */
static void cmd_interface_rma_testing_release_dependencies (CuTest *test,
	struct cmd_interface_rma_testing *cmd)
{
	device_manager_release (&cmd->device_manager);
}

/**
 * Helper function to initialize a RMA command handler for testing.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to initialize.
 */
static void cmd_interface_rma_testing_init (CuTest *test, struct cmd_interface_rma_testing *cmd)
{
	int status;

	cmd_interface_rma_testing_init_dependencies (test, cmd);

	status = cmd_interface_rma_init (&cmd->handler, &cmd->device_manager);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the testing components and validate all mocks.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
static void cmd_interface_rma_testing_release (CuTest *test, struct cmd_interface_rma_testing *cmd)
{
	cmd_interface_rma_testing_release_dependencies (test, cmd);

	cmd_interface_rma_release (&cmd->handler);
}

/*******************
 * Test cases
 *******************/

static void cmd_interface_rma_test_init (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	int status;

	TEST_START;

	cmd_interface_rma_testing_init_dependencies (test, &cmd);

	status = cmd_interface_rma_init (&cmd.handler, &cmd.device_manager);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cmd.handler.base.process_request);
	CuAssertPtrNotNull (test, cmd.handler.base.process_response);
	CuAssertPtrNotNull (test, cmd.handler.base.generate_error_packet);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_init_null (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	int status;

	TEST_START;

	cmd_interface_rma_testing_init_dependencies (test, &cmd);

	status = cmd_interface_rma_init (NULL, &cmd.device_manager);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_rma_init (&cmd.handler, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_rma_testing_release_dependencies (test, &cmd);
}

static void cmd_interface_rma_test_static_init (CuTest *test)
{
	struct cmd_interface_rma_testing cmd = {
		.handler = cmd_interface_rma_static_init (&cmd.device_manager)
	};

	TEST_START;

	CuAssertPtrNotNull (test, cmd.handler.base.process_request);
	CuAssertPtrNotNull (test, cmd.handler.base.process_response);
	CuAssertPtrNotNull (test, cmd.handler.base.generate_error_packet);

	cmd_interface_rma_testing_init_dependencies (test, &cmd);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_rma_release (NULL);
}

static void cmd_interface_rma_test_process_get_capabilities (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	cerberus_protocol_required_commands_testing_process_get_capabilities (test, &cmd.handler.base,
		&cmd.device_manager);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_get_capabilities_static_init (CuTest *test)
{
	struct cmd_interface_rma_testing cmd = {
		.handler = cmd_interface_rma_static_init (&cmd.device_manager)
	};

	TEST_START;

	cmd_interface_rma_testing_init_dependencies (test, &cmd);

	cerberus_protocol_required_commands_testing_process_get_capabilities (test, &cmd.handler.base,
		&cmd.device_manager);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_get_capabilities_error (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	cerberus_protocol_required_commands_testing_process_get_capabilities_invalid_len (test,
		&cmd.handler.base);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_null (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	status = cmd.handler.base.process_request (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_payload_too_short (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN - 1;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cmd_interface_rma_testing_init (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_unsupported_message (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
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

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cmd_interface_rma_testing_init (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 1;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->integrity_check = 0;
	header->pci_vendor_id = 0xAA;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_reserved_fields_not_zero (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 1;
	header->reserved2 = 0;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cmd_interface_rma_testing_init (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	header->reserved1 = 0;
	header->reserved2 = 1;

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_unknown_command (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->command = 0xFF;

	request.length = CERBERUS_PROTOCOL_MIN_MSG_LEN;
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	cmd_interface_rma_testing_init (test, &cmd);

	request.crypto_timeout = true;
	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_REQUEST, status);
	CuAssertIntEquals (test, false, request.crypto_timeout);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_response (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_response_static_init (CuTest *test)
{
	struct cmd_interface_rma_testing cmd = {
		.handler = cmd_interface_rma_static_init (&cmd.device_manager)
	};
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	cmd_interface_rma_testing_init_dependencies (test, &cmd);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_process_response_null (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	status = cmd.handler.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_generate_error_packet (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet (test, &cmd.handler.base);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_generate_error_packet_static_init (CuTest *test)
{
	struct cmd_interface_rma_testing cmd = {
		.handler = cmd_interface_rma_static_init (&cmd.device_manager)
	};

	TEST_START;

	cmd_interface_rma_testing_init_dependencies (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet (test, &cmd.handler.base);

	cmd_interface_rma_testing_release (test, &cmd);
}

static void cmd_interface_rma_test_generate_error_packet_error (CuTest *test)
{
	struct cmd_interface_rma_testing cmd;

	TEST_START;

	cmd_interface_rma_testing_init (test, &cmd);

	cerberus_protocol_required_commands_testing_generate_error_packet_invalid_arg (test,
		&cmd.handler.base);

	cmd_interface_rma_testing_release (test, &cmd);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_rma);

TEST (cmd_interface_rma_test_init);
TEST (cmd_interface_rma_test_init_null);
TEST (cmd_interface_rma_test_static_init);
TEST (cmd_interface_rma_test_release_null);
TEST (cmd_interface_rma_test_process_get_capabilities);
TEST (cmd_interface_rma_test_process_get_capabilities_static_init);
TEST (cmd_interface_rma_test_process_get_capabilities_error);
TEST (cmd_interface_rma_test_process_null);
TEST (cmd_interface_rma_test_process_payload_too_short);
TEST (cmd_interface_rma_test_process_unsupported_message);
TEST (cmd_interface_rma_test_process_reserved_fields_not_zero);
TEST (cmd_interface_rma_test_process_unknown_command);
TEST (cmd_interface_rma_test_process_response);
TEST (cmd_interface_rma_test_process_response_static_init);
TEST (cmd_interface_rma_test_process_response_null);
TEST (cmd_interface_rma_test_generate_error_packet);
TEST (cmd_interface_rma_test_generate_error_packet_static_init);
TEST (cmd_interface_rma_test_generate_error_packet_error);

TEST_SUITE_END;
// *INDENT-ON*
