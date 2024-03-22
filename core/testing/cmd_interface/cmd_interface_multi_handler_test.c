// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_interface_multi_handler.h"
#include "cmd_interface/cmd_interface_multi_handler_static.h"
#include "common/array_size.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_protocol_mock.h"


TEST_SUITE_LABEL ("cmd_interface_multi_handler");


/**
 * Dependencies for testing the multi-message type command handler.
 */
struct cmd_interface_multi_handler_testing {
	struct cmd_interface_protocol_mock protocol;				/**< Mock for the protocol handler. */
	struct cmd_interface_mock msg_handler[3];					/**< Mock for the message handlers. */
	struct cmd_interface_multi_handler_msg_type msg_type[3];	/**< List of message handlers. */
	struct cmd_interface_multi_handler test;					/**< Command handler instance under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to initialize.
 */
static void cmd_interface_multi_handler_testing_init_dependencies (CuTest *test,
	struct cmd_interface_multi_handler_testing *cmd)
{
	int status;
	size_t i;

	status = cmd_interface_protocol_mock_init (&cmd->protocol);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < ARRAY_SIZE (cmd->msg_type); i++) {
		status = cmd_interface_mock_init (&cmd->msg_handler[i]);
		CuAssertIntEquals (test, 0, status);

		status = cmd_interface_multi_handler_msg_type_init (&cmd->msg_type[i], i * 4,
			&cmd->msg_handler[i].base);
		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to release.
 */
static void cmd_interface_multi_handler_testing_release_dependencies (CuTest *test,
	struct cmd_interface_multi_handler_testing *cmd)
{
	int status;
	size_t i;

	status = cmd_interface_protocol_mock_validate_and_release (&cmd->protocol);

	for (i = 0; i < ARRAY_SIZE (cmd->msg_type); i++) {
		status |= cmd_interface_mock_validate_and_release (&cmd->msg_handler[i]);
	}

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a multi-message type command handler for testing.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to initialize.
 */
static void cmd_interface_multi_handler_testing_init (CuTest *test,
	struct cmd_interface_multi_handler_testing *cmd)
{
	int status;

	cmd_interface_multi_handler_testing_init_dependencies (test, cmd);

	status = cmd_interface_multi_handler_init (&cmd->test, &cmd->protocol.base, cmd->msg_type,
		ARRAY_SIZE (cmd->msg_type));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release multi-message type command handler test components and validate all mocks.
 *
 * @param test The test framework.
 * @param cmd Testing dependencies to release.
 */
static void cmd_interface_multi_handler_testing_release (CuTest *test,
	struct cmd_interface_multi_handler_testing *cmd)
{
	cmd_interface_multi_handler_release (&cmd->test);
	cmd_interface_multi_handler_testing_release_dependencies (test, cmd);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_multi_handler_test_msg_type_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;

	TEST_START;

	status = cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[0], 0x1234,
		&cmd.msg_handler[0].base);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x1234, cmd.msg_type[0].type_id);
	CuAssertPtrEquals (test, &cmd.msg_handler[0], (void*) cmd.msg_type[0].handler);
}

static void cmd_interface_multi_handler_test_msg_type_init_null (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;

	TEST_START;

	status = cmd_interface_multi_handler_msg_type_init (NULL, 0x1234,
		&cmd.msg_handler[0].base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[0], 0x1234,
		NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
}

static void cmd_interface_multi_handler_test_msg_type_init_static_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd = {
		.msg_type = {
			cmd_interface_multi_handler_msg_type_static_init (0x54321, &cmd.msg_handler[1].base)
		}
	};

	TEST_START;

	CuAssertIntEquals (test, 0x54321, cmd.msg_type[0].type_id);
	CuAssertPtrEquals (test, &cmd.msg_handler[1], (void*) cmd.msg_type[0].handler);
}

static void cmd_interface_multi_handler_test_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;

	TEST_START;

	cmd_interface_multi_handler_testing_init_dependencies (test, &cmd);

	status = cmd_interface_multi_handler_init (&cmd.test, &cmd.protocol.base, cmd.msg_type, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cmd.test.base.process_request);
	CuAssertPtrNotNull (test, cmd.test.base.process_response);
	CuAssertPtrNotNull (test, cmd.test.base.generate_error_packet);

	CuAssertPtrNotNull (test, cmd.test.is_message_type_supported);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_init_null (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;

	TEST_START;

	cmd_interface_multi_handler_testing_init_dependencies (test, &cmd);

	status = cmd_interface_multi_handler_init (NULL, &cmd.protocol.base, cmd.msg_type, 1);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_multi_handler_init (&cmd.test, NULL, cmd.msg_type, 1);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_multi_handler_init (&cmd.test, &cmd.protocol.base, NULL, 1);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_multi_handler_init (&cmd.test, &cmd.protocol.base, cmd.msg_type, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_multi_handler_testing_release_dependencies (test, &cmd);
}

static void cmd_interface_multi_handler_test_static_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd = {
		.msg_type = {
			cmd_interface_multi_handler_msg_type_static_init (0x1122, &cmd.msg_handler[0].base)
		},
		.test = cmd_interface_multi_handler_static_init (&cmd.protocol.base, cmd.msg_type, 1)
	};

	TEST_START;

	CuAssertPtrNotNull (test, cmd.test.base.process_request);
	CuAssertPtrNotNull (test, cmd.test.base.process_response);
	CuAssertPtrNotNull (test, cmd.test.base.generate_error_packet);

	CuAssertPtrNotNull (test, cmd.test.is_message_type_supported);

	cmd_interface_multi_handler_testing_init_dependencies (test, &cmd);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_multi_handler_release (NULL);
}

static void cmd_interface_multi_handler_test_process_request_no_protocol_header (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	uint32_t message_type = 0;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[0].mock, cmd.msg_handler[0].base.process_request,
		&cmd.msg_handler[0], 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.msg_handler[0].mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (0), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_with_protocol_header (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	size_t protocol_header = 14;
	uint32_t message_type = 0;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));

	for (i = 0; i < response_length + protocol_header; i++) {
		response_data[i] = ~i;
	}

	response.data = &response_data[protocol_header];
	response.length = response_length;
	response.payload = &response_data[protocol_header];
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	/* Get the message type, no payload offset. */
	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	/* Return the request with a protocol header offset. */
	request.payload = &data[protocol_header];
	request.payload_length = sizeof (data) - protocol_header;
	status |= mock_expect_output_deep_copy_tmp (&cmd.protocol.mock, 0, &request,
		sizeof (request), cmd_interface_mock_copy_request, cmd_interface_mock_duplicate_request,
		cmd_interface_mock_free_request);

	/* Process the request and generate a response with a protocol header offset. */
	status |= mock_expect (&cmd.msg_handler[0].mock, cmd.msg_handler[0].base.process_request,
		&cmd.msg_handler[0], 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy_tmp (&cmd.msg_handler[0].mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request, cmd_interface_mock_duplicate_request,
		cmd_interface_mock_free_request);

	/* Handle the result, still with the offset. */
	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (0), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	/* Return the response with no protocol header offset. */
	response.data = response_data;
	response.length = response_length + protocol_header;
	response.payload = response.data;
	response.payload_length = response.length;
	status |= mock_expect_output_deep_copy (&cmd.protocol.mock, 2, &response, sizeof (response),
		cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Reset the request to no offset for processing. */
	request.payload = request.data;
	request.payload_length = request.length;

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length + protocol_header, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_last_message_type (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[128];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 96;
	uint32_t message_type = 8;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[2].mock, cmd.msg_handler[2].base.process_request,
		&cmd.msg_handler[2], 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.msg_handler[2].mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (0), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_encrypt_flag_set (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 128;
	uint32_t message_type = 4;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = 64;
	request.payload = data;
	request.payload_length = 64;
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = true;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = true;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[1].mock, cmd.msg_handler[1].base.process_request,
		&cmd.msg_handler[1], 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.msg_handler[1].mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (0), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, true, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_no_response_handling (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	uint32_t message_type = 0;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	/* Remove the response handler. */
	cmd.protocol.base.handle_request_result = NULL;

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[0].mock, cmd.msg_handler[0].base.process_request,
		&cmd.msg_handler[0], 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.msg_handler[0].mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_static_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd = {
		.test = cmd_interface_multi_handler_static_init (&cmd.protocol.base, cmd.msg_type, 3)
	};
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	uint32_t message_type = 0x44332211;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init_dependencies (test, &cmd);

	/* Use different message type IDs. */
	cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[0], 0x1122, &cmd.msg_handler[0].base);
	cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[1], 0x88776655,
		&cmd.msg_handler[1].base);
	cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[2], 0x44332211,
		&cmd.msg_handler[2].base);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[2].mock, cmd.msg_handler[2].base.process_request,
		&cmd.msg_handler[2], 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.msg_handler[2].mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (0), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_null (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = cmd.test.base.process_request (NULL, &request);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd.test.base.process_request (&cmd.test.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_message_type_failed (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol,
		CMD_HANDLER_PROTO_PARSE_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PROTO_PARSE_FAILED, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_message_type_error_response (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol,
		CMD_HANDLER_PROTO_ERROR_RESPONSE,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_deep_copy (&cmd.protocol.mock, 0, &response, sizeof (response),
		cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_fail_with_error_response (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	uint32_t message_type = 0;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[0].mock, cmd.msg_handler[0].base.process_request,
		&cmd.msg_handler[0], CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (CMD_HANDLER_PROCESS_FAILED), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.protocol.mock, 2, &response, sizeof (response),
		cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_fail_without_error_response (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint32_t message_type = 0;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[0].mock, cmd.msg_handler[0].base.process_request,
		&cmd.msg_handler[0], CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, CMD_HANDLER_PROTO_HANDLE_FAILED, MOCK_ARG (CMD_HANDLER_PROCESS_FAILED),
		MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PROTO_HANDLE_FAILED, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_fail_no_response_handling (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint32_t message_type = 0;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	/* Remove the response handler. */
	cmd.protocol.base.handle_request_result = NULL;

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.msg_handler[0].mock, cmd.msg_handler[0].base.process_request,
		&cmd.msg_handler[0], CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_unknown_message_type_with_error_response (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint8_t response_data[sizeof (data)];
	struct cmd_interface_msg response;
	size_t response_length = 64;
	uint32_t message_type = 3;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	for (i = 0; i < response_length; i++) {
		response_data[i] = ~i;
	}

	response.length = response_length;
	response.payload = response_data;
	response.payload_length = response_length;
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, 0, MOCK_ARG (CMD_HANDLER_UNKNOWN_MESSAGE_TYPE), MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cmd.protocol.mock, 2, &response, sizeof (response),
		cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, request.data, request.payload);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertIntEquals (test, sizeof (response_data), request.max_response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x55, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 4, request.channel_id);

	status = testing_validate_array (response_data, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_unknown_message_type_without_error_response (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint32_t message_type = 3;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	status |= mock_expect (&cmd.protocol.mock, cmd.protocol.base.handle_request_result,
		&cmd.protocol, CMD_HANDLER_BUF_TOO_SMALL, MOCK_ARG (CMD_HANDLER_UNKNOWN_MESSAGE_TYPE),
		MOCK_ARG (message_type),
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_BUF_TOO_SMALL, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_request_unknown_message_type_no_response_handling (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t data[256];
	struct cmd_interface_msg request;
	uint32_t message_type = 3;
	int status;
	size_t i;

	TEST_START;

	memset (&request, 0, sizeof (request));
	memset (data, 0, sizeof (data));
	request.data = data;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	request.length = sizeof (data);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.max_response = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	/* Remove the response handler. */
	cmd.protocol.base.handle_request_result = NULL;

	status = mock_expect (&cmd.protocol.mock, cmd.protocol.base.parse_message, &cmd.protocol, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&cmd.protocol.mock, 1, &message_type, sizeof (message_type), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd.test.base.process_request (&cmd.test.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_MESSAGE_TYPE, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_response (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	uint8_t response_data[64];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	response.length = sizeof (response_data);
	response.payload = response_data;
	response.payload_length = sizeof (response_data);
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = cmd.test.base.process_response (&cmd.test.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_process_response_static_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd = {
		.test = cmd_interface_multi_handler_static_init (&cmd.protocol.base, cmd.msg_type, 3)
	};
	uint8_t response_data[64];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;

	response.length = sizeof (response_data);
	response.payload = response_data;
	response.payload_length = sizeof (response_data);
	response.max_response = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 4;

	cmd_interface_multi_handler_testing_init_dependencies (test, &cmd);

	status = cmd.test.base.process_response (&cmd.test.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_generate_error_packet (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = cmd.test.base.generate_error_packet (&cmd.test.base, &request, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_generate_error_packet_static_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd = {
		.test = cmd_interface_multi_handler_static_init (&cmd.protocol.base, cmd.msg_type, 3)
	};
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	cmd_interface_multi_handler_testing_init_dependencies (test, &cmd);

	status = cmd.test.base.generate_error_packet (&cmd.test.base, &request, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_OPERATION, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_is_message_type_supported (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;
	TEST_START;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = cmd.test.is_message_type_supported (&cmd.test, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd.test.is_message_type_supported (&cmd.test, 4);
	CuAssertIntEquals (test, 0, status);

	status = cmd.test.is_message_type_supported (&cmd.test, 8);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_is_message_type_supported_static_init (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd = {
		.test = cmd_interface_multi_handler_static_init (&cmd.protocol.base, cmd.msg_type, 3)
	};
	int status;
	TEST_START;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	/* Use different message type IDs. */
	cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[0], 0x1122, &cmd.msg_handler[0].base);
	cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[1], 0x88776655,
		&cmd.msg_handler[1].base);
	cmd_interface_multi_handler_msg_type_init (&cmd.msg_type[2], 0x44332211,
		&cmd.msg_handler[2].base);

	status = cmd.test.is_message_type_supported (&cmd.test, 0x1122);
	CuAssertIntEquals (test, 0, status);

	status = cmd.test.is_message_type_supported (&cmd.test, 0x88776655);
	CuAssertIntEquals (test, 0, status);

	status = cmd.test.is_message_type_supported (&cmd.test, 0x44332211);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_is_message_type_supported_null (CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;
	TEST_START;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = cmd.test.is_message_type_supported (NULL, 0);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}

static void cmd_interface_multi_handler_test_is_message_type_supported_unknown_message_type (
	CuTest *test)
{
	struct cmd_interface_multi_handler_testing cmd;
	int status;
	TEST_START;

	cmd_interface_multi_handler_testing_init (test, &cmd);

	status = cmd.test.is_message_type_supported (&cmd.test, 1);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_MESSAGE_TYPE, status);

	cmd_interface_multi_handler_testing_release (test, &cmd);
}


TEST_SUITE_START (cmd_interface_multi_handler);

TEST (cmd_interface_multi_handler_test_msg_type_init);
TEST (cmd_interface_multi_handler_test_msg_type_init_null);
TEST (cmd_interface_multi_handler_test_msg_type_init_static_init);
TEST (cmd_interface_multi_handler_test_init);
TEST (cmd_interface_multi_handler_test_init_null);
TEST (cmd_interface_multi_handler_test_static_init);
TEST (cmd_interface_multi_handler_test_release_null);
TEST (cmd_interface_multi_handler_test_process_request_no_protocol_header);
TEST (cmd_interface_multi_handler_test_process_request_with_protocol_header);
TEST (cmd_interface_multi_handler_test_process_request_last_message_type);
TEST (cmd_interface_multi_handler_test_process_request_encrypt_flag_set);
TEST (cmd_interface_multi_handler_test_process_request_no_response_handling);
TEST (cmd_interface_multi_handler_test_process_request_static_init);
TEST (cmd_interface_multi_handler_test_process_request_null);
TEST (cmd_interface_multi_handler_test_process_request_message_type_failed);
TEST (cmd_interface_multi_handler_test_process_request_message_type_error_response);
TEST (cmd_interface_multi_handler_test_process_request_fail_with_error_response);
TEST (cmd_interface_multi_handler_test_process_request_fail_without_error_response);
TEST (cmd_interface_multi_handler_test_process_request_fail_no_response_handling);
TEST (cmd_interface_multi_handler_test_process_request_unknown_message_type_with_error_response);
TEST (cmd_interface_multi_handler_test_process_request_unknown_message_type_without_error_response);
TEST (cmd_interface_multi_handler_test_process_request_unknown_message_type_no_response_handling);
TEST (cmd_interface_multi_handler_test_process_response);
TEST (cmd_interface_multi_handler_test_process_response_static_init);
TEST (cmd_interface_multi_handler_test_generate_error_packet);
TEST (cmd_interface_multi_handler_test_generate_error_packet_static_init);
TEST (cmd_interface_multi_handler_test_is_message_type_supported);
TEST (cmd_interface_multi_handler_test_is_message_type_supported_static_init);
TEST (cmd_interface_multi_handler_test_is_message_type_supported_null);
TEST (cmd_interface_multi_handler_test_is_message_type_supported_unknown_message_type);

TEST_SUITE_END;
