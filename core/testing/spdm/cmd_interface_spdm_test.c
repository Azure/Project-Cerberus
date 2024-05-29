// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "spdm/cmd_interface_spdm.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_protocol.h"
#include "spdm/spdm_protocol_observer.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/spdm/spdm_protocol_observer_mock.h"


TEST_SUITE_LABEL ("cmd_interface_spdm");


/**
 * Dependencies for testing the SPDM command interface.
 */
struct cmd_interface_spdm_testing {
	struct cmd_interface_spdm handler;				/**< Command handler instance. */
	struct spdm_protocol_observer_mock observer;	/**< SPDM protocol observer. */
};


/**
 * Helper function to setup the SPDM command interface.
 *
 * @param test The test framework.
 * @param cmd The instance to use for testing.
 * @param add_observer Flag indicating whether to register observer for SPDM response notifications.
 */
static void setup_cmd_interface_spdm_mock_test (CuTest *test,
	struct cmd_interface_spdm_testing *cmd, bool add_observer)
{
	int status;

	status = cmd_interface_spdm_init (&cmd->handler);
	CuAssertIntEquals (test, 0, status);

	status = spdm_protocol_observer_mock_init (&cmd->observer);
	CuAssertIntEquals (test, 0, status);

	if (add_observer) {
		status = cmd_interface_spdm_add_spdm_protocol_observer (&cmd->handler, &cmd->observer.base);
		CuAssertIntEquals (test, 0, status);
	}
}

/**
 * Helper function to release the SPDM command interface instance.
 *
 * @param test The test framework.
 * @param cmd The testing instance to release.
 */
static void complete_cmd_interface_spdm_mock_test (CuTest *test,
	struct cmd_interface_spdm_testing *cmd)
{
	int status;

	status = spdm_protocol_observer_mock_validate_and_release (&cmd->observer);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_deinit (&cmd->handler);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_spdm_test_init (CuTest *test)
{
	struct cmd_interface_spdm interface;
	int status;

	TEST_START;

	status = cmd_interface_spdm_init (&interface);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, interface.base.process_request);
	CuAssertPtrNotNull (test, interface.base.process_response);
	CuAssertPtrNotNull (test, interface.base.generate_error_packet);

	cmd_interface_spdm_deinit (&interface);
}

static void cmd_interface_spdm_test_init_invalid_arg (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_interface_spdm_init (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void cmd_interface_spdm_test_deinit_invalid_arg (CuTest *test)
{
	TEST_START;

	cmd_interface_spdm_deinit (NULL);
}

static void cmd_interface_spdm_test_process_request (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_request (&cmd.handler.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_version_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) &data[16];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_version_response);
	response.length = 16 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_version_response,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 16 + sizeof (struct spdm_get_version_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_version_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_version_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_version_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_version_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_version_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_version_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_version_response) - 1;
	response.length = 8 + response.payload_length;
	response.max_response = 512;
	response.source_eid = 0xab;
	response.source_addr = 0xcd;
	response.target_eid = 0xbc;
	response.channel_id = 5;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_version_response) - 1, response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_version_response) - 1,
		response.payload_length);
	CuAssertIntEquals (test, 512, response.max_response);
	CuAssertIntEquals (test, 0xab, response.source_eid);
	CuAssertIntEquals (test, 0xcd, response.source_addr);
	CuAssertIntEquals (test, 0xbc, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 5, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_capabilities_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->base_capabilities.header.spdm_minor_version = 2;
	rsp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_capabilities);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_capabilities_response,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_capabilities), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_capabilities_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) &data[16];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->base_capabilities.header.spdm_minor_version = 2;
	rsp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_capabilities);
	response.length = 16 + response.payload_length;
	response.max_response = 512;
	response.source_eid = 0xab;
	response.source_addr = 0xcd;
	response.target_eid = 0xbc;
	response.channel_id = 1;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 16 + sizeof (struct spdm_get_capabilities), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities), response.payload_length);
	CuAssertIntEquals (test, 512, response.max_response);
	CuAssertIntEquals (test, 0xab, response.source_eid);
	CuAssertIntEquals (test, 0xcd, response.source_addr);
	CuAssertIntEquals (test, 0xbc, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 1, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_capabilities_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_capabilities) - 1;
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_capabilities) - 1, response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities) - 1, response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_negotiate_algorithms_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	rsp->length = sizeof (struct spdm_negotiate_algorithms_response);

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_negotiate_algorithms_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_spdm_negotiate_algorithms_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_negotiate_algorithms_response),
		response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response),
		response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_negotiate_algorithms_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	rsp->length = sizeof (struct spdm_negotiate_algorithms_response);

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_negotiate_algorithms_response);
	response.length = 8 + response.payload_length;
	response.max_response = 512;
	response.source_eid = 0x2a;
	response.source_addr = 0x3c;
	response.target_eid = 0x4b;
	response.channel_id = 7;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_negotiate_algorithms_response),
		response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response),
		response.payload_length);
	CuAssertIntEquals (test, 512, response.max_response);
	CuAssertIntEquals (test, 0x2a, response.source_eid);
	CuAssertIntEquals (test, 0x3c, response.source_addr);
	CuAssertIntEquals (test, 0x4b, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 7, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_negotiate_algorithms_response_fail (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	rsp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_negotiate_algorithms_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_negotiate_algorithms_response),
		response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response),
		response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_digests_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_digests_response *rsp =	(struct spdm_get_digests_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_digests_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_digests_response,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_digests_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_digests_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_digests_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_digests_response *rsp =	(struct spdm_get_digests_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_digests_response);
	response.length = 8 + response.payload_length;
	response.max_response = 768;
	response.source_eid = 0x5a;
	response.source_addr = 0x5c;
	response.target_eid = 0x5b;
	response.channel_id = 5;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_digests_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_digests_response), response.payload_length);
	CuAssertIntEquals (test, 768, response.max_response);
	CuAssertIntEquals (test, 0x5a, response.source_eid);
	CuAssertIntEquals (test, 0x5c, response.source_addr);
	CuAssertIntEquals (test, 0x5b, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 5, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_digests_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_digests_response *rsp =	(struct spdm_get_digests_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_digests_response) - 1;
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_digests_response) - 1, response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_digests_response) - 1,
		response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_certificate_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_certificate_response *rsp =	(struct spdm_get_certificate_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_CERTIFICATE;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_certificate_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_certificate_response,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_certificate_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_certificate_response),
		response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_certificate_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_certificate_response *rsp =	(struct spdm_get_certificate_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_CERTIFICATE;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_certificate_response);
	response.length = 8 + response.payload_length;
	response.max_response = 512;
	response.source_eid = 0xa2;
	response.source_addr = 0xc2;
	response.target_eid = 0xb2;
	response.channel_id = 2;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_certificate_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_certificate_response),
		response.payload_length);
	CuAssertIntEquals (test, 512, response.max_response);
	CuAssertIntEquals (test, 0xa2, response.source_eid);
	CuAssertIntEquals (test, 0xc2, response.source_addr);
	CuAssertIntEquals (test, 0xb2, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 2, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_certificate_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_certificate_response *rsp =	(struct spdm_get_certificate_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_CERTIFICATE;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_get_certificate_response) - 1;
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_get_certificate_response) - 1,
		response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_get_certificate_response) - 1,
		response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_challenge_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	response.payload = (uint8_t*) rsp;
	response.payload_length =
		spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_challenge_response,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test,
		8 + spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH),
		response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test,
		spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH),
		response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_challenge_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	response.payload = (uint8_t*) rsp;
	response.payload_length =
		spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH);
	response.length = 8 + response.payload_length;
	response.max_response = 512;
	response.source_eid = 0xa3;
	response.source_addr = 0x3c;
	response.target_eid = 0xb3;
	response.channel_id = 6;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test,
		8 + spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH),
		response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test,
		spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH),
		response.payload_length);
	CuAssertIntEquals (test, 512, response.max_response);
	CuAssertIntEquals (test, 0xa3, response.source_eid);
	CuAssertIntEquals (test, 0x3c, response.source_addr);
	CuAssertIntEquals (test, 0xb3, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 6, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_challenge_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_challenge_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_challenge_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_measurements_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	response.payload = (uint8_t*) rsp;
	response.payload_length = spdm_get_measurements_resp_length (rsp);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_measurements_response,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + spdm_get_measurements_resp_length (rsp), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, spdm_get_measurements_resp_length (rsp), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_measurements_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	response.payload = (uint8_t*) rsp;
	response.payload_length = spdm_get_measurements_resp_length (rsp);
	response.length = 8 + response.payload_length;
	response.max_response = 256;
	response.source_eid = 0x1a;
	response.source_addr = 0x1c;
	response.target_eid = 0xb1;
	response.channel_id = 4;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + spdm_get_measurements_resp_length (rsp), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, spdm_get_measurements_resp_length (rsp), response.payload_length);
	CuAssertIntEquals (test, 256, response.max_response);
	CuAssertIntEquals (test, 0x1a, response.source_eid);
	CuAssertIntEquals (test, 0x1c, response.source_addr);
	CuAssertIntEquals (test, 0xb1, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 4, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_measurements_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	response.payload = (uint8_t*) rsp;
	response.payload_length = spdm_get_measurements_resp_length (rsp) - 1;
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + spdm_get_measurements_resp_length (rsp) - 1, response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, spdm_get_measurements_resp_length (rsp) - 1, response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_error_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_error_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_error_response);
	response.length = 8 + response.payload_length;
	response.max_response = 512;
	response.source_eid = 0xa8;
	response.source_addr = 0x8c;
	response.target_eid = 0xb8;
	response.channel_id = 8;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_error_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), response.payload_length);
	CuAssertIntEquals (test, 512, response.max_response);
	CuAssertIntEquals (test, 0xa8, response.source_eid);
	CuAssertIntEquals (test, 0x8c, response.source_addr);
	CuAssertIntEquals (test, 0xb8, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 8, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response_response_not_ready (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	rsp->error_code = SPDM_ERROR_RESPONSE_NOT_READY;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_error_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_response_not_ready,
		&cmd.observer, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &response,
		sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_error_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response_response_not_ready_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	rsp->error_code = SPDM_ERROR_RESPONSE_NOT_READY;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_error_response);
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_error_response), response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response_incorrect_len (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) &data[8];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	response.payload = (uint8_t*) rsp;
	response.payload_length = sizeof (struct spdm_error_response) - 1;
	response.length = 8 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);

	response.payload_length = sizeof (struct spdm_error_response) + 1;
	response.length = 8 + response.payload_length;

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);

	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_error_response) + 1, response.length);
	CuAssertPtrEquals (test, rsp, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response) + 1, response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_invalid_arg (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (NULL, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_payload_too_short (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) &data[4];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.payload = (uint8_t*) header;
	response.payload_length = sizeof (struct spdm_protocol_header) - 1;
	response.length = 4 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 4 + sizeof (struct spdm_protocol_header) - 1, response.length);
	CuAssertPtrEquals (test, header, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_protocol_header) - 1, response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_unknown_command (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) &data[12];
	int status;

	TEST_START;

	memset (&response, 0, sizeof (response));
	memset (data, 0, sizeof (data));
	response.data = data;

	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = 0xFF;

	response.payload = (uint8_t*) header;
	response.payload_length = sizeof (struct spdm_protocol_header);
	response.length = 12 + response.payload_length;
	response.max_response = 1024;
	response.source_eid = 0xaa;
	response.source_addr = 0xcc;
	response.target_eid = 0xbb;
	response.channel_id = 3;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNKNOWN_COMMAND, status);
	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 12 + sizeof (struct spdm_protocol_header), response.length);
	CuAssertPtrEquals (test, header, response.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_protocol_header), response.payload_length);
	CuAssertIntEquals (test, 1024, response.max_response);
	CuAssertIntEquals (test, 0xaa, response.source_eid);
	CuAssertIntEquals (test, 0xcc, response.source_addr);
	CuAssertIntEquals (test, 0xbb, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 3, response.channel_id);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_generate_error_packet (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.generate_error_packet (&cmd.handler.base, &request, 0, 0, 0);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNSUPPORTED_OPERATION, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_add_spdm_protocol_observer_invalid_arg (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd_interface_spdm_add_spdm_protocol_observer (NULL, &cmd.observer.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = cmd_interface_spdm_add_spdm_protocol_observer (&cmd.handler, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_remove_spdm_protocol_observer_invalid_arg (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	int status;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd_interface_spdm_remove_spdm_protocol_observer (NULL, &cmd.observer.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = cmd_interface_spdm_remove_spdm_protocol_observer (&cmd.handler, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_spdm);

TEST (cmd_interface_spdm_test_init);
TEST (cmd_interface_spdm_test_init_invalid_arg);
TEST (cmd_interface_spdm_test_deinit_invalid_arg);
TEST (cmd_interface_spdm_test_process_request);
TEST (cmd_interface_spdm_test_process_response_get_version_response);
TEST (cmd_interface_spdm_test_process_response_get_version_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_version_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_capabilities_response);
TEST (cmd_interface_spdm_test_process_response_get_capabilities_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_capabilities_response_fail);
TEST (cmd_interface_spdm_test_process_response_negotiate_algorithms_response);
TEST (cmd_interface_spdm_test_process_response_negotiate_algorithms_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_negotiate_algorithms_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_digests_response);
TEST (cmd_interface_spdm_test_process_response_get_digests_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_digests_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_certificate_response);
TEST (cmd_interface_spdm_test_process_response_get_certificate_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_certificate_response_fail);
TEST (cmd_interface_spdm_test_process_response_challenge_response);
TEST (cmd_interface_spdm_test_process_response_challenge_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_challenge_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_measurements_response);
TEST (cmd_interface_spdm_test_process_response_get_measurements_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_measurements_response_fail);
TEST (cmd_interface_spdm_test_process_response_error_response);
TEST (cmd_interface_spdm_test_process_response_error_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_error_response_response_not_ready);
TEST (cmd_interface_spdm_test_process_response_error_response_response_not_ready_no_observer);
TEST (cmd_interface_spdm_test_process_response_error_response_incorrect_len);
TEST (cmd_interface_spdm_test_process_response_invalid_arg);
TEST (cmd_interface_spdm_test_process_response_payload_too_short);
TEST (cmd_interface_spdm_test_process_response_unknown_command);
TEST (cmd_interface_spdm_test_generate_error_packet);
TEST (cmd_interface_spdm_test_add_spdm_protocol_observer_invalid_arg);
TEST (cmd_interface_spdm_test_remove_spdm_protocol_observer_invalid_arg);

TEST_SUITE_END;
// *INDENT-ON*
