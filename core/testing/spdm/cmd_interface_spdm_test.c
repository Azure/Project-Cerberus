// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "spdm/spdm_protocol.h"
#include "spdm/spdm_protocol_observer.h"
#include "spdm/spdm_commands.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/spdm/spdm_protocol_observer_mock.h"
#include "spdm/cmd_interface_spdm.h"


TEST_SUITE_LABEL ("cmd_interface_spdm");


/**
 * Dependencies for testing the SPDM command interface.
 */
struct cmd_interface_spdm_testing {
	struct cmd_interface_spdm handler;							/**< Command handler instance. */
	struct spdm_protocol_observer_mock observer;				/**< SPDM protocol observer. */
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

static void cmd_interface_spdm_test_process_response_payload_too_short (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.length = SPDM_PROTOCOL_MIN_MSG_LEN - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_unsupported_msg (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	header->msg_type = 0;
	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.length = SPDM_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNSUPPORTED_MSG, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_not_interoperable (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	header->spdm_major_version = SPDM_MAJOR_VERSION + 1;
	header->req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.length = SPDM_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_NOT_INTEROPERABLE, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_version_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.length = sizeof (struct spdm_get_version_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_version_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_version_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.length = sizeof (struct spdm_get_version_response) - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_version_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_version_response *rsp = (struct spdm_get_version_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	response.length = sizeof (struct spdm_get_version_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_capabilities_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->base_capabilities.header.spdm_minor_version = 2;
	rsp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	response.length = sizeof (struct spdm_get_capabilities);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock, cmd.observer.base.on_spdm_get_capabilities_response,
		&cmd.observer, 0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response,
		sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_capabilities_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	response.length = sizeof (struct spdm_get_capabilities) - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_capabilities_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_capabilities *rsp = (struct spdm_get_capabilities*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->base_capabilities.header.spdm_minor_version = 2;
	rsp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	response.length = sizeof (struct spdm_get_capabilities);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_negotiate_algorithms_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	rsp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1;

	response.length = sizeof (struct spdm_negotiate_algorithms_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_spdm_negotiate_algorithms_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_negotiate_algorithms_response_fail (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	rsp->length = sizeof (struct spdm_negotiate_algorithms_response) - 2;

	response.length = sizeof (struct spdm_negotiate_algorithms_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_negotiate_algorithms_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	rsp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1;

	response.length = sizeof (struct spdm_negotiate_algorithms_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_digests_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_digests_response *rsp =	(struct spdm_get_digests_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	response.length = sizeof (struct spdm_get_digests_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_spdm_get_digests_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_digests_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_digests_response *rsp =	(struct spdm_get_digests_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	response.length = sizeof (struct spdm_get_digests_response) - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_digests_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_digests_response *rsp =	(struct spdm_get_digests_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	response.length = sizeof (struct spdm_get_digests_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_certificate_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_certificate_response *rsp =	(struct spdm_get_certificate_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_CERTIFICATE;

	response.length = sizeof (struct spdm_get_certificate_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_spdm_get_certificate_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_certificate_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_certificate_response *rsp =	(struct spdm_get_certificate_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_CERTIFICATE;

	response.length = sizeof (struct spdm_get_certificate_response) - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_certificate_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_certificate_response *rsp =	(struct spdm_get_certificate_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_CERTIFICATE;

	response.length = sizeof (struct spdm_get_certificate_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_challenge_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	response.length = spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH) +
		1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_spdm_challenge_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_challenge_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	response.length = sizeof (struct spdm_challenge_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_challenge_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	response.length = spdm_get_challenge_resp_length (rsp, SHA384_HASH_LENGTH, SHA384_HASH_LENGTH) +
		1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_measurements_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	response.length = spdm_get_measurements_resp_length (rsp) + 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = mock_expect (&cmd.observer.mock,
		cmd.observer.base.on_spdm_get_measurements_response, &cmd.observer, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &response, sizeof (response)));
	CuAssertIntEquals (test, 0, status);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_measurements_response_fail (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	response.length = spdm_get_measurements_resp_length (rsp) - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_get_measurements_response_no_observer (
	CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	response.length = spdm_get_measurements_resp_length (rsp) + 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, 0, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	response.length = sizeof (struct spdm_error_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response_incorrect_len (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	response.length = sizeof (struct spdm_error_response) - 1;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);

	response.length = sizeof (struct spdm_error_response) + 1;

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);

	complete_cmd_interface_spdm_mock_test (test, &cmd);
}

static void cmd_interface_spdm_test_process_response_error_response_no_observer (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_error_response *rsp = (struct spdm_error_response*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rsp->header.req_rsp_code = SPDM_RESPONSE_ERROR;

	response.length = sizeof (struct spdm_error_response);
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, false);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MESSAGE, status);

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

static void cmd_interface_spdm_test_process_response_unknown_command (CuTest *test)
{
	struct cmd_interface_spdm_testing cmd;
	struct cmd_interface_msg response;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct spdm_protocol_header *header = (struct spdm_protocol_header*) data;
	int status;

	memset (&response, 0, sizeof (struct cmd_interface_msg));
	memset (data, 0, sizeof (data));
	response.data = data;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	header->spdm_major_version = SPDM_MAJOR_VERSION;
	header->req_rsp_code = 0xFF;

	response.length = SPDM_PROTOCOL_MIN_MSG_LEN;
	response.source_eid = 0xaa;
	response.target_eid = 0xbb;

	TEST_START;

	setup_cmd_interface_spdm_mock_test (test, &cmd, true);

	status = cmd.handler.base.process_response (&cmd.handler.base, &response);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_UNKNOWN_COMMAND, status);

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


TEST_SUITE_START (cmd_interface_spdm);

TEST (cmd_interface_spdm_test_init);
TEST (cmd_interface_spdm_test_init_invalid_arg);
TEST (cmd_interface_spdm_test_deinit_invalid_arg);
TEST (cmd_interface_spdm_test_process_request);
TEST (cmd_interface_spdm_test_process_response_payload_too_short);
TEST (cmd_interface_spdm_test_process_response_unsupported_msg);
TEST (cmd_interface_spdm_test_process_response_not_interoperable);
TEST (cmd_interface_spdm_test_process_response_get_version_response);
TEST (cmd_interface_spdm_test_process_response_get_version_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_version_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_capabilities_response);
TEST (cmd_interface_spdm_test_process_response_get_capabilities_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_capabilities_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_negotiate_algorithms_response);
TEST (cmd_interface_spdm_test_process_response_negotiate_algorithms_response_fail);
TEST (cmd_interface_spdm_test_process_response_negotiate_algorithms_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_digests_response);
TEST (cmd_interface_spdm_test_process_response_get_digests_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_digests_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_certificate_response);
TEST (cmd_interface_spdm_test_process_response_get_certificate_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_certificate_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_challenge_response);
TEST (cmd_interface_spdm_test_process_response_challenge_response_fail);
TEST (cmd_interface_spdm_test_process_response_challenge_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_get_measurements_response);
TEST (cmd_interface_spdm_test_process_response_get_measurements_response_fail);
TEST (cmd_interface_spdm_test_process_response_get_measurements_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_error_response);
TEST (cmd_interface_spdm_test_process_response_error_response_incorrect_len);
TEST (cmd_interface_spdm_test_process_response_error_response_no_observer);
TEST (cmd_interface_spdm_test_process_response_invalid_arg);
TEST (cmd_interface_spdm_test_process_response_unknown_command);
TEST (cmd_interface_spdm_test_generate_error_packet);
TEST (cmd_interface_spdm_test_add_spdm_protocol_observer_invalid_arg);
TEST (cmd_interface_spdm_test_remove_spdm_protocol_observer_invalid_arg);

TEST_SUITE_END;
