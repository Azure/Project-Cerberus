// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/msg_transport_mctp_message.h"
#include "mctp/msg_transport_mctp_message_static.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/msg_transport_mock.h"


TEST_SUITE_LABEL ("msg_transport_mctp_message");


/**
 * Dependencies for testing the message transport for MCTP messages.
 */
struct msg_transport_mctp_message_testing {
	struct msg_transport_mock mctp_transport;		/**< Mock for the MCTP transport layer. */
	struct cmd_interface_protocol_mctp protocol;	/**< MCTP protocol handler. */
	struct msg_transport_mctp_message test;			/**< Message transport being tested. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to initialize.
 */
static void msg_transport_mctp_message_testing_init_dependencies (CuTest *test,
	struct msg_transport_mctp_message_testing *mctp)
{
	int status;

	status = msg_transport_mock_init (&mctp->mctp_transport);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_protocol_mctp_init (&mctp->protocol);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to release.
 */
static void msg_transport_mctp_message_testing_release_dependencies (CuTest *test,
	struct msg_transport_mctp_message_testing *mctp)
{
	int status;

	status = msg_transport_mock_validate_and_release (&mctp->mctp_transport);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_protocol_mctp_release (&mctp->protocol);
}

/**
 * Initialize a MCTP message transport for testing.
 *
 * @param test The test framework.
 * @param mctp Testing components to initialize.
 * @param message_type The message type for the transport.
 */
static void msg_transport_mctp_message_testing_init (CuTest *test,
	struct msg_transport_mctp_message_testing *mctp, uint8_t message_type)
{
	int status;

	msg_transport_mctp_message_testing_init_dependencies (test, mctp);

	status = msg_transport_mctp_message_init (&mctp->test, &mctp->mctp_transport.base,
		&mctp->protocol, message_type);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release MCTP message transport test components and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing components to release.
 */
static void msg_transport_mctp_message_testing_release (CuTest *test,
	struct msg_transport_mctp_message_testing *mctp)
{
	msg_transport_mctp_message_release (&mctp->test);
	msg_transport_mctp_message_testing_release_dependencies (test, mctp);
}


/*******************
 * Test cases
 *******************/

static void msg_transport_mctp_message_test_init (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	status = msg_transport_mctp_message_init (&mctp.test, &mctp.mctp_transport.base, &mctp.protocol,
		MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, mctp.test.base.base.get_max_message_overhead);
	CuAssertPtrNotNull (test, mctp.test.base.base.get_max_message_payload_length);
	CuAssertPtrNotNull (test, mctp.test.base.base.get_max_encapsulated_message_length);
	CuAssertPtrNotNull (test, mctp.test.base.base.get_buffer_overhead);
	CuAssertPtrNotNull (test, mctp.test.base.base.send_request_message);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_init_null (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	status = msg_transport_mctp_message_init (NULL, &mctp.mctp_transport.base, &mctp.protocol,
		MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_mctp_message_init (&mctp.test, NULL, &mctp.protocol,
		MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_mctp_message_init (&mctp.test, &mctp.mctp_transport.base, NULL,
		MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_mctp_message_testing_release_dependencies (test, &mctp);
}

static void msg_transport_mctp_message_test_static_init (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp = {
		.test = msg_transport_mctp_message_static_init (&mctp.mctp_transport.base, &mctp.protocol,
			MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG)
	};

	TEST_START;

	CuAssertPtrNotNull (test, mctp.test.base.base.get_max_message_overhead);
	CuAssertPtrNotNull (test, mctp.test.base.base.get_max_message_payload_length);
	CuAssertPtrNotNull (test, mctp.test.base.base.get_max_encapsulated_message_length);
	CuAssertPtrNotNull (test, mctp.test.base.base.get_buffer_overhead);
	CuAssertPtrNotNull (test, mctp.test.base.base.send_request_message);

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_release_null (CuTest *test)
{
	TEST_START;

	msg_transport_mctp_message_release (NULL);
}

static void msg_transport_mctp_message_test_get_max_message_overhead (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	uint8_t dest_id = 8;
	int overhead = 24;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	status = mock_expect (&mctp.mctp_transport.mock,
		mctp.mctp_transport.base.get_max_message_overhead, &mctp.mctp_transport, overhead,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_max_message_overhead (&mctp.test.base.base, dest_id);
	CuAssertIntEquals (test, overhead + 1, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_max_message_overhead_static_init (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp = {
		.test = msg_transport_mctp_message_static_init (&mctp.mctp_transport.base, &mctp.protocol,
			MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG)
	};
	uint8_t dest_id = 78;
	int overhead = 34;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	status = mock_expect (&mctp.mctp_transport.mock,
		mctp.mctp_transport.base.get_max_message_overhead, &mctp.mctp_transport, overhead,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_max_message_overhead (&mctp.test.base.base, dest_id);
	CuAssertIntEquals (test, overhead + 1, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_max_message_payload_length (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	uint8_t dest_id = 3;
	int payload = 345;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	status = mock_expect (&mctp.mctp_transport.mock,
		mctp.mctp_transport.base.get_max_message_payload_length, &mctp.mctp_transport, payload,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_max_message_payload_length (&mctp.test.base.base, dest_id);
	CuAssertIntEquals (test, payload - 1, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_max_message_payload_length_static_init (
	CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp = {
		.test = msg_transport_mctp_message_static_init (&mctp.mctp_transport.base, &mctp.protocol,
			MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG)
	};
	uint8_t dest_id = 65;
	int payload = 1024;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	status = mock_expect (&mctp.mctp_transport.mock,
		mctp.mctp_transport.base.get_max_message_payload_length, &mctp.mctp_transport, payload,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_max_message_payload_length (&mctp.test.base.base, dest_id);
	CuAssertIntEquals (test, payload - 1, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_max_encapsulated_message_length (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	uint8_t dest_id = 12;
	int total = 543;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	status = mock_expect (&mctp.mctp_transport.mock,
		mctp.mctp_transport.base.get_max_encapsulated_message_length, &mctp.mctp_transport, total,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_max_encapsulated_message_length (&mctp.test.base.base,
		dest_id);
	CuAssertIntEquals (test, total, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_max_encapsulated_message_length_static_init (
	CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp = {
		.test = msg_transport_mctp_message_static_init (&mctp.mctp_transport.base, &mctp.protocol,
			MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG)
	};
	uint8_t dest_id = 4;
	int total = 728;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	status = mock_expect (&mctp.mctp_transport.mock,
		mctp.mctp_transport.base.get_max_encapsulated_message_length, &mctp.mctp_transport, total,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_max_encapsulated_message_length (&mctp.test.base.base,
		dest_id);
	CuAssertIntEquals (test, total, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_buffer_overhead (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	uint8_t dest_id = 8;
	size_t length = 128;
	int overhead = 24;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.get_buffer_overhead,
		&mctp.mctp_transport, overhead,	MOCK_ARG (dest_id), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_buffer_overhead (&mctp.test.base.base, dest_id, length);
	CuAssertIntEquals (test, overhead + 1, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_get_buffer_overhead_static_init (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp = {
		.test = msg_transport_mctp_message_static_init (&mctp.mctp_transport.base, &mctp.protocol,
			MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG)
	};
	uint8_t dest_id = 56;
	size_t length = 512;
	int overhead = 33;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.get_buffer_overhead,
		&mctp.mctp_transport, overhead,	MOCK_ARG (dest_id), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.base.get_buffer_overhead (&mctp.test.base.base, dest_id, length);
	CuAssertIntEquals (test, overhead + 1, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	struct mctp_base_protocol_message_header *header;
	uint8_t tx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg req_expected = {0};
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg resp_expected = {0};
	struct cmd_interface_msg response = {0};
	uint8_t eid = 0x23;
	uint32_t timeout = 100;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	/* Create the expected message that is being sent. */
	header = (struct mctp_base_protocol_message_header*) tx_expected;
	header->integrity_check = 0;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	tx_expected[1] = 0x12;
	tx_expected[2] = 0x34;
	tx_expected[3] = 0x56;
	tx_expected[4] = 0x78;
	tx_expected[5] = 0x90;
	tx_expected[6] = 0xab;
	tx_expected[7] = 0xcd;
	tx_expected[8] = 0xef;

	req_expected.data = tx_expected;
	req_expected.max_response = sizeof (tx_expected);
	req_expected.payload = tx_expected;
	req_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&req_expected, 9);

	/* Create the expected response that will be generated. */
	header = (struct mctp_base_protocol_message_header*) rx_expected;
	header->integrity_check = 0;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	rx_expected[1] = 0x11;
	rx_expected[2] = 0x22;
	rx_expected[3] = 0x33;
	rx_expected[4] = 0x44;

	resp_expected.data = rx_expected;
	resp_expected.max_response = sizeof (rx_expected);
	resp_expected.payload = rx_expected;
	resp_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&resp_expected, 5);

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.send_request_message,
		&mctp.mctp_transport, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &req_expected,
		sizeof (req_expected), cmd_interface_mock_save_request,	cmd_interface_mock_free_request),
		MOCK_ARG (timeout), MOCK_ARG_PTR (&response));
	status |= mock_expect_output_deep_copy (&mctp.mctp_transport.mock, 2, &resp_expected,
		sizeof (resp_expected), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	request.data = tx_message;
	request.max_response = sizeof (tx_message);
	request.payload = &tx_message[1];
	request.target_eid = eid;

	memcpy (request.payload, &tx_expected[1], 8);
	cmd_interface_msg_set_message_payload_length (&request, 8);

	/* Get the response container ready. */
	msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		&response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, resp_expected.length, response.length);
	CuAssertIntEquals (test, 1, cmd_interface_msg_get_protocol_length (&response));
	CuAssertIntEquals (test, response.length - 1, response.payload_length);
	CuAssertIntEquals (test, eid, response.target_eid);

	status = testing_validate_array (&rx_expected[1], response.payload, response.payload_length);
	CuAssertIntEquals (test, 0, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message_static_init (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp = {
		.test = msg_transport_mctp_message_static_init (&mctp.mctp_transport.base, &mctp.protocol,
			0x38)
	};
	struct mctp_base_protocol_message_header *header;
	uint8_t tx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg req_expected = {0};
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg resp_expected = {0};
	struct cmd_interface_msg response = {0};
	uint8_t eid = 0x92;
	uint32_t timeout = 250;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init_dependencies (test, &mctp);

	/* Create the expected message that is being sent. */
	header = (struct mctp_base_protocol_message_header*) tx_expected;
	header->integrity_check = 0;
	header->msg_type = 0x38;

	tx_expected[1] = 0x12;
	tx_expected[2] = 0x34;
	tx_expected[3] = 0x56;
	tx_expected[4] = 0x78;
	tx_expected[5] = 0x90;
	tx_expected[6] = 0xab;

	req_expected.data = tx_expected;
	req_expected.max_response = sizeof (tx_expected);
	req_expected.payload = tx_expected;
	req_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&req_expected, 7);

	/* Create the expected response that will be generated. */
	header = (struct mctp_base_protocol_message_header*) rx_expected;
	header->integrity_check = 0;
	header->msg_type = 0x38;

	rx_expected[1] = 0x11;
	rx_expected[2] = 0x22;
	rx_expected[3] = 0x33;
	rx_expected[4] = 0x44;
	rx_expected[5] = 0x55;

	resp_expected.data = rx_expected;
	resp_expected.max_response = sizeof (rx_expected);
	resp_expected.payload = rx_expected;
	resp_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&resp_expected, 6);

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.send_request_message,
		&mctp.mctp_transport, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &req_expected,
		sizeof (req_expected), cmd_interface_mock_save_request,	cmd_interface_mock_free_request),
		MOCK_ARG (timeout), MOCK_ARG_PTR (&response));
	status |= mock_expect_output_deep_copy (&mctp.mctp_transport.mock, 2, &resp_expected,
		sizeof (resp_expected), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	request.data = tx_message;
	request.max_response = sizeof (tx_message);
	request.payload = &tx_message[1];
	request.target_eid = eid;

	memcpy (request.payload, &tx_expected[1], 6);
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Get the response container ready. */
	msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		&response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, resp_expected.length, response.length);
	CuAssertIntEquals (test, 1, cmd_interface_msg_get_protocol_length (&response));
	CuAssertIntEquals (test, response.length - 1, response.payload_length);
	CuAssertIntEquals (test, eid, response.target_eid);

	status = testing_validate_array (&rx_expected[1], response.payload, response.payload_length);
	CuAssertIntEquals (test, 0, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message_null (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg response = {0};
	uint32_t timeout = 100;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	status = mctp.test.base.base.send_request_message (NULL, &request, timeout, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, NULL, timeout,
		&response);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message_wrong_response_type (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	struct mctp_base_protocol_message_header *header;
	uint8_t tx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg req_expected = {0};
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg resp_expected = {0};
	struct cmd_interface_msg response = {0};
	uint8_t eid = 0x23;
	uint32_t timeout = 100;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, 0x45);

	/* Create the expected message that is being sent. */
	header = (struct mctp_base_protocol_message_header*) tx_expected;
	header->integrity_check = 0;
	header->msg_type = 0x45;

	tx_expected[1] = 0x12;
	tx_expected[2] = 0x34;
	tx_expected[3] = 0x56;
	tx_expected[4] = 0x78;
	tx_expected[5] = 0x90;
	tx_expected[6] = 0xab;
	tx_expected[7] = 0xcd;
	tx_expected[8] = 0xef;

	req_expected.data = tx_expected;
	req_expected.max_response = sizeof (tx_expected);
	req_expected.payload = tx_expected;
	req_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&req_expected, 9);

	/* Create the expected response that will be generated. */
	header = (struct mctp_base_protocol_message_header*) rx_expected;
	header->integrity_check = 0;
	header->msg_type = 0x67;

	rx_expected[1] = 0x11;
	rx_expected[2] = 0x22;
	rx_expected[3] = 0x33;
	rx_expected[4] = 0x44;

	resp_expected.data = rx_expected;
	resp_expected.max_response = sizeof (rx_expected);
	resp_expected.payload = rx_expected;
	resp_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&resp_expected, 5);

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.send_request_message,
		&mctp.mctp_transport, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &req_expected,
		sizeof (req_expected), cmd_interface_mock_save_request,	cmd_interface_mock_free_request),
		MOCK_ARG (timeout), MOCK_ARG_PTR (&response));
	status |= mock_expect_output_deep_copy (&mctp.mctp_transport.mock, 2, &resp_expected,
		sizeof (resp_expected), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	request.data = tx_message;
	request.max_response = sizeof (tx_message);
	request.payload = &tx_message[1];
	request.target_eid = eid;

	memcpy (request.payload, &tx_expected[1], 8);
	cmd_interface_msg_set_message_payload_length (&request, 8);

	/* Get the response container ready. */
	msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		&response);
	CuAssertIntEquals (test, MSG_TRANSPORT_UNEXPECTED_RESPONSE, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message_no_header_space (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg response = {0};
	uint8_t eid = 0x23;
	uint32_t timeout = 100;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	/* Build the request message to send. */
	request.data = tx_message;
	request.max_response = sizeof (tx_message);
	request.payload = tx_message;
	request.target_eid = eid;

	cmd_interface_msg_set_message_payload_length (&request, 8);

	/* Get the response container ready. */
	msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		&response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_NO_HEADER_SPACE, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message_send_error (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	struct mctp_base_protocol_message_header *header;
	uint8_t tx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg req_expected = {0};
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg response = {0};
	uint8_t eid = 0x23;
	uint32_t timeout = 100;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	/* Create the expected message that is being sent. */
	header = (struct mctp_base_protocol_message_header*) tx_expected;
	header->integrity_check = 0;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	tx_expected[1] = 0x12;
	tx_expected[2] = 0x34;
	tx_expected[3] = 0x56;
	tx_expected[4] = 0x78;
	tx_expected[5] = 0x90;
	tx_expected[6] = 0xab;
	tx_expected[7] = 0xcd;
	tx_expected[8] = 0xef;

	req_expected.data = tx_expected;
	req_expected.max_response = sizeof (tx_expected);
	req_expected.payload = tx_expected;
	req_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&req_expected, 9);

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.send_request_message,
		&mctp.mctp_transport, MSG_TRANSPORT_SEND_REQUEST_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &req_expected,
		sizeof (req_expected), cmd_interface_mock_save_request,	cmd_interface_mock_free_request),
		MOCK_ARG (timeout), MOCK_ARG_PTR (&response));

	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	request.data = tx_message;
	request.max_response = sizeof (tx_message);
	request.payload = &tx_message[1];
	request.target_eid = eid;

	memcpy (request.payload, &tx_expected[1], 8);
	cmd_interface_msg_set_message_payload_length (&request, 8);

	/* Get the response container ready. */
	msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		&response);
	CuAssertIntEquals (test, MSG_TRANSPORT_SEND_REQUEST_FAILED, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}

static void msg_transport_mctp_message_test_send_request_message_parse_error (CuTest *test)
{
	struct msg_transport_mctp_message_testing mctp;
	struct mctp_base_protocol_message_header *header;
	uint8_t tx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_expected[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg req_expected = {0};
	struct cmd_interface_msg request = {0};
	struct cmd_interface_msg resp_expected = {0};
	struct cmd_interface_msg response = {0};
	uint8_t eid = 0x23;
	uint32_t timeout = 100;
	int status;

	TEST_START;

	msg_transport_mctp_message_testing_init (test, &mctp, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM);

	/* Create the expected message that is being sent. */
	header = (struct mctp_base_protocol_message_header*) tx_expected;
	header->integrity_check = 0;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	tx_expected[1] = 0x12;
	tx_expected[2] = 0x34;
	tx_expected[3] = 0x56;
	tx_expected[4] = 0x78;
	tx_expected[5] = 0x90;
	tx_expected[6] = 0xab;
	tx_expected[7] = 0xcd;
	tx_expected[8] = 0xef;

	req_expected.data = tx_expected;
	req_expected.max_response = sizeof (tx_expected);
	req_expected.payload = tx_expected;
	req_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&req_expected, 9);

	/* Create the expected response that will be generated. */
	header = (struct mctp_base_protocol_message_header*) rx_expected;
	header->integrity_check = 0;
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	rx_expected[1] = 0x11;
	rx_expected[2] = 0x22;
	rx_expected[3] = 0x33;
	rx_expected[4] = 0x44;

	resp_expected.data = rx_expected;
	resp_expected.max_response = sizeof (rx_expected);
	resp_expected.payload = rx_expected;
	resp_expected.target_eid = eid;
	cmd_interface_msg_set_message_payload_length (&resp_expected, 0);	// Short message

	status = mock_expect (&mctp.mctp_transport.mock, mctp.mctp_transport.base.send_request_message,
		&mctp.mctp_transport, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &req_expected,
		sizeof (req_expected), cmd_interface_mock_save_request,	cmd_interface_mock_free_request),
		MOCK_ARG (timeout), MOCK_ARG_PTR (&response));
	status |= mock_expect_output_deep_copy (&mctp.mctp_transport.mock, 2, &resp_expected,
		sizeof (resp_expected), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	request.data = tx_message;
	request.max_response = sizeof (tx_message);
	request.payload = &tx_message[1];
	request.target_eid = eid;

	memcpy (request.payload, &tx_expected[1], 8);
	cmd_interface_msg_set_message_payload_length (&request, 8);

	/* Get the response container ready. */
	msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);

	status = mctp.test.base.base.send_request_message (&mctp.test.base.base, &request, timeout,
		&response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);

	msg_transport_mctp_message_testing_release (test, &mctp);
}


// *INDENT-OFF*
TEST_SUITE_START (msg_transport_mctp_message);

TEST (msg_transport_mctp_message_test_init);
TEST (msg_transport_mctp_message_test_init_null);
TEST (msg_transport_mctp_message_test_static_init);
TEST (msg_transport_mctp_message_test_release_null);
TEST (msg_transport_mctp_message_test_get_max_message_overhead);
TEST (msg_transport_mctp_message_test_get_max_message_overhead_static_init);
TEST (msg_transport_mctp_message_test_get_max_message_payload_length);
TEST (msg_transport_mctp_message_test_get_max_message_payload_length_static_init);
TEST (msg_transport_mctp_message_test_get_max_encapsulated_message_length);
TEST (msg_transport_mctp_message_test_get_max_encapsulated_message_length_static_init);
TEST (msg_transport_mctp_message_test_get_buffer_overhead);
TEST (msg_transport_mctp_message_test_get_buffer_overhead_static_init);
TEST (msg_transport_mctp_message_test_send_request_message);
TEST (msg_transport_mctp_message_test_send_request_message_static_init);
TEST (msg_transport_mctp_message_test_send_request_message_null);
TEST (msg_transport_mctp_message_test_send_request_message_wrong_response_type);
TEST (msg_transport_mctp_message_test_send_request_message_no_header_space);
TEST (msg_transport_mctp_message_test_send_request_message_send_error);
TEST (msg_transport_mctp_message_test_send_request_message_parse_error);

TEST_SUITE_END;
// *INDENT-ON*
