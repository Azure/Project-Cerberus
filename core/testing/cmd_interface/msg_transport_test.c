// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/msg_transport.h"
#include "testing/mock/cmd_interface/msg_transport_mock.h"


TEST_SUITE_LABEL ("msg_transport");


/*******************
 * Test cases
 *******************/

static void msg_transport_test_create_empty_request (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	size_t overhead = 16;
	size_t max_payload = sizeof (data) * 2;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x33), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, max_payload, MOCK_ARG (0x33));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, sizeof (data), request.max_response);
	CuAssertPtrEquals (test, &data[overhead], request.payload);
	CuAssertIntEquals (test, sizeof (data) - overhead, request.payload_length);
	CuAssertIntEquals (test, 0, request.source_eid);
	CuAssertIntEquals (test, 0, request.source_addr);
	CuAssertIntEquals (test, 0x33, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_no_transport_overhead (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[96];
	size_t overhead = 0;
	size_t max_payload = sizeof (data) * 2;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = (uint8_t*) &transport,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x22), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, max_payload, MOCK_ARG (0x22));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x22,
		&request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, sizeof (data), request.max_response);
	CuAssertPtrEquals (test, data, request.payload);
	CuAssertIntEquals (test, sizeof (data), request.payload_length);
	CuAssertIntEquals (test, 0, request.source_eid);
	CuAssertIntEquals (test, 0, request.source_addr);
	CuAssertIntEquals (test, 0x22, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_overhead_same_as_buffer (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[32];
	size_t overhead = sizeof (data);
	size_t max_payload = sizeof (data) * 2;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x11), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, max_payload, MOCK_ARG (0x11));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x11,
		&request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, sizeof (data), request.max_response);
	CuAssertPtrEquals (test, &data[overhead], request.payload);
	CuAssertIntEquals (test, 0, request.payload_length);
	CuAssertIntEquals (test, 0, request.source_eid);
	CuAssertIntEquals (test, 0, request.source_addr);
	CuAssertIntEquals (test, 0x11, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_payload_length_limited_by_target (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	size_t overhead = 16;
	size_t max_payload = 32;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x33), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, max_payload, MOCK_ARG (0x33));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, sizeof (data), request.max_response);
	CuAssertPtrEquals (test, &data[overhead], request.payload);
	CuAssertIntEquals (test, max_payload, request.payload_length);
	CuAssertIntEquals (test, 0, request.source_eid);
	CuAssertIntEquals (test, 0, request.source_addr);
	CuAssertIntEquals (test, 0x33, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_payload_length_limited_by_buffer (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	size_t overhead = 16;
	size_t max_payload = 49;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x33), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, max_payload, MOCK_ARG (0x33));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, sizeof (data), request.max_response);
	CuAssertPtrEquals (test, &data[overhead], request.payload);
	CuAssertIntEquals (test, sizeof (data) - overhead, request.payload_length);
	CuAssertIntEquals (test, 0, request.source_eid);
	CuAssertIntEquals (test, 0, request.source_addr);
	CuAssertIntEquals (test, 0x33, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_payload_length_same_as_buffer (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[50];
	size_t overhead = 32;
	size_t max_payload = sizeof (data) - overhead;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x23), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, max_payload, MOCK_ARG (0x23));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x23,
		&request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, request.data);
	CuAssertIntEquals (test, 0, request.length);
	CuAssertIntEquals (test, sizeof (data), request.max_response);
	CuAssertPtrEquals (test, &data[overhead], request.payload);
	CuAssertIntEquals (test, sizeof (data) - overhead, request.payload_length);
	CuAssertIntEquals (test, 0, request.source_eid);
	CuAssertIntEquals (test, 0, request.source_addr);
	CuAssertIntEquals (test, 0x23, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_null (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (NULL, data, sizeof (data), 0x33, &request);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_create_empty_request (&transport.base, NULL, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_overhead_more_than_buffer (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	size_t overhead = sizeof (data) + 1;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport,
		overhead, MOCK_ARG (0x33), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, MSG_TRANSPORT_OVERHEAD_MORE_THAN_BUFFER, status);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_check_overhead_error (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport,
		MSG_TRANSPORT_OVERHEAD_FAILED, MOCK_ARG (0x33), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, MSG_TRANSPORT_OVERHEAD_FAILED, status);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_request_check_payload_error (CuTest *test)
{
	struct msg_transport_mock transport;
	uint8_t data[64];
	size_t overhead = 16;
	struct cmd_interface_msg request = {
		.data = (uint8_t*) &transport,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = data,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_mock_init (&transport);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&transport.mock, transport.base.get_buffer_overhead, &transport, overhead,
		MOCK_ARG (0x33), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&transport.mock, transport.base.get_max_message_payload_length,
		&transport, MSG_TRANSPORT_MAX_PAYLOAD_FAILED, MOCK_ARG (0x33));

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_request (&transport.base, data, sizeof (data), 0x33,
		&request);
	CuAssertIntEquals (test, MSG_TRANSPORT_MAX_PAYLOAD_FAILED, status);

	status = msg_transport_mock_validate_and_release (&transport);
	CuAssertIntEquals (test, 0, status);
}

static void msg_transport_test_create_empty_response (CuTest *test)
{
	uint8_t data[64];
	struct cmd_interface_msg response = {
		.data = (uint8_t*) &response,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = (uint8_t*) &response,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_create_empty_response (data, sizeof (data), &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 0, response.length);
	CuAssertIntEquals (test, sizeof (data), response.max_response);
	CuAssertPtrEquals (test, data, response.payload);
	CuAssertIntEquals (test, 0, response.payload_length);
	CuAssertIntEquals (test, 0, response.source_eid);
	CuAssertIntEquals (test, 0, response.source_addr);
	CuAssertIntEquals (test, 0, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
}

static void msg_transport_test_create_empty_response_null (CuTest *test)
{
	uint8_t data[64];
	struct cmd_interface_msg response = {
		.data = (uint8_t*) &response,
		.length = 128,
		.max_response = sizeof (data) - 10,
		.payload = (uint8_t*) &response,
		.payload_length = 4,
		.source_eid = 0x55,
		.source_addr = 0xaa,
		.target_eid = 0x66,
		.is_encrypted = true,
		.crypto_timeout = true,
		.channel_id = 100
	};
	int status;

	TEST_START;

	status = msg_transport_create_empty_response (NULL, sizeof (data), &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_create_empty_response (data, sizeof (data), NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);
}


// *INDENT-OFF*
TEST_SUITE_START (msg_transport);

TEST (msg_transport_test_create_empty_request);
TEST (msg_transport_test_create_empty_request_payload_length_limited_by_target);
TEST (msg_transport_test_create_empty_request_payload_length_limited_by_buffer);
TEST (msg_transport_test_create_empty_request_payload_length_same_as_buffer);
TEST (msg_transport_test_create_empty_request_no_transport_overhead);
TEST (msg_transport_test_create_empty_request_overhead_same_as_buffer);
TEST (msg_transport_test_create_empty_request_null);
TEST (msg_transport_test_create_empty_request_overhead_more_than_buffer);
TEST (msg_transport_test_create_empty_request_check_overhead_error);
TEST (msg_transport_test_create_empty_request_check_payload_error);
TEST (msg_transport_test_create_empty_response);
TEST (msg_transport_test_create_empty_response_null);

TEST_SUITE_END;
// *INDENT-ON*
