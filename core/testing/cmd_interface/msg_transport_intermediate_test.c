// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/msg_transport_intermediate.h"
#include "cmd_interface/msg_transport_intermediate_static.h"
#include "common/unused.h"
#include "testing/mock/cmd_interface/msg_transport_mock.h"


TEST_SUITE_LABEL ("msg_transport_intermediate");


/**
 * Dependencies for testing a message transport that acts as an intermediate layer above another
 * message transport.
 */
struct msg_transport_intermediate_testing {
	struct msg_transport_mock transport;	/**< Mock for the next transport layer. */
	struct msg_transport_intermediate test;	/**< Message transport being tested. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param intermediate Testing dependencies to initialize.
 */
static void msg_transport_intermediate_testing_init_dependencies (CuTest *test,
	struct msg_transport_intermediate_testing *intermediate)
{
	int status;

	status = msg_transport_mock_init (&intermediate->transport);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param intermediate Testing dependencies to release.
 */
static void msg_transport_intermediate_testing_release_dependencies (CuTest *test,
	struct msg_transport_intermediate_testing *intermediate)
{
	int status;

	status = msg_transport_mock_validate_and_release (&intermediate->transport);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an intermediate message transport for testing.
 *
 * @param test The test framework.
 * @param intermediate Testing components to initialize.
 * @param overhead_bytes The number of overhead bytes to report.
 */
static void msg_transport_intermediate_testing_init (CuTest *test,
	struct msg_transport_intermediate_testing *intermediate, size_t overhead_bytes)
{
	int status;

	msg_transport_intermediate_testing_init_dependencies (test, intermediate);

	status = msg_transport_intermediate_init (&intermediate->test, &intermediate->transport.base,
		overhead_bytes);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release intermediate message transport test components and validate all mocks.
 *
 * @param test The test framework.
 * @param intermediate Testing components to release.
 */
static void msg_transport_intermediate_testing_release (CuTest *test,
	struct msg_transport_intermediate_testing *intermediate)
{
	msg_transport_intermediate_release (&intermediate->test);
	msg_transport_intermediate_testing_release_dependencies (test, intermediate);
}

/* Stub function for msg_transport.send_request_message that can be used for static initialization
 * tests. */
int msg_transport_intermediate_testing_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response)
{
	UNUSED (transport);
	UNUSED (request);
	UNUSED (timeout_ms);
	UNUSED (response);

	return -1;
}


/*******************
 * Test cases
 *******************/

static void msg_transport_intermediate_test_init (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	status = msg_transport_intermediate_init (&intermediate.test, &intermediate.transport.base, 10);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, intermediate.test.base.get_max_message_overhead);
	CuAssertPtrNotNull (test, intermediate.test.base.get_max_message_payload_length);
	CuAssertPtrNotNull (test, intermediate.test.base.get_max_encapsulated_message_length);
	CuAssertPtrNotNull (test, intermediate.test.base.get_buffer_overhead);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_init_null (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	status = msg_transport_intermediate_init (NULL, &intermediate.transport.base, 10);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = msg_transport_intermediate_init (&intermediate.test, NULL, 10);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_intermediate_testing_release_dependencies (test, &intermediate);
}

static void msg_transport_intermediate_test_static_init (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate = {
		.test =
			msg_transport_intermediate_static_init (
			msg_transport_intermediate_testing_send_request_message, &intermediate.transport.base,
			20)
	};

	TEST_START;

	CuAssertPtrNotNull (test, intermediate.test.base.get_max_message_overhead);
	CuAssertPtrNotNull (test, intermediate.test.base.get_max_message_payload_length);
	CuAssertPtrNotNull (test, intermediate.test.base.get_max_encapsulated_message_length);
	CuAssertPtrNotNull (test, intermediate.test.base.get_buffer_overhead);
	CuAssertPtrNotNull (test, intermediate.test.base.send_request_message);

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_release_null (CuTest *test)
{
	TEST_START;

	msg_transport_intermediate_release (NULL);
}

static void msg_transport_intermediate_test_get_max_message_overhead (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 8;
	int overhead = 24;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_overhead, &intermediate.transport, overhead,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_overhead (&intermediate.test.base, dest_id);
	CuAssertIntEquals (test, overhead + 10, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_overhead_static_init (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate = {
		.test =
			msg_transport_intermediate_static_init (
			msg_transport_intermediate_testing_send_request_message, &intermediate.transport.base,
			15)
	};
	uint8_t dest_id = 78;
	int overhead = 34;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_overhead, &intermediate.transport, overhead,
		MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_overhead (&intermediate.test.base, dest_id);
	CuAssertIntEquals (test, overhead + 15, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_overhead_null (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 8;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = intermediate.test.base.get_max_message_overhead (NULL, dest_id);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_overhead_transport_error (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 51;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_overhead, &intermediate.transport,
		MSG_TRANSPORT_MAX_OVERHEAD_FAILED, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_overhead (&intermediate.test.base, dest_id);
	CuAssertIntEquals (test, MSG_TRANSPORT_MAX_OVERHEAD_FAILED, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_payload_length (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 3;
	int payload = 345;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_payload_length, &intermediate.transport,
		payload, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_payload_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, payload - 10, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_payload_length_less_than_overhead (
	CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 31;
	int payload = 11;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, payload + 1);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_payload_length, &intermediate.transport,
		payload, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_payload_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, 0, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_payload_length_static_init (
	CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate = {
		.test =
			msg_transport_intermediate_static_init (
			msg_transport_intermediate_testing_send_request_message, &intermediate.transport.base,
			20)
	};
	uint8_t dest_id = 65;
	int payload = 1024;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_payload_length, &intermediate.transport,
		payload, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_payload_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, payload - 20, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_payload_length_null (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 3;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = intermediate.test.base.get_max_message_payload_length (NULL, dest_id);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_message_payload_length_transport_error (
	CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 3;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_message_payload_length, &intermediate.transport,
		MSG_TRANSPORT_MAX_PAYLOAD_FAILED, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_message_payload_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, MSG_TRANSPORT_MAX_PAYLOAD_FAILED, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_encapsulated_message_length (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 12;
	int total = 543;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_encapsulated_message_length, &intermediate.transport,
		total, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_encapsulated_message_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, total, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_encapsulated_message_length_static_init (
	CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate = {
		.test =
			msg_transport_intermediate_static_init (
			msg_transport_intermediate_testing_send_request_message, &intermediate.transport.base,
			20)
	};
	uint8_t dest_id = 4;
	int total = 728;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_encapsulated_message_length, &intermediate.transport,
		total, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_encapsulated_message_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, total, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_encapsulated_message_length_null (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 12;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = intermediate.test.base.get_max_encapsulated_message_length (NULL, dest_id);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_max_encapsulated_message_length_transport_error (
	CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 12;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_max_encapsulated_message_length, &intermediate.transport,
		MSG_TRANSPORT_MAX_BUFFER_FAILED, MOCK_ARG (dest_id));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_max_encapsulated_message_length (&intermediate.test.base,
		dest_id);
	CuAssertIntEquals (test, MSG_TRANSPORT_MAX_BUFFER_FAILED, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_buffer_overhead (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 8;
	size_t length = 128;
	int overhead = 24;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_buffer_overhead, &intermediate.transport, overhead,
		MOCK_ARG (dest_id), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_buffer_overhead (&intermediate.test.base, dest_id, length);
	CuAssertIntEquals (test, overhead + 10, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_buffer_overhead_static_init (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate = {
		.test =
			msg_transport_intermediate_static_init (
			msg_transport_intermediate_testing_send_request_message, &intermediate.transport.base,
			4)
	};
	uint8_t dest_id = 56;
	size_t length = 512;
	int overhead = 33;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init_dependencies (test, &intermediate);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_buffer_overhead, &intermediate.transport, overhead,
		MOCK_ARG (dest_id), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_buffer_overhead (&intermediate.test.base, dest_id, length);
	CuAssertIntEquals (test, overhead + 4, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_buffer_overhead_null (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 8;
	size_t length = 128;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = intermediate.test.base.get_buffer_overhead (NULL, dest_id, length);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}

static void msg_transport_intermediate_test_get_buffer_overhead_transport_error (CuTest *test)
{
	struct msg_transport_intermediate_testing intermediate;
	uint8_t dest_id = 8;
	size_t length = 128;
	int status;

	TEST_START;

	msg_transport_intermediate_testing_init (test, &intermediate, 10);

	status = mock_expect (&intermediate.transport.mock,
		intermediate.transport.base.get_buffer_overhead, &intermediate.transport,
		MSG_TRANSPORT_OVERHEAD_FAILED, MOCK_ARG (dest_id), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = intermediate.test.base.get_buffer_overhead (&intermediate.test.base, dest_id, length);
	CuAssertIntEquals (test, MSG_TRANSPORT_OVERHEAD_FAILED, status);

	msg_transport_intermediate_testing_release (test, &intermediate);
}


// *INDENT-OFF*
TEST_SUITE_START (msg_transport_intermediate);

TEST (msg_transport_intermediate_test_init);
TEST (msg_transport_intermediate_test_init_null);
TEST (msg_transport_intermediate_test_static_init);
TEST (msg_transport_intermediate_test_release_null);
TEST (msg_transport_intermediate_test_get_max_message_overhead);
TEST (msg_transport_intermediate_test_get_max_message_overhead_static_init);
TEST (msg_transport_intermediate_test_get_max_message_overhead_null);
TEST (msg_transport_intermediate_test_get_max_message_overhead_transport_error);
TEST (msg_transport_intermediate_test_get_max_message_payload_length);
TEST (msg_transport_intermediate_test_get_max_message_payload_length_less_than_overhead);
TEST (msg_transport_intermediate_test_get_max_message_payload_length_static_init);
TEST (msg_transport_intermediate_test_get_max_message_payload_length_null);
TEST (msg_transport_intermediate_test_get_max_message_payload_length_transport_error);
TEST (msg_transport_intermediate_test_get_max_encapsulated_message_length);
TEST (msg_transport_intermediate_test_get_max_encapsulated_message_length_static_init);
TEST (msg_transport_intermediate_test_get_max_encapsulated_message_length_null);
TEST (msg_transport_intermediate_test_get_max_encapsulated_message_length_transport_error);
TEST (msg_transport_intermediate_test_get_buffer_overhead);
TEST (msg_transport_intermediate_test_get_buffer_overhead_static_init);
TEST (msg_transport_intermediate_test_get_buffer_overhead_null);
TEST (msg_transport_intermediate_test_get_buffer_overhead_transport_error);

TEST_SUITE_END;
// *INDENT-ON*
