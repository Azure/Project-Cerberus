// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/unused.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "spdm/cmd_interface_protocol_spdm_pcisig_static.h"

TEST_SUITE_LABEL ("cmd_interface_protocol_spdm_pcisig");

/**
 * Dependencies for testing the protocol handler for SPDM VDM messages.
 */
struct cmd_interface_protocol_spdm_pcisig_testing {
	struct cmd_interface_protocol_spdm_pcisig test;
};


/**
 * Initialize all dependencies for testing
 *
 * @param test The test framework
 * @param spdm_pcisig Testing dependencies
 */
static void cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (CuTest *test,
	struct cmd_interface_protocol_spdm_pcisig_testing *spdm_pcisig)
{
	UNUSED (test);
	UNUSED (spdm_pcisig);
}

/**
 * Release all dependencies and validate all mocks
 *
 * @param test The test framework
 * @param spdm_pcisig Testing dependencies
 */
static void cmd_interface_protocol_spdm_pcisig_testing_release_dependencies (CuTest *test,
	struct cmd_interface_protocol_spdm_pcisig_testing *spdm_pcisig)
{
	UNUSED (test);
	UNUSED (spdm_pcisig);
}

/**
 * Initialize SPDM VDM protocol handler for testing
 *
 * @param test The test framework
 * @param spdm_pcisig Testing components to initialize
 */
static void cmd_interface_protocol_spdm_pcisig_testing_init (CuTest *test,
	struct cmd_interface_protocol_spdm_pcisig_testing *spdm_pcisig)
{
	int status;

	cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (test, spdm_pcisig);

	status = cmd_interface_protocol_spdm_pcisig_init (&spdm_pcisig->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release SPDM VDM protocol component and validate all mocks
 *
 * @param test The test framework
 * @param spdm_pcisig Testing components to release
 */
static void cmd_interface_protocol_spdm_pcisig_testing_release (CuTest *test,
	struct cmd_interface_protocol_spdm_pcisig_testing *spdm_pcisig)
{
	cmd_interface_protocol_spdm_pcisig_release (&spdm_pcisig->test);
	cmd_interface_protocol_spdm_pcisig_testing_release_dependencies (test, spdm_pcisig);
}

/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_spdm_pcisig_test_init (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (test, &spdm_pcisig);

	status = cmd_interface_protocol_spdm_pcisig_init (&spdm_pcisig.test);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, spdm_pcisig.test.base.parse_message);
	CuAssertPtrNotNull (test, spdm_pcisig.test.base.handle_request_result);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_init_null (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (test, &spdm_pcisig);

	status = cmd_interface_protocol_spdm_pcisig_init (NULL);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT, status);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig = {
		.test = cmd_interface_protocol_spdm_pcisig_static_init (),
	};

	TEST_START;

	CuAssertPtrNotNull (test, spdm_pcisig.test.base.parse_message);
	CuAssertPtrNotNull (test, spdm_pcisig.test.base.handle_request_result);

	cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (test, &spdm_pcisig);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_release (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_spdm_pcisig_release (NULL);
}

static void cmd_interface_protocol_spdm_pcisig_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	struct spdm_protocol_pcisig_header *header = (struct spdm_protocol_pcisig_header*) data;
	uint32_t message_type;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	header->vendor_id_len = 2;
	header->vendor_id = 0x1;
	header->protocol_id = 0x33;
	header->payload_length = 16;

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, &message, &message_type);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x33, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data + sizeof (struct spdm_protocol_pcisig_header),
		message.payload);
	CuAssertIntEquals (test, message.length - sizeof (struct spdm_protocol_pcisig_header),
		message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig = {
		.test = cmd_interface_protocol_spdm_pcisig_static_init (),
	};
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	struct spdm_protocol_pcisig_header *header = (struct spdm_protocol_pcisig_header*) data;
	uint32_t message_type;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (test, &spdm_pcisig);

	header->vendor_id_len = 2;
	header->vendor_id = 0x1;
	header->protocol_id = 0x33;
	header->payload_length = 16;

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, &message, &message_type);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x33, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data + sizeof (struct spdm_protocol_pcisig_header),
		message.payload);
	CuAssertIntEquals (test, message.length - sizeof (struct spdm_protocol_pcisig_header),
		message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	struct spdm_protocol_pcisig_header *header = (struct spdm_protocol_pcisig_header*) data;
	uint32_t message_type;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	header->vendor_id_len = 2;
	header->vendor_id = 0x1;
	header->protocol_id = 0x33;
	header->payload_length = 16;

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);

	status = spdm_pcisig.test.base.parse_message (NULL, &message, &message_type);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT, status);

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, NULL, &message_type);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT, status);

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, &message, NULL);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT, status);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_parse_message_too_small (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	struct spdm_protocol_pcisig_header *header = (struct spdm_protocol_pcisig_header*) data;
	uint32_t message_type;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	header->vendor_id_len = 2;
	header->vendor_id = 0x1;
	header->protocol_id = 0x33;
	header->payload_length = 16;

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (struct spdm_protocol_pcisig_header) - 1;

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, &message, &message_type);

	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_MSG_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (struct spdm_protocol_pcisig_header) - 1,
		message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_parse_message_invalid_header (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	struct spdm_protocol_pcisig_header *header = (struct spdm_protocol_pcisig_header*) data;
	uint32_t message_type;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	header->vendor_id_len = 4;
	header->vendor_id = 0x1;
	header->protocol_id = 0x33;
	header->payload_length = 16;

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, &message, &message_type);

	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_HEADER, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	header->vendor_id_len = 2;
	header->vendor_id = 0x11;

	status = spdm_pcisig.test.base.parse_message (&spdm_pcisig.test.base, &message, &message_type);

	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_HEADER, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_handle_request_result (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data + sizeof (struct spdm_protocol_pcisig_header);
	message.payload_length = 8;

	status = spdm_pcisig.test.base.handle_request_result (&spdm_pcisig.test.base, 0, 1, &message);

	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_protocol_pcisig_header),
		message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_handle_request_result_static_init (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig = {
		.test = cmd_interface_protocol_spdm_pcisig_static_init (),
	};
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init_dependencies (test, &spdm_pcisig);

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data + sizeof (struct spdm_protocol_pcisig_header);
	message.payload_length = 8;

	status = spdm_pcisig.test.base.handle_request_result (&spdm_pcisig.test.base, 0, 1, &message);

	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_protocol_pcisig_header),
		message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_handle_request_result_failed_result (
	CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data + sizeof (struct spdm_protocol_pcisig_header);
	message.payload_length = 8;

	status = spdm_pcisig.test.base.handle_request_result (&spdm_pcisig.test.base, 21, 1, &message);
	CuAssertIntEquals (test, 21, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, 8 + sizeof (struct spdm_protocol_pcisig_header),
		message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_handle_request_result_null (CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	struct cmd_interface_msg message;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	status = spdm_pcisig.test.base.handle_request_result (NULL, 0, 1, &message);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT, status);

	status = spdm_pcisig.test.base.handle_request_result (&spdm_pcisig.test.base, 0, 1, NULL);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_ARGUMENT, status);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

static void cmd_interface_protocol_spdm_pcisig_test_handle_request_result_invalid_response (
	CuTest *test)
{
	struct cmd_interface_protocol_spdm_pcisig_testing spdm_pcisig;
	uint8_t data[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg message;
	int status;

	TEST_START;

	cmd_interface_protocol_spdm_pcisig_testing_init (test, &spdm_pcisig);

	memset (&message, 0, sizeof (message));

	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data + sizeof (struct spdm_protocol_pcisig_header) - 1;
	message.payload_length = 8;

	status = spdm_pcisig.test.base.handle_request_result (&spdm_pcisig.test.base, 0, 1, &message);
	CuAssertIntEquals (test, SPDM_PCISIG_PROTOCOL_INVALID_RESPONSE, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data + sizeof (struct spdm_protocol_pcisig_header) - 1,
		message.payload);
	CuAssertIntEquals (test, 8, message.payload_length);

	cmd_interface_protocol_spdm_pcisig_testing_release (test, &spdm_pcisig);
}

// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_protocol_spdm_pcisig);

TEST (cmd_interface_protocol_spdm_pcisig_test_init);
TEST (cmd_interface_protocol_spdm_pcisig_test_init_null);
TEST (cmd_interface_protocol_spdm_pcisig_test_static_init);
TEST (cmd_interface_protocol_spdm_pcisig_test_release);
TEST (cmd_interface_protocol_spdm_pcisig_test_parse_message);
TEST (cmd_interface_protocol_spdm_pcisig_test_parse_message_static_init);
TEST (cmd_interface_protocol_spdm_pcisig_test_parse_message_null);
TEST (cmd_interface_protocol_spdm_pcisig_test_parse_message_too_small);
TEST (cmd_interface_protocol_spdm_pcisig_test_parse_message_invalid_header);
TEST (cmd_interface_protocol_spdm_pcisig_test_handle_request_result);
TEST (cmd_interface_protocol_spdm_pcisig_test_handle_request_result_static_init);
TEST (cmd_interface_protocol_spdm_pcisig_test_handle_request_result_failed_result);
TEST (cmd_interface_protocol_spdm_pcisig_test_handle_request_result_null);
TEST (cmd_interface_protocol_spdm_pcisig_test_handle_request_result_invalid_response);

TEST_SUITE_END;
// *INDENT-ON*
