// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "pcisig/doe/doe_cmd_channel.h"
#include "pcisig/doe/doe_interface.h"
#include "pcisig/doe/doe_interface_static.h"
#include "testing/mock/pcisig/doe/doe_channel_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "common/array_size.h"


TEST_SUITE_LABEL ("doe_interface");


/**
 * Dependencies for testing.
 */
struct doe_interface_testing {
	struct doe_interface doe_interface;			/**< DOE interface. */
	struct doe_cmd_channel_mock cmd_channel;	/**< Mock for the DOE command channel. */
	struct cmd_interface_mock spdm_responder;	/**< Mock for the SPDM responder. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param interface_testing Testing dependencies to initialize.
 */
static void doe_interface_testing_init_dependencies (CuTest *test,
	struct doe_interface_testing *interface_testing)
{
	int status;

	status = doe_cmd_channel_mock_init (&interface_testing->cmd_channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&interface_testing->spdm_responder);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param channel_testing Testing dependencies to release.
 */
static void doe_interface_testing_release_dependencies (CuTest *test,
	struct doe_interface_testing *interface_testing)
{
	int status;

	status = doe_cmd_channel_mock_validate_and_release (&interface_testing->cmd_channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&interface_testing->spdm_responder);
	CuAssertIntEquals (test, 0, status);
}

/**
 *  Initialize doe interface for testing.
 *
 * @param test The test framework.
 * @param interface_testing Testing dependencies to initialize.
 */
static void doe_interface_testing_init (CuTest *test,
	struct doe_interface_testing *interface_testing)
{
	int status;

	doe_interface_testing_init_dependencies (test, interface_testing);

	status = doe_interface_init (&interface_testing->doe_interface,
		&interface_testing->spdm_responder.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 *  Release doe interface and validate all mocks.
 *
 * @param test The test framework.
 * @param interface_testing Testing dependencies to release.
 */
static void doe_interface_testing_release (CuTest *test,
	struct doe_interface_testing *interface_testing)
{
	doe_interface_testing_release_dependencies (test, interface_testing);

	doe_interface_release (&interface_testing->doe_interface);
}


/*******************
 * Test cases
 *******************/

static void doe_interface_test_doe_interface_init (CuTest *test)
{
	int status;
	struct doe_interface doe;
	struct cmd_interface cmd_spdm_responder;
	struct doe_interface_testing interface_testing;

	TEST_START;

	doe_interface_testing_init_dependencies (test, &interface_testing);

	status = doe_interface_init (&doe, &cmd_spdm_responder);
	CuAssertIntEquals (test, 0, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_init_invalid_params (CuTest *test)
{
	int status;
	struct doe_interface doe;
	struct cmd_interface cmd_spdm_responder;
	struct doe_interface_testing interface_testing;

	TEST_START;

	doe_interface_testing_init_dependencies (test, &interface_testing);

	status = doe_interface_init (NULL, &cmd_spdm_responder);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_ARGUMENT, status);

	status = doe_interface_init (&doe, NULL);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_ARGUMENT, status);

	doe_interface_testing_release_dependencies (test, &interface_testing);
}

static void doe_interface_test_doe_interface_release_null (CuTest *test)
{
	TEST_START;
	doe_interface_release (NULL);
}

static void doe_interface_test_doe_interface_process_message_decode_spdm_data_object_type (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_interface_testing interface_testing;
	struct doe_base_protocol_transport_header *doe_header;
	int status;
	struct cmd_interface_msg msg_expected = {0};

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	msg_expected.is_encrypted = false;
	msg_expected.length = sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t);
	msg_expected.payload_length = sizeof (uint32_t);
	msg_expected.data = doe_message.message;
	msg_expected.payload = (uint8_t*) doe_message.message +
		sizeof (struct doe_base_protocol_transport_header);
	msg_expected.max_response = ARRAY_SIZE (doe_message.message);

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &msg_expected,
			sizeof (msg_expected)));
	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length = DOE_MESSAGE_MIN_SIZE_IN_DWORDS;

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, 0, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_decode_spdm_data_object_type_static_init (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_interface_testing interface_testing = {
		.doe_interface = doe_interface_static_init (&interface_testing.spdm_responder.base)
	};
	struct doe_base_protocol_transport_header *doe_header;
	int status;
	struct cmd_interface_msg msg_expected = {0};

	TEST_START;

	doe_interface_testing_init_dependencies (test, &interface_testing);

	msg_expected.is_encrypted = false;
	msg_expected.length = sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t);
	msg_expected.payload_length = sizeof (uint32_t);
	msg_expected.data = doe_message.message;
	msg_expected.payload = (uint8_t *) doe_message.message +
		sizeof (struct doe_base_protocol_transport_header);
	msg_expected.max_response = ARRAY_SIZE (doe_message.message);

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &msg_expected,
			sizeof (msg_expected)));
	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, 0, status);

	doe_interface_testing_release_dependencies (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_decode_secure_spdm_data_object_type (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_interface_testing interface_testing;
	struct doe_base_protocol_transport_header *doe_header;
	int status;
	struct cmd_interface_msg msg_expected = {0};

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	msg_expected.is_encrypted = true;
	msg_expected.length = sizeof (struct doe_base_protocol_transport_header) +
		2 * sizeof (uint32_t);
	msg_expected.payload_length = 2 * sizeof (uint32_t);
	msg_expected.data = doe_message.message;
	msg_expected.payload = (uint8_t *) doe_message.message +
		sizeof (struct doe_base_protocol_transport_header);
	msg_expected.max_response = ARRAY_SIZE (doe_message.message);

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &msg_expected,
			sizeof (msg_expected)));
	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
	doe_header->length = (sizeof (struct doe_base_protocol_transport_header) +
		2 * sizeof (uint32_t)) / sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, 0, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_decode_max_size (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_interface_testing interface_testing;
	struct doe_base_protocol_transport_header *doe_header;
	int status;
	struct cmd_interface_msg msg_expected = {0};

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	msg_expected.is_encrypted = false;
	msg_expected.length = DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES;
	msg_expected.payload_length = DOE_MESSAGE_SPEC_MAX_SIZE_IN_BYTES -
		sizeof (struct doe_base_protocol_transport_header);
	msg_expected.data = doe_message.message;
	msg_expected.payload = (uint8_t*) doe_message.message +
		sizeof (struct doe_base_protocol_transport_header);
	msg_expected.max_response = ARRAY_SIZE (doe_message.message);

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &msg_expected,
			sizeof (msg_expected)));
	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length = 0;

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, 0, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_null (CuTest *test)
{
	struct doe_cmd_message doe_message;
	struct doe_interface doe_interface;
	int status;

	TEST_START;

	status = doe_interface_process_message (NULL, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_ARGUMENT, status);

	status = doe_interface_process_message (&doe_interface, NULL);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_ARGUMENT, status);
}

static void doe_interface_test_doe_interface_process_message_decode_invalid_message_size
	(CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_interface_testing interface_testing;
	struct doe_base_protocol_transport_header *doe_header =
		(struct doe_base_protocol_transport_header*) doe_message.message;
	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	doe_header->length = DOE_MESSAGE_SPEC_MAX_SIZE_IN_DWORDS;
	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_MSG_SIZE, status);

	doe_header->length = sizeof (struct doe_base_protocol_transport_header) / sizeof (uint32_t);
	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_MSG_SIZE, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_decode_unsupported_vendor_id (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_interface_testing interface_testing;
	struct doe_base_protocol_transport_header *doe_header;
	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = 0xDEAD;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_VENDOR_ID, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_unsupported_data_object_type (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_interface_testing interface_testing;
	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = 0xFF;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_UNSUPPORTED_DATA_OBJECT_TYPE, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_secure_spdm_invalid_message_size (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_interface_testing interface_testing;
	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_MSG_SIZE, status);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_encode_alignment_check (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_interface_testing interface_testing;
	struct cmd_interface_msg processed_msg;
	int status;
	size_t message_size;

	TEST_START;

	for (message_size = 1; message_size < DOE_ALIGNMENT; message_size++) {
		doe_interface_testing_init (test, &interface_testing);

		processed_msg.payload_length = message_size;

		status = mock_expect (&interface_testing.spdm_responder.mock,
			interface_testing.spdm_responder.base.process_request,
			&interface_testing.spdm_responder.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
		status |= mock_expect_output (&interface_testing.spdm_responder.mock, 0, &processed_msg,
			sizeof (processed_msg), -1);

		CuAssertIntEquals (test, 0, status);

		doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
		doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
		doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
		doe_header->length =
			(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
			sizeof (uint32_t);

		status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
		CuAssertIntEquals (test, 0, status);
		doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
		CuAssertIntEquals (test, doe_header->length,
			(DOE_ALIGNMENT + sizeof (struct doe_base_protocol_transport_header)) /
			sizeof (uint32_t));

		doe_interface_testing_release (test, &interface_testing);
	}
}

static void doe_interface_test_doe_interface_process_message_encode_zero_payload (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_interface_testing interface_testing;
	struct cmd_interface_msg processed_msg;
	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	processed_msg.payload_length = 0;

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&interface_testing.spdm_responder.mock, 0, &processed_msg,
		sizeof (processed_msg), -1);

	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SECURED_SPDM;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + 2 * sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, 0, status);
	doe_header = (struct doe_base_protocol_transport_header *) doe_message.message;
	CuAssertIntEquals (test, doe_header->length,
		(sizeof (struct doe_base_protocol_transport_header)) / sizeof (uint32_t));
	CuAssertIntEquals (test, doe_header->reserved, 0);
	CuAssertIntEquals (test, doe_header->vendor_id, DOE_VENDOR_ID_PCISIG);
	CuAssertIntEquals (test, doe_header->data_object_type, DOE_DATA_OBJECT_TYPE_SECURED_SPDM);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_encode_max_payload (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_interface_testing interface_testing;
	struct cmd_interface_msg processed_msg;
	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	processed_msg.payload_length = DOE_MESSAGE_MAX_SIZE_IN_BYTES -
		sizeof (struct doe_base_protocol_transport_header);

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&interface_testing.spdm_responder.mock, 0,
		&processed_msg, sizeof (processed_msg), -1);

	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, 0, status);
	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	CuAssertIntEquals (test, doe_header->length, DOE_MESSAGE_MAX_SIZE_INDICATOR);
	CuAssertIntEquals (test, doe_header->reserved, 0);
	CuAssertIntEquals (test, doe_header->vendor_id, DOE_VENDOR_ID_PCISIG);
	CuAssertIntEquals (test, doe_header->data_object_type, DOE_DATA_OBJECT_TYPE_SPDM);

	doe_interface_testing_release (test, &interface_testing);
}

static void doe_interface_test_doe_interface_process_message_encode_gt_max_payload (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_interface_testing interface_testing;
	struct cmd_interface_msg processed_msg;

	int status;

	TEST_START;

	doe_interface_testing_init (test, &interface_testing);

	processed_msg.payload_length = DOE_MESSAGE_MAX_SIZE_IN_BYTES -
		sizeof (struct doe_base_protocol_transport_header) + 1;

	status = mock_expect (&interface_testing.spdm_responder.mock,
		interface_testing.spdm_responder.base.process_request,
		&interface_testing.spdm_responder.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&interface_testing.spdm_responder.mock, 0, &processed_msg,
		sizeof (processed_msg), -1);

	CuAssertIntEquals (test, 0, status);

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length =
		(sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	status = doe_interface_process_message (&interface_testing.doe_interface, &doe_message);
	CuAssertIntEquals (test, DOE_INTERFACE_INVALID_MSG_SIZE, status);

	doe_interface_testing_release (test, &interface_testing);
}


TEST_SUITE_START (doe_interface);

TEST (doe_interface_test_doe_interface_init);
TEST (doe_interface_test_doe_interface_init_invalid_params);
TEST (doe_interface_test_doe_interface_release_null);
TEST (doe_interface_test_doe_interface_process_message_decode_spdm_data_object_type);
TEST (doe_interface_test_doe_interface_process_message_decode_spdm_data_object_type_static_init);
TEST (doe_interface_test_doe_interface_process_message_decode_secure_spdm_data_object_type);
TEST (doe_interface_test_doe_interface_process_message_decode_max_size);
TEST (doe_interface_test_doe_interface_process_message_null);
TEST (doe_interface_test_doe_interface_process_message_decode_invalid_message_size);
TEST (doe_interface_test_doe_interface_process_message_decode_unsupported_vendor_id);
TEST (doe_interface_test_doe_interface_process_message_unsupported_data_object_type);
TEST (doe_interface_test_doe_interface_process_message_secure_spdm_invalid_message_size);
TEST (doe_interface_test_doe_interface_process_message_encode_alignment_check);
TEST (doe_interface_test_doe_interface_process_message_encode_zero_payload);
TEST (doe_interface_test_doe_interface_process_message_encode_max_payload);
TEST (doe_interface_test_doe_interface_process_message_encode_gt_max_payload);

TEST_SUITE_END;