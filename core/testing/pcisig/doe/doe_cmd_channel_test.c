// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "common/array_size.h"
#include "common/unused.h"
#include "pcisig/doe/doe_cmd_channel.h"
#include "pcisig/doe/doe_cmd_channel_static.h"
#include "pcisig/doe/doe_interface.h"
#include "pcisig/doe/doe_interface_static.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/pcisig/doe/doe_channel_mock.h"


TEST_SUITE_LABEL ("doe_cmd_channel");

#define DOE_DATA_OBJECT_PROTOCOLS_MAX_COUNT		3

/**
 * Dependencies for testing.
 */
struct doe_cmd_channel_testing {
	struct doe_interface doe_interface;															/**< DOE interface. */
	struct doe_cmd_channel_mock cmd_channel;													/**< Mock for the DOE command channel. */
	struct cmd_interface_mock spdm_responder;													/**< Mock for the SPDM responder. */
	struct doe_data_object_protocol data_object_protocol[DOE_DATA_OBJECT_PROTOCOLS_MAX_COUNT];	/**< Supported DOE data object protocols. */
};


/**
 *  Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param channel_testing Testing dependencies to initialize.
 */
static void doe_cmd_channel_testing_init_dependencies (CuTest *test,
	struct doe_cmd_channel_testing *channel_testing)
{
	int status;
	struct doe_data_object_protocol data_object_protocol[] = {
		{DOE_VENDOR_ID_PCISIG, DOE_DATA_OBJECT_TYPE_DOE_DISCOVERY},
		{DOE_VENDOR_ID_PCISIG, DOE_DATA_OBJECT_TYPE_SPDM},
		{DOE_VENDOR_ID_PCISIG, DOE_DATA_OBJECT_TYPE_SECURED_SPDM},
	};

	memcpy (channel_testing->data_object_protocol, data_object_protocol,
		sizeof (data_object_protocol));

	status = doe_cmd_channel_mock_init (&channel_testing->cmd_channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&channel_testing->spdm_responder);
	CuAssertIntEquals (test, 0, status);

	status = doe_interface_init (&channel_testing->doe_interface,
		&channel_testing->spdm_responder.base, channel_testing->data_object_protocol,
		ARRAY_SIZE (channel_testing->data_object_protocol));
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param channel_testing Testing dependencies to release.
 */
static void doe_cmd_channel_testing_release_dependencies (CuTest *test,
	struct doe_cmd_channel_testing *channel_testing)
{
	int status;

	status = doe_cmd_channel_mock_validate_and_release (&channel_testing->cmd_channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&channel_testing->spdm_responder);
	CuAssertIntEquals (test, 0, status);

	doe_interface_release (&channel_testing->doe_interface);
}

/**
 * Dummy handler to receive a message from a DOE communication channel.
 *
 * @param channel The channel to receive a message from.
 * @param message Output for the message pointer being received.
 * @param ms_timeout The amount of time to wait for a received message, in milliseconds.
 *
 * @return DOE_CMD_CHANNEL_RX_FAILED.
 */
static int doe_cmd_channel_testing_empty_receive_message (const struct doe_cmd_channel *channel,
	struct doe_cmd_message **message, int ms_timeout)
{
	UNUSED (channel);
	UNUSED (message);
	UNUSED (ms_timeout);

	return DOE_CMD_CHANNEL_RX_FAILED;
}

/**
 * Dummy handler to send a message over a DOE communication channel.
 *
 * @param channel The channel to send the message on.
 * @param message The message to send.
 *
 * @return DOE_CMD_CHANNEL_TX_FAILED.
 */
static int doe_cmd_channel_testing_empty_send_message (const struct doe_cmd_channel *channel,
	const struct doe_cmd_message *message)
{
	UNUSED (channel);
	UNUSED (message);

	return DOE_CMD_CHANNEL_TX_FAILED;
}


/*******************
 * Test cases
 *******************/

static void doe_cmd_channel_test_init_static (CuTest *test)
{
	const struct doe_cmd_channel channel =
		doe_cmd_channel_static_init (doe_cmd_channel_testing_empty_receive_message,
		doe_cmd_channel_testing_empty_send_message);

	TEST_START;

	CuAssertPtrNotNull (test, channel.receive_message);
	CuAssertPtrNotNull (test, channel.send_message);
}

static void doe_cmd_channel_test_receive_and_process (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_cmd_message *doe_message_ptr = &doe_message;
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_cmd_channel_testing channel_testing;
	int status;

	TEST_START;

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length = (sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	doe_cmd_channel_testing_init_dependencies (test, &channel_testing);

	status = mock_expect (&channel_testing.cmd_channel.mock,
		channel_testing.cmd_channel.base.receive_message, &channel_testing.cmd_channel.base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (20));
	status |= mock_expect_output (&channel_testing.cmd_channel.mock, 0, &doe_message_ptr,
		sizeof (doe_message_ptr), -1);

	status |= mock_expect (&channel_testing.cmd_channel.mock,
		channel_testing.cmd_channel.base.send_message, &channel_testing.cmd_channel.base, 0,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&channel_testing.spdm_responder.mock,
		channel_testing.spdm_responder.base.process_request, &channel_testing.spdm_responder.base,
		0, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = doe_cmd_channel_receive_and_process (&channel_testing.cmd_channel.base,
		&channel_testing.doe_interface, 20);
	CuAssertIntEquals (test, 0, status);

	doe_cmd_channel_testing_release_dependencies (test, &channel_testing);
}

static void doe_cmd_channel_test_receive_and_process_message_invalid_params (CuTest *test)
{
	struct doe_cmd_channel channel = {0};
	struct doe_interface doe = {0};
	int status;

	TEST_START;

	status = doe_cmd_channel_receive_and_process (NULL, &doe, -1);
	CuAssertIntEquals (test, DOE_CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = doe_cmd_channel_receive_and_process (&channel, NULL, 30);
	CuAssertIntEquals (test, DOE_CMD_CHANNEL_INVALID_ARGUMENT, status);
}

static void doe_cmd_channel_test_receive_and_process_receive_fail (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_cmd_channel_testing channel_testing;
	int status;

	TEST_START;

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length = (sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	doe_cmd_channel_testing_init_dependencies (test, &channel_testing);

	status = mock_expect (&channel_testing.cmd_channel.mock,
		channel_testing.cmd_channel.base.receive_message, &channel_testing.cmd_channel.base,
		DOE_CMD_CHANNEL_RX_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (50));
	CuAssertIntEquals (test, 0, status);

	status = doe_cmd_channel_receive_and_process (&channel_testing.cmd_channel.base,
		&channel_testing.doe_interface, 50);
	CuAssertIntEquals (test, DOE_CMD_CHANNEL_RX_FAILED, status);

	doe_cmd_channel_testing_release_dependencies (test, &channel_testing);
}

static void doe_cmd_channel_test_receive_and_process_doe_interface_process_message_decode_fail (
	CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_cmd_message *doe_message_ptr = &doe_message;
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_cmd_channel_testing channel_testing;
	int status;

	TEST_START;

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length = DOE_MESSAGE_SPEC_MAX_SIZE_IN_DWORDS;

	doe_cmd_channel_testing_init_dependencies (test, &channel_testing);

	status = mock_expect (&channel_testing.cmd_channel.mock,
		channel_testing.cmd_channel.base.receive_message, &channel_testing.cmd_channel.base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (10));
	status |= mock_expect_output (&channel_testing.cmd_channel.mock, 0, &doe_message_ptr,
		sizeof (doe_message_ptr), -1);

	CuAssertIntEquals (test, 0, status);

	status = doe_cmd_channel_receive_and_process (&channel_testing.cmd_channel.base,
		&channel_testing.doe_interface, 10);
	CuAssertTrue (test, status != 0);

	doe_cmd_channel_testing_release_dependencies (test, &channel_testing);
}

static void doe_cmd_channel_test_receive_and_process_send_fail (CuTest *test)
{
	struct doe_cmd_message doe_message = {0};
	struct doe_cmd_message *doe_message_ptr = &doe_message;
	struct doe_base_protocol_transport_header *doe_header;
	struct doe_cmd_channel_testing channel_testing;
	int status;

	TEST_START;

	doe_header = (struct doe_base_protocol_transport_header*) doe_message.message;
	doe_header->vendor_id = DOE_VENDOR_ID_PCISIG;
	doe_header->data_object_type = DOE_DATA_OBJECT_TYPE_SPDM;
	doe_header->length = (sizeof (struct doe_base_protocol_transport_header) + sizeof (uint32_t)) /
		sizeof (uint32_t);

	doe_cmd_channel_testing_init_dependencies (test, &channel_testing);

	status = mock_expect (&channel_testing.cmd_channel.mock,
		channel_testing.cmd_channel.base.receive_message, &channel_testing.cmd_channel.base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel_testing.cmd_channel.mock, 0, &doe_message_ptr,
		sizeof (doe_message_ptr), -1);

	status |= mock_expect (&channel_testing.cmd_channel.mock,
		channel_testing.cmd_channel.base.send_message, &channel_testing.cmd_channel.base, -1,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));

	status |= mock_expect (&channel_testing.spdm_responder.mock,
		channel_testing.spdm_responder.base.process_request, &channel_testing.spdm_responder.base,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));

	CuAssertIntEquals (test, 0, status);

	status = doe_cmd_channel_receive_and_process (&channel_testing.cmd_channel.base,
		&channel_testing.doe_interface, -1);
	CuAssertTrue (test, status != 0);

	doe_cmd_channel_testing_release_dependencies (test, &channel_testing);
}


// *INDENT-OFF*
TEST_SUITE_START (doe_cmd_channel);

TEST (doe_cmd_channel_test_init_static);
TEST (doe_cmd_channel_test_receive_and_process);
TEST (doe_cmd_channel_test_receive_and_process_message_invalid_params);
TEST (doe_cmd_channel_test_receive_and_process_receive_fail);
TEST (doe_cmd_channel_test_receive_and_process_doe_interface_process_message_decode_fail);
TEST (doe_cmd_channel_test_receive_and_process_send_fail);

TEST_SUITE_END;
// *INDENT-ON*
