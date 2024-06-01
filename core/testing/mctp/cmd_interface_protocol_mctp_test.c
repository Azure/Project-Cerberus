// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "mctp/cmd_interface_protocol_mctp.h"
#include "mctp/cmd_interface_protocol_mctp_static.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/mctp_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("cmd_interface_protocol_mctp");


/**
 * Dependencies for testing the protocol handler for MCTP messages.
 */
struct cmd_interface_protocol_mctp_testing {
	struct logging_mock log;					/**< Mock for the debug log. */
	struct cmd_interface_protocol_mctp test;	/**< Protocol handler being tested. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to initialize.
 */
static void cmd_interface_protocol_mctp_testing_init_dependencies (CuTest *test,
	struct cmd_interface_protocol_mctp_testing *mctp)
{
	int status;

	status = logging_mock_init (&mctp->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &mctp->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to release.
 */
static void cmd_interface_protocol_mctp_testing_release_dependencies (CuTest *test,
	struct cmd_interface_protocol_mctp_testing *mctp)
{
	int status;

	debug_log = NULL;

	status = logging_mock_validate_and_release (&mctp->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a MCTP protocol handler for testing.
 *
 * @param test The test framework.
 * @param mctp Testing components to initialize.
 */
static void cmd_interface_protocol_mctp_testing_init (CuTest *test,
	struct cmd_interface_protocol_mctp_testing *mctp)
{
	int status;

	cmd_interface_protocol_mctp_testing_init_dependencies (test, mctp);

	status = cmd_interface_protocol_mctp_init (&mctp->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release MCTP protocol test components and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing components to release.
 */
static void cmd_interface_protocol_mctp_testing_release (CuTest *test,
	struct cmd_interface_protocol_mctp_testing *mctp)
{
	cmd_interface_protocol_mctp_release (&mctp->test);
	cmd_interface_protocol_mctp_testing_release_dependencies (test, mctp);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_mctp_test_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	int status;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init_dependencies (test, &mctp);

	status = cmd_interface_protocol_mctp_init (&mctp.test);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, mctp.test.base.parse_message);
	CuAssertPtrNotNull (test, mctp.test.base.handle_request_result);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_init_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	int status;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init_dependencies (test, &mctp);

	status = cmd_interface_protocol_mctp_init (NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	cmd_interface_protocol_mctp_testing_release_dependencies (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp = {
		.test = cmd_interface_protocol_mctp_static_init
	};

	TEST_START;

	CuAssertPtrNotNull (test, mctp.test.base.parse_message);
	CuAssertPtrNotNull (test, mctp.test.base.handle_request_result);

	cmd_interface_protocol_mctp_testing_init_dependencies (test, &mctp);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_mctp_release (NULL);
}

static void cmd_interface_protocol_mctp_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * 2] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x13, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_payload_offset (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * 2] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[payload_offset];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x27;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = 0x11;
	message.source_addr = 0x65;
	message.target_eid = 0x22;
	message.channel_id = 7;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x27, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset + 1], message.payload);
	CuAssertIntEquals (test, message.length - (payload_offset + 1), message.payload_length);
	CuAssertIntEquals (test, 0x11, message.source_eid);
	CuAssertIntEquals (test, 0x65, message.source_addr);
	CuAssertIntEquals (test, 0x22, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 7, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_minimum_length (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * 2] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (*header);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x13, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, 0, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_mctp_control (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * 2] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, message_type);

	/* TODO:  This should be updated to strip the message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT, message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_mctp_control_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * 2] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 12;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[payload_offset];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_type = 0;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, message_type);

	/* TODO:  This should be updated to strip the message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT + payload_offset,
		message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_release (&mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_vendor_defined_pci (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x7e;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_vendor_defined_pci_with_integrity_check (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x7e;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_spdm (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x05;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp = {
		.test = cmd_interface_protocol_mctp_static_init
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init_dependencies (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x13, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (NULL, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp.test.base.parse_message (&mctp.test.base, NULL, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp.test.base.parse_message (&mctp.test.base, &message, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_no_payload (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = 0;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, 0, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_integrity_check (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_mctp_control_with_integrity_check (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_spdm_with_integrity_check (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x05;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_response_length_too_small (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data) - 1;
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESP_TOO_SMALL, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_parse_message_response_length_too_small_payload_offset
(
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT + 16] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 17;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[payload_offset];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_RESP_TOO_SMALL, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_payload_offset (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 9;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[payload_offset];
	int status;
	uint32_t message_type = 0x67;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x27;
	header->integrity_check = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[payload_offset + 1];
	message.payload_length = sizeof (data) - (payload_offset + 1);
	message.source_eid = 0x11;
	message.source_addr = 0x65;
	message.target_eid = 0x22;
	message.channel_id = 7;

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);
	CuAssertIntEquals (test, 0x11, message.source_eid);
	CuAssertIntEquals (test, 0x65, message.source_addr);
	CuAssertIntEquals (test, 0x22, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 7, message.channel_id);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_request_failure (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, CMD_HANDLER_PROCESS_FAILED,
		message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x13, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_mctp_control (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[1];
	int status;
	uint32_t message_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	/* TODO:  This should be updated to add the message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_mctp_control_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[1];
	int status;
	uint32_t message_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL,
		.arg1 = CMD_HANDLER_PROCESS_FAILED,
		.arg2 = 4
	};

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.handle_request_result (&mctp.test.base, CMD_HANDLER_PROCESS_FAILED,
		message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, status);

	/* TODO:  This should be updated to add the message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x13, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_vendor_defined_pci (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[1];
	int status;
	uint32_t message_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x13, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void
cmd_interface_protocol_mctp_test_handle_request_result_vendor_defined_pci_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) &data[1];
	int status;
	uint32_t message_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, CMD_HANDLER_PROCESS_FAILED,
		message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x13, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_spdm (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_spdm_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, CMD_HANDLER_PROCESS_FAILED,
		message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x13, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp = {
		.test = cmd_interface_protocol_mctp_static_init
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init_dependencies (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_handle_request_result_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.test.base.handle_request_result (NULL, 0, message_type, &message);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_add_header (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;

	status = cmd_interface_protocol_mctp_add_header (&mctp.test, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_add_header_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp = {
		.test = cmd_interface_protocol_mctp_static_init
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x21;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init_dependencies (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;

	status = cmd_interface_protocol_mctp_add_header (&mctp.test, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	CuAssertIntEquals (test, message_type, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_add_header_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[1];
	message.payload_length = sizeof (data) - 1;

	status = cmd_interface_protocol_mctp_add_header (NULL, message_type, &message);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = cmd_interface_protocol_mctp_add_header (&mctp.test, message_type, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[1], message.payload);
	CuAssertIntEquals (test, message.length - 1, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_test_add_header_insufficient_space (CuTest *test)
{
	struct cmd_interface_protocol_mctp_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_testing_init (test, &mctp);

	header->msg_type = 0x13;
	header->integrity_check = 1;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);

	status = cmd_interface_protocol_mctp_add_header (&mctp.test, message_type, &message);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_NO_HEADER_SPACE, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_testing_release (test, &mctp);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_protocol_mctp);

TEST (cmd_interface_protocol_mctp_test_init);
TEST (cmd_interface_protocol_mctp_test_init_null);
TEST (cmd_interface_protocol_mctp_test_static_init);
TEST (cmd_interface_protocol_mctp_test_release_null);
TEST (cmd_interface_protocol_mctp_test_parse_message);
TEST (cmd_interface_protocol_mctp_test_parse_message_payload_offset);
TEST (cmd_interface_protocol_mctp_test_parse_message_minimum_length);
TEST (cmd_interface_protocol_mctp_test_parse_message_mctp_control);
TEST (cmd_interface_protocol_mctp_test_parse_message_mctp_control_payload_offset);
TEST (cmd_interface_protocol_mctp_test_parse_message_vendor_defined_pci);
TEST (cmd_interface_protocol_mctp_test_parse_message_vendor_defined_pci_with_integrity_check);
TEST (cmd_interface_protocol_mctp_test_parse_message_spdm);
TEST (cmd_interface_protocol_mctp_test_parse_message_static_init);
TEST (cmd_interface_protocol_mctp_test_parse_message_null);
TEST (cmd_interface_protocol_mctp_test_parse_message_no_payload);
TEST (cmd_interface_protocol_mctp_test_parse_message_integrity_check);
TEST (cmd_interface_protocol_mctp_test_parse_message_mctp_control_with_integrity_check);
TEST (cmd_interface_protocol_mctp_test_parse_message_spdm_with_integrity_check);
TEST (cmd_interface_protocol_mctp_test_parse_message_response_length_too_small);
TEST (cmd_interface_protocol_mctp_test_parse_message_response_length_too_small_payload_offset);
TEST (cmd_interface_protocol_mctp_test_handle_request_result);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_payload_offset);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_request_failure);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_mctp_control);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_mctp_control_request_failure);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_vendor_defined_pci);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_vendor_defined_pci_request_failure);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_spdm);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_spdm_request_failure);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_static_init);
TEST (cmd_interface_protocol_mctp_test_handle_request_result_null);
TEST (cmd_interface_protocol_mctp_test_add_header);
TEST (cmd_interface_protocol_mctp_test_add_header_static_init);
TEST (cmd_interface_protocol_mctp_test_add_header_null);
TEST (cmd_interface_protocol_mctp_test_add_header_insufficient_space);

TEST_SUITE_END;
// *INDENT-ON*
