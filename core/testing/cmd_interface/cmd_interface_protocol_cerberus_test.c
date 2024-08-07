// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_interface_protocol_cerberus.h"
#include "cmd_interface/cmd_interface_protocol_cerberus_static.h"
#include "cmd_interface/cmd_logging.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("cmd_interface_protocol_cerberus");


/**
 * Dependencies for testing the protocol handler for Cerberus messages.
 */
struct cmd_interface_protocol_cerberus_testing {
	struct logging_mock log;						/**< Mock for the debug log. */
	struct cmd_interface_protocol_cerberus test;	/**< Protocol handler being tested. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param cerberus Testing dependencies to initialize.
 */
static void cmd_interface_protocol_cerberus_testing_init_dependencies (CuTest *test,
	struct cmd_interface_protocol_cerberus_testing *cerberus)
{
	int status;

	status = logging_mock_init (&cerberus->log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &cerberus->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param cerberus Testing dependencies to release.
 */
static void cmd_interface_protocol_cerberus_testing_release_dependencies (CuTest *test,
	struct cmd_interface_protocol_cerberus_testing *cerberus)
{
	int status;

	debug_log = NULL;

	status = logging_mock_validate_and_release (&cerberus->log);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a Cerberus protocol handler for testing.
 *
 * @param test The test framework.
 * @param cerberus Testing components to initialize.
 */
static void cmd_interface_protocol_cerberus_testing_init (CuTest *test,
	struct cmd_interface_protocol_cerberus_testing *cerberus)
{
	int status;

	cmd_interface_protocol_cerberus_testing_init_dependencies (test, cerberus);

	status = cmd_interface_protocol_cerberus_init (&cerberus->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release Cerberus protocol test components and validate all mocks.
 *
 * @param test The test framework.
 * @param cerberus Testing components to release.
 */
static void cmd_interface_protocol_cerberus_testing_release (CuTest *test,
	struct cmd_interface_protocol_cerberus_testing *cerberus)
{
	cmd_interface_protocol_cerberus_release (&cerberus->test);
	cmd_interface_protocol_cerberus_testing_release_dependencies (test, cerberus);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_cerberus_test_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	int status;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init_dependencies (test, &cerberus);

	status = cmd_interface_protocol_cerberus_init (&cerberus.test);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cerberus.test.base.parse_message);
	CuAssertPtrNotNull (test, cerberus.test.base.handle_request_result);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_init_null (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	int status;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init_dependencies (test, &cerberus);

	status = cmd_interface_protocol_cerberus_init (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_protocol_cerberus_testing_release_dependencies (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_static_init
	};

	TEST_START;

	CuAssertPtrNotNull (test, cerberus.test.base.parse_message);
	CuAssertPtrNotNull (test, cerberus.test.base.handle_request_result);

	cmd_interface_protocol_cerberus_testing_init_dependencies (test, &cerberus);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_cerberus_release (NULL);
}

static void cmd_interface_protocol_cerberus_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.crypto_timeout = true;
	message.channel_id = 4;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x12, message_type);

	/* TODO:  Remove protocol header during processing. */
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

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_payload_offset (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct cerberus_protocol_header *header =
		(struct cerberus_protocol_header*) &data[payload_offset];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x34;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = 0x11;
	message.source_addr = 0x65;
	message.target_eid = 0x22;
	message.is_encrypted = true;
	message.crypto_timeout = true;
	message.channel_id = 7;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x34, message_type);

	/* TODO:  Remove protocol header during processing. */
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

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_minimum_length (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x56;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (*header);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.crypto_timeout = true;
	message.channel_id = 4;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x56, message_type);

	/* TODO:  Remove protocol header during processing. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header), message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_static_init
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init_dependencies (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.crypto_timeout = true;
	message.channel_id = 4;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x12, message_type);

	/* TODO:  Remove protocol header during processing. */
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

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.crypto_timeout = true;
	message.channel_id = 4;

	status = cerberus.test.base.parse_message (NULL, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);

	message.crypto_timeout = true;

	status = cerberus.test.base.parse_message (&cerberus.test.base, NULL, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, true, message.crypto_timeout);

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_short_message (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (*header) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header) - 1, message.payload_length);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_reserved1_not_zero (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 7;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

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

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_reserved2_not_zero (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 1;
	header->rq = 0;
	header->command = 0x12;

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

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_encrypted (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 1;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = false;
	message.crypto_timeout = true;
	message.channel_id = 4;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_ENCRYPTION_UNSUPPORTED, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_parse_message_invalid_mctp_header (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	/* TODO:  The test case will eventually not be possible and will get removed. */

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x12;

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

	/* Invalid message type. */
	header->msg_type = 0x2b;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	/* Integrity check bit set. */
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 1;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	/* Invalid PCI vendor ID. */
	header->integrity_check = 0;
	header->pci_vendor_id = 0x1234;

	status = cerberus.test.base.parse_message (&cerberus.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 1;
	header->command = 0x12;

	/* TODO:  Input should be a payload offset past the MCTP header. */
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

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
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

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, message_type, header->command);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 9;
	struct cerberus_protocol_header *header =
		(struct cerberus_protocol_header*) &data[payload_offset];
	int status;
	uint32_t message_type = 0x84;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 0;
	header->command = 0x12;

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

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
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

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 0, header->rq);
	CuAssertIntEquals (test, 0x84, header->command);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_encrypted (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x39;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 1;
	header->command = 0x12;

	/* TODO:  Input should be a payload with header space removed. */
	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x39, header->command);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_success_no_payload (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	error->header.msg_type = 0x45;
	error->header.integrity_check = 1;
	error->header.pci_vendor_id = 0x1234;
	error->header.reserved1 = 3;
	error->header.crypt = 1;
	error->header.reserved2 = 1;
	error->header.rq = 0;
	error->header.command = 0x12;
	error->error_code = 0x34;
	error->error_data = 0x56;

	/* TODO:  Input should be a payload offset past the MCTP header. */
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

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (*error), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x1414, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, 0, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_success_no_payload_encrypted
(
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	error->header.msg_type = 0x45;
	error->header.integrity_check = 1;
	error->header.pci_vendor_id = 0x1234;
	error->header.reserved1 = 3;
	error->header.crypt = 1;
	error->header.reserved2 = 1;
	error->header.rq = 1;
	error->header.command = 0x12;
	error->error_code = 0x34;
	error->error_data = 0x56;

	/* TODO:  Input should be a payload offset past the MCTP header. */
	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = 0;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (*error), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x1414, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, 0, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_success_zero_data_length (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	error->header.msg_type = 0x45;
	error->header.integrity_check = 1;
	error->header.pci_vendor_id = 0x1234;
	error->header.reserved1 = 3;
	error->header.crypt = 1;
	error->header.reserved2 = 1;
	error->header.rq = 0;
	error->header.command = 0x12;
	error->error_code = 0x34;
	error->error_data = 0x56;

	/* TODO:  Input should be a payload offset past the MCTP header. */
	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = 0;
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (*error), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x1414, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, 0, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x23;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CERBERUS_REQUEST_FAIL,
		.arg1 = 0x04230a07,
		.arg2 = CMD_HANDLER_PROCESS_FAILED
	};

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 0;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 7;

	status = mock_expect (&cerberus.log.mock, cerberus.log.base.create_entry, &cerberus.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	CuAssertIntEquals (test, 0, status);

	status = cerberus.test.base.handle_request_result (&cerberus.test.base,
		CMD_HANDLER_PROCESS_FAILED, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (*error), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 7, message.channel_id);

	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x1414, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, error->error_data);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_request_failure_cmd_set_1 (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x23;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CERBERUS_REQUEST_FAIL,
		.arg1 = 0x04230a07,
		.arg2 = CMD_HANDLER_PROCESS_FAILED
	};

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 1;
	header->command = 0x12;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 7;

	status = mock_expect (&cerberus.log.mock, cerberus.log.base.create_entry, &cerberus.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	CuAssertIntEquals (test, 0, status);

	status = cerberus.test.base.handle_request_result (&cerberus.test.base,
		CMD_HANDLER_PROCESS_FAILED, message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (*error), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 7, message.channel_id);

	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x1414, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, error->error_data);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_static_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_static_init
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init_dependencies (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 1;
	header->command = 0x12;

	/* TODO:  Input should be a payload with header space removed. */
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

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type,
		&message);
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

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, header->reserved1);
	CuAssertIntEquals (test, 0, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x56, header->command);

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_test_handle_request_result_null (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_testing_init (test, &cerberus);

	header->msg_type = 0x45;
	header->integrity_check = 1;
	header->pci_vendor_id = 0x1234;
	header->reserved1 = 3;
	header->crypt = 1;
	header->reserved2 = 1;
	header->rq = 1;
	header->command = 0x12;

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

	status = cerberus.test.base.handle_request_result (NULL, 0, message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cerberus.test.base.handle_request_result (&cerberus.test.base, 0, message_type, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

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

	cmd_interface_protocol_cerberus_testing_release (test, &cerberus);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_protocol_cerberus);

TEST (cmd_interface_protocol_cerberus_test_init);
TEST (cmd_interface_protocol_cerberus_test_init_null);
TEST (cmd_interface_protocol_cerberus_test_static_init);
TEST (cmd_interface_protocol_cerberus_test_release_null);
TEST (cmd_interface_protocol_cerberus_test_parse_message);
TEST (cmd_interface_protocol_cerberus_test_parse_message_payload_offset);
TEST (cmd_interface_protocol_cerberus_test_parse_message_minimum_length);
TEST (cmd_interface_protocol_cerberus_test_parse_message_static_init);
TEST (cmd_interface_protocol_cerberus_test_parse_message_null);
TEST (cmd_interface_protocol_cerberus_test_parse_message_short_message);
TEST (cmd_interface_protocol_cerberus_test_parse_message_reserved1_not_zero);
TEST (cmd_interface_protocol_cerberus_test_parse_message_reserved2_not_zero);
TEST (cmd_interface_protocol_cerberus_test_parse_message_encrypted);
TEST (cmd_interface_protocol_cerberus_test_parse_message_invalid_mctp_header);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_payload_offset);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_encrypted);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_success_no_payload);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_success_no_payload_encrypted);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_success_zero_data_length);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_request_failure);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_request_failure_cmd_set_1);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_static_init);
TEST (cmd_interface_protocol_cerberus_test_handle_request_result_null);

TEST_SUITE_END;
// *INDENT-ON*
