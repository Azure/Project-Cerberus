// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_interface_protocol_cerberus_secure.h"
#include "cmd_interface/cmd_interface_protocol_cerberus_secure_static.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/session_manager_mock.h"


TEST_SUITE_LABEL ("cmd_interface_protocol_cerberus_secure");


/**
 * Dependencies for testing the secure Cerberus protocol handler.
 */
struct cmd_interface_protocol_cerberus_secure_testing {
	struct session_manager_mock session;				/**< Mock for the session manager. */
	struct cmd_interface_protocol_cerberus_secure test;	/**< The protocol handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param cerberus Testing dependencies to initialize.
 */
static void cmd_interface_protocol_cerberus_secure_testing_init_dependencies (CuTest *test,
	struct cmd_interface_protocol_cerberus_secure_testing *cerberus)
{
	int status;

	status = session_manager_mock_init (&cerberus->session);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param cerberus Testing dependencies to release.
 */
static void cmd_interface_protocol_cerberus_secure_testing_release_dependencies (CuTest *test,
	struct cmd_interface_protocol_cerberus_secure_testing *cerberus)
{
	int status;

	status = session_manager_mock_validate_and_release (&cerberus->session);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a secure Cerberus protocol handler for testing.
 *
 * @param test The test framework.
 * @param cerberus Testing dependencies to initialize.
 */
static void cmd_interface_protocol_cerberus_secure_testing_init (CuTest *test,
	struct cmd_interface_protocol_cerberus_secure_testing *cerberus)
{
	int status;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, cerberus);

	status = cmd_interface_protocol_cerberus_secure_init (&cerberus->test, &cerberus->session.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release secure Cerberus protocol test components and validate all mocks.
 *
 * @param test The test framework.
 * @param cerberus Testing dependencies to release.
 */
static void cmd_interface_protocol_cerberus_secure_testing_release (CuTest *test,
	struct cmd_interface_protocol_cerberus_secure_testing *cerberus)
{
	cmd_interface_protocol_cerberus_secure_release (&cerberus->test);
	cmd_interface_protocol_cerberus_secure_testing_release_dependencies (test, cerberus);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_cerberus_secure_test_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	int status;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

	status = cmd_interface_protocol_cerberus_secure_init (&cerberus.test, &cerberus.session.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, cerberus.test.base.base.parse_message);
	CuAssertPtrNotNull (test, cerberus.test.base.base.handle_request_result);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_init_null (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	int status;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

	status = cmd_interface_protocol_cerberus_secure_init (NULL, &cerberus.session.base);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_protocol_cerberus_secure_init (&cerberus.test, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_protocol_cerberus_secure_testing_release_dependencies (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_secure_static_init (&cerberus.session.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, cerberus.test.base.base.parse_message);
	CuAssertPtrNotNull (test, cerberus.test.base.base.handle_request_result);

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_cerberus_secure_release (NULL);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct cerberus_protocol_header *header =
		(struct cerberus_protocol_header*) &data[payload_offset];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_minimum_length (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_encrypted (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg decrypted;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Encrypted message. */
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
	message.channel_id = 4;

	/* Decrypted message. */
	header = (struct cerberus_protocol_header*) decrypted_data;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 1;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x75;

	memset (&decrypted, 0, sizeof (decrypted));
	decrypted.data = decrypted_data;
	decrypted.length = sizeof (decrypted_data);
	decrypted.max_response = sizeof (decrypted_data);
	decrypted.payload = decrypted_data;
	decrypted.payload_length = sizeof (decrypted_data);
	decrypted.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted.source_addr = 0x55;
	decrypted.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	decrypted.is_encrypted = true;
	decrypted.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.decrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &decrypted,
		sizeof (decrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x75, message_type);

	/* TODO:  Remove protocol header during processing. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data) - SESSION_MANAGER_TRAILER_LEN, message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_encrypted_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct cerberus_protocol_header *header =
		(struct cerberus_protocol_header*) &data[payload_offset];
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg decrypted;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Encrypted message. */
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
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = 0x11;
	message.source_addr = 0x65;
	message.target_eid = 0x22;
	message.channel_id = 7;

	/* Decrypted message. */
	header = (struct cerberus_protocol_header*) &decrypted_data[payload_offset];;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 1;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x57;

	memset (&decrypted, 0, sizeof (decrypted));
	decrypted.data = decrypted_data;
	decrypted.length = sizeof (decrypted_data);
	decrypted.max_response = sizeof (decrypted_data);
	decrypted.payload = &decrypted_data[payload_offset];
	decrypted.payload_length = sizeof (decrypted_data) - payload_offset;
	decrypted.source_eid = 0x11;
	decrypted.source_addr = 0x65;
	decrypted.target_eid = 0x22;
	decrypted.is_encrypted = true;
	decrypted.channel_id = 7;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.decrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &decrypted,
		sizeof (decrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x57, message_type);

	/* TODO:  Remove protocol header during processing. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data) - SESSION_MANAGER_TRAILER_LEN, message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);
	CuAssertIntEquals (test, 0x11, message.source_eid);
	CuAssertIntEquals (test, 0x65, message.source_addr);
	CuAssertIntEquals (test, 0x22, message.target_eid);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 7, message.channel_id);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_secure_static_init (&cerberus.session.base)
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_static_init_encrypted (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_secure_static_init (&cerberus.session.base)
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	uint8_t decrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg decrypted;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

	/* Encrypted message. */
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
	message.channel_id = 4;

	/* Decrypted message. */
	header = (struct cerberus_protocol_header*) decrypted_data;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 1;
	header->reserved2 = 0;
	header->rq = 0;
	header->command = 0x75;

	memset (&decrypted, 0, sizeof (decrypted));
	decrypted.data = decrypted_data;
	decrypted.length = sizeof (decrypted_data);
	decrypted.max_response = sizeof (decrypted_data);
	decrypted.payload = decrypted_data;
	decrypted.payload_length = sizeof (decrypted_data);
	decrypted.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	decrypted.source_addr = 0x55;
	decrypted.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	decrypted.is_encrypted = true;
	decrypted.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.decrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &decrypted,
		sizeof (decrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x75, message_type);

	/* TODO:  Remove protocol header during processing. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data) - SESSION_MANAGER_TRAILER_LEN, message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (NULL, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);

	message.crypto_timeout = true;

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, NULL,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, true, message.crypto_timeout);

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, true, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_short_message (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header) - 1, message.payload_length);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_reserved1_not_zero (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_reserved2_not_zero (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_RSVD_NOT_ZERO, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_invalid_mctp_header (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	/* TODO:  The test case will eventually not be possible and will get removed. */

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	/* Integrity check bit set. */
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 1;

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	/* Invalid PCI vendor ID. */
	header->integrity_check = 0;
	header->pci_vendor_id = 0x1234;

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_parse_message_decrypt_fail (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Encrypted message. */
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
	message.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.decrypt_message,
		&cerberus.session, SESSION_MANAGER_DECRYPT_MSG_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	status = cerberus.test.base.base.parse_message (&cerberus.test.base.base, &message,
		&message_type);
	CuAssertIntEquals (test, SESSION_MANAGER_DECRYPT_MSG_FAILED, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 9;
	struct cerberus_protocol_header *header =
		(struct cerberus_protocol_header*) &data[payload_offset];
	int status;
	uint32_t message_type = 0x84;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_encrypted (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg encrypted;
	int status;
	uint32_t message_type = 0x39;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Plaintext message after Cerberus handling. */
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x39;

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

	/* Encrypted message. */
	header = (struct cerberus_protocol_header*) encrypted_data;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x75;

	memset (&encrypted, 0, sizeof (encrypted));
	encrypted.data = encrypted_data;
	encrypted.length = sizeof (encrypted_data);
	encrypted.max_response = sizeof (encrypted_data);
	encrypted.payload = encrypted_data;
	encrypted.payload_length = sizeof (encrypted_data);
	encrypted.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted.source_addr = 0x55;
	encrypted.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	encrypted.is_encrypted = true;
	encrypted.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.encrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &encrypted,
		sizeof (encrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Input message. */
	header = (struct cerberus_protocol_header*) data;

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
	message.max_response = sizeof (data) - SESSION_MANAGER_TRAILER_LEN;
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x75, header->command);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_encrypted_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 9;
	struct cerberus_protocol_header *header =
		(struct cerberus_protocol_header*) &data[payload_offset];
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg encrypted;
	int status;
	uint32_t message_type = 0x39;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Plaintext message after Cerberus handling. */
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x39;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	/* Encrypted message. */
	header = (struct cerberus_protocol_header*) &encrypted_data[payload_offset];

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x75;

	memset (&encrypted, 0, sizeof (encrypted));
	encrypted.data = encrypted_data;
	encrypted.length = sizeof (encrypted_data);
	encrypted.max_response = sizeof (encrypted_data);
	encrypted.payload = &encrypted_data[payload_offset];
	encrypted.payload_length = sizeof (encrypted_data) - payload_offset;
	encrypted.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted.source_addr = 0x55;
	encrypted.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	encrypted.is_encrypted = true;
	encrypted.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.encrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &encrypted,
		sizeof (encrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Input message. */
	header = (struct cerberus_protocol_header*) &data[payload_offset];

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
	message.max_response = sizeof (data) - SESSION_MANAGER_TRAILER_LEN;
	message.payload = &data[payload_offset];
	message.payload_length = sizeof (data) - payload_offset;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);
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
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x75, header->command);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_success_no_payload (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_success_no_payload_encrypted (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg encrypted;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Plaintext message after Cerberus handling. */
	error->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.integrity_check = 0;
	error->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	error->header.reserved1 = 0;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.rq = 0;
	error->header.command = 0x7f;
	error->error_code = 0;
	error->error_data = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (*error);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (*error);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	/* Encrypted message. */
	error = (struct cerberus_protocol_error*) encrypted_data;

	error->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.integrity_check = 0;
	error->header.pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	error->header.reserved1 = 0;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.rq = 0;
	error->header.command = 0x86;
	error->error_code = 0x98;
	error->error_data = 0x12349876;

	memset (&encrypted, 0, sizeof (encrypted));
	encrypted.data = encrypted_data;
	encrypted.length = sizeof (*error);
	encrypted.max_response = sizeof (encrypted_data);
	encrypted.payload = encrypted_data;
	encrypted.payload_length = sizeof (*error);
	encrypted.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted.source_addr = 0x55;
	encrypted.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	encrypted.is_encrypted = true;
	encrypted.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.encrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &encrypted,
		sizeof (encrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Input message data. */
	error = (struct cerberus_protocol_error*) data;

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
	message.max_response = sizeof (data) - SESSION_MANAGER_TRAILER_LEN;
	message.payload = data;
	message.payload_length = 0;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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
	CuAssertIntEquals (test, 1, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, 0x86, error->header.command);
	CuAssertIntEquals (test, 0x98, error->error_code);
	CuAssertIntEquals (test, 0x12349876, error->error_data);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_success_zero_data_length (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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
	message.length = 0;
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x23;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base,
		CMD_HANDLER_PROCESS_FAILED, message_type, &message);
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

	CuAssertIntEquals (test, 0x45, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);
	CuAssertIntEquals (test, 0x1234, header->pci_vendor_id);
	CuAssertIntEquals (test, 3, header->reserved1);
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 1, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x12, header->command);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_static_init (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_secure_static_init (&cerberus.session.base)
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

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

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_static_init_encrypted (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus = {
		.test = cmd_interface_protocol_cerberus_secure_static_init (&cerberus.session.base)
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	uint8_t encrypted_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg encrypted;
	int status;
	uint32_t message_type = 0x39;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init_dependencies (test, &cerberus);

	/* Plaintext message after Cerberus handling. */
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x39;

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

	/* Encrypted message. */
	header = (struct cerberus_protocol_header*) encrypted_data;

	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x75;

	memset (&encrypted, 0, sizeof (encrypted));
	encrypted.data = encrypted_data;
	encrypted.length = sizeof (encrypted_data);
	encrypted.max_response = sizeof (encrypted_data);
	encrypted.payload = encrypted_data;
	encrypted.payload_length = sizeof (encrypted_data);
	encrypted.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	encrypted.source_addr = 0x55;
	encrypted.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	encrypted.is_encrypted = true;
	encrypted.channel_id = 4;

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.encrypt_message,
		&cerberus.session, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));
	status |= mock_expect_output_deep_copy (&cerberus.session.mock, 0, &encrypted,
		sizeof (encrypted), cmd_interface_mock_copy_request);

	CuAssertIntEquals (test, 0, status);

	/* Input message. */
	header = (struct cerberus_protocol_header*) data;

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
	message.max_response = sizeof (data) - SESSION_MANAGER_TRAILER_LEN;
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
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
	CuAssertIntEquals (test, 1, header->crypt);
	CuAssertIntEquals (test, 0, header->reserved2);
	CuAssertIntEquals (test, 1, header->rq);
	CuAssertIntEquals (test, 0x75, header->command);

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_null (CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x56;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

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

	status = cerberus.test.base.base.handle_request_result (NULL, 0, message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, NULL);
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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}

static void cmd_interface_protocol_cerberus_secure_test_handle_request_result_encrypt_fail (
	CuTest *test)
{
	struct cmd_interface_protocol_cerberus_secure_testing cerberus;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_header *header = (struct cerberus_protocol_header*) data;
	int status;
	uint32_t message_type = 0x39;

	TEST_START;

	cmd_interface_protocol_cerberus_secure_testing_init (test, &cerberus);

	/* Plaintext message after Cerberus handling. */
	header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	header->integrity_check = 0;
	header->pci_vendor_id = CERBERUS_PROTOCOL_MSFT_PCI_VID;
	header->reserved1 = 0;
	header->crypt = 0;
	header->reserved2 = 0;
	header->rq = 1;
	header->command = 0x39;

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

	status = mock_expect (&cerberus.session.mock, cerberus.session.base.encrypt_message,
		&cerberus.session, SESSION_MANAGER_ENCRYPT_MSG_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, &message,
			sizeof (message), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
			cmd_interface_mock_duplicate_request));

	CuAssertIntEquals (test, 0, status);

	/* Input message. */
	header = (struct cerberus_protocol_header*) data;

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
	message.max_response = sizeof (data) - SESSION_MANAGER_TRAILER_LEN;
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.is_encrypted = true;
	message.channel_id = 4;

	status = cerberus.test.base.base.handle_request_result (&cerberus.test.base.base, 0,
		message_type, &message);
	CuAssertIntEquals (test, SESSION_MANAGER_ENCRYPT_MSG_FAILED, status);

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

	cmd_interface_protocol_cerberus_secure_testing_release (test, &cerberus);
}


TEST_SUITE_START (cmd_interface_protocol_cerberus_secure);

TEST (cmd_interface_protocol_cerberus_secure_test_init);
TEST (cmd_interface_protocol_cerberus_secure_test_init_null);
TEST (cmd_interface_protocol_cerberus_secure_test_static_init);
TEST (cmd_interface_protocol_cerberus_secure_test_release_null);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_payload_offset);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_minimum_length);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_encrypted);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_encrypted_payload_offset);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_static_init);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_static_init_encrypted);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_null);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_short_message);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_reserved1_not_zero);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_reserved2_not_zero);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_invalid_mctp_header);
TEST (cmd_interface_protocol_cerberus_secure_test_parse_message_decrypt_fail);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_payload_offset);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_encrypted);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_encrypted_payload_offset);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_success_no_payload);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_success_no_payload_encrypted);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_success_zero_data_length);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_request_failure);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_static_init);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_static_init_encrypted);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_null);
TEST (cmd_interface_protocol_cerberus_secure_test_handle_request_result_encrypt_fail);

TEST_SUITE_END;
