// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "mctp/cmd_interface_protocol_mctp_vdm_pci.h"
#include "mctp/cmd_interface_protocol_mctp_vdm_pci_static.h"
#include "mctp/mctp_base_protocol.h"


TEST_SUITE_LABEL ("cmd_interface_protocol_mctp_vdm_pci");


/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_mctp_vdm_pci_test_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	int status;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, mctp.base.parse_message);
	CuAssertPtrEquals (test, NULL, mctp.base.handle_request_result);

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp =
		cmd_interface_protocol_mctp_vdm_pci_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, mctp.base.parse_message);
	CuAssertPtrEquals (test, NULL, mctp.base.handle_request_result);

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_mctp_vdm_pci_release (NULL);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1234, message_type);

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

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_payload_offset (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x5487;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x5487, message_type);

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

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_minimum_length (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1234, message_type);

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

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_with_integrity_check (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1234, message_type);

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

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp =
		cmd_interface_protocol_mctp_vdm_pci_static_init;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1234, message_type);

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

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (NULL, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp.base.parse_message (&mctp.base, NULL, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp.base.parse_message (&mctp.base, &message, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_short_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header) - 1, message.payload_length);

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}

static void cmd_interface_protocol_mctp_vdm_pci_test_parse_message_wrong_mctp_message_type (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_vdm_pci mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_vdm_pci_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x77;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1234;

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

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_vdm_pci_release (&mctp);
}


TEST_SUITE_START (cmd_interface_protocol_mctp_vdm_pci);

TEST (cmd_interface_protocol_mctp_vdm_pci_test_init);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_init_null);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_static_init);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_release_null);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_payload_offset);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_minimum_length);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_with_integrity_check);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_static_init);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_null);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_short_message);
TEST (cmd_interface_protocol_mctp_vdm_pci_test_parse_message_wrong_mctp_message_type);

TEST_SUITE_END;
