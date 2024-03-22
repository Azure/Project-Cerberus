// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "mctp/cmd_interface_protocol_mctp_msft_vdm.h"
#include "mctp/cmd_interface_protocol_mctp_msft_vdm_static.h"
#include "mctp/mctp_base_protocol.h"


TEST_SUITE_LABEL ("cmd_interface_protocol_mctp_msft_vdm");


/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_mctp_msft_vdm_test_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	int status;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, mctp.base.parse_message);
	CuAssertPtrNotNull (test, mctp.base.handle_request_result);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp =
		cmd_interface_protocol_mctp_msft_vdm_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, mctp.base.parse_message);
	CuAssertPtrNotNull (test, mctp.base.handle_request_result);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_release (NULL);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, 0, message_type);

	/* TODO:  Update the payload to point to the Microsoft message header. */
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

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_payload_offset (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[payload_offset + sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 1;

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
	CuAssertIntEquals (test, 1, message_type);

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

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_minimum_length (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (*header) + sizeof (*msft_header);
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, message_type);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header) + sizeof (*msft_header), message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp =
		cmd_interface_protocol_mctp_msft_vdm_static_init;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, 0, message_type);

	/* TODO:  Update the payload to point to the Microsoft message header. */
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

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp.base.parse_message (&mctp.base, NULL, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp.base.parse_message (&mctp.base, &message, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_short_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (*header) + sizeof (*msft_header) - 1;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.base.parse_message (&mctp.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header) + sizeof (*msft_header) - 1, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_mctp_message_type (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x4e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_with_integrity_check (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_vendor_id (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1413;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type = 0;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x13;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	msft_header->rq = 1;

	/* TODO:  The input should have the payload after the MCTP VDM header. */
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

	status = mctp.base.handle_request_result (&mctp.base, 0, message_type, &message);
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

	CuAssertIntEquals (test, 0x7e, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1414, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 9;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[payload_offset + sizeof (*header)];
	int status;
	uint32_t message_type = 1;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x27;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	msft_header->rq = 0;

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

	status = mctp.base.handle_request_result (&mctp.base, 0, message_type, &message);
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

	CuAssertIntEquals (test, 0x7e, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1414, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type = 0;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x13;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	msft_header->rq = 1;

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

	status = mctp.base.handle_request_result (&mctp.base, CMD_HANDLER_PROCESS_FAILED, message_type,
		&message);
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

	CuAssertIntEquals (test, 0x13, header->msg_header.msg_type);
	CuAssertIntEquals (test, 1, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1234, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_static_init (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp =
		cmd_interface_protocol_mctp_msft_vdm_static_init;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type = 0;

	TEST_START;

	header->msg_header.msg_type = 0x13;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	msft_header->rq = 1;

	/* TODO:  The input should have the payload after the MCTP VDM header. */
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

	status = mctp.base.handle_request_result (&mctp.base, 0, message_type, &message);
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

	CuAssertIntEquals (test, 0x7e, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1414, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x13;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = &data[3];
	message.payload_length = sizeof (data) - 3;
	message.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	message.source_addr = 0x55;
	message.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	message.channel_id = 4;

	status = mctp.base.handle_request_result (NULL, 0, message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp.base.handle_request_result (&mctp.base, 0, message_type, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[3], message.payload);
	CuAssertIntEquals (test, message.length - 3, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_msft_vdm_release (&mctp);
}


TEST_SUITE_START (cmd_interface_protocol_mctp_msft_vdm);

TEST (cmd_interface_protocol_mctp_msft_vdm_test_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_init_null);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_static_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_release_null);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_payload_offset);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_minimum_length);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_static_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_null);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_short_message);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_mctp_message_type);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_with_integrity_check);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_vendor_id);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_payload_offset);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_request_failure);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_static_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_null);

TEST_SUITE_END;
