// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_logging.h"
#include "mctp/cmd_interface_protocol_mctp_msft_vdm.h"
#include "mctp/cmd_interface_protocol_mctp_msft_vdm_static.h"
#include "mctp/mctp_base_protocol.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/mock/logging/logging_mock.h"


TEST_SUITE_LABEL ("cmd_interface_protocol_mctp_msft_vdm");


/**
 * Dependencies for testing the protocol handler for Microsoft MCTP vendor defined messages.
 */
struct cmd_interface_protocol_mctp_msft_vdm_testing {
	struct device_manager device_mgr;						/**< Device manager. */
	struct logging_mock log;								/**< Mock for the debug log. */
	struct cmd_interface_protocol_mctp_msft_vdm test;		/**< Protocol handler being tested. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to initialize.
 */
static void cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (CuTest *test,
	struct cmd_interface_protocol_mctp_msft_vdm_testing *mctp)
{
	int status;

	status = logging_mock_init (&mctp->log);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&mctp->device_mgr, 2, 0, 0, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x51, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	debug_log = &mctp->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to release.
 */
static void cmd_interface_protocol_mctp_msft_vdm_testing_release_dependencies (CuTest *test,
	struct cmd_interface_protocol_mctp_msft_vdm_testing *mctp)
{
	int status;

	debug_log = NULL;

	status = logging_mock_validate_and_release (&mctp->log);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&mctp->device_mgr);
}

/**
 * Initialize a MSFT VDM protocol handler for testing.
 *
 * @param test The test framework.
 * @param mctp Testing components to initialize.
 */
static void cmd_interface_protocol_mctp_msft_vdm_testing_init (CuTest *test,
	struct cmd_interface_protocol_mctp_msft_vdm_testing *mctp)
{
	int status;

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, mctp);

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp->test, &mctp->device_mgr);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release MSFT VDM protocol test components and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing components to release.
 */
static void cmd_interface_protocol_mctp_msft_vdm_testing_release (CuTest *test,
	struct cmd_interface_protocol_mctp_msft_vdm_testing *mctp)
{
	cmd_interface_protocol_mctp_msft_vdm_release (&mctp->test);
	cmd_interface_protocol_mctp_msft_vdm_testing_release_dependencies (test, mctp);
}


/*******************
 * Test cases
 *******************/

static void cmd_interface_protocol_mctp_msft_vdm_test_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	int status;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, &mctp);

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp.test, &mctp.device_mgr);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, mctp.test.base.parse_message);
	CuAssertPtrNotNull (test, mctp.test.base.handle_request_result);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_init_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	int status;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, &mctp);

	status = cmd_interface_protocol_mctp_msft_vdm_init (NULL, &mctp.device_mgr);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = cmd_interface_protocol_mctp_msft_vdm_init (&mctp.test, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	cmd_interface_protocol_mctp_msft_vdm_testing_release_dependencies (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp = {
		.test = cmd_interface_protocol_mctp_msft_vdm_static_init (&mctp.device_mgr)
	};

	TEST_START;

	CuAssertPtrNotNull (test, mctp.test.base.parse_message);
	CuAssertPtrNotNull (test, mctp.test.base.handle_request_result);

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, &mctp);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_release (NULL);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_payload_offset (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 6;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[payload_offset + sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_minimum_length (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_capabilites (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	struct device_manager_full_capabilities capabilities;
	size_t max_packet = 128;
	size_t max_message = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 2;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, message_type);

	/* TODO:  Update the payload to point to the Microsoft message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, max_message, message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_capabilites_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	struct device_manager_full_capabilities capabilities;
	size_t max_packet = 128;
	size_t max_message = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 2;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 10;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[payload_offset + sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, message_type);

	/* TODO:  Update the payload to point to the Microsoft message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, max_message + payload_offset, message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_buffer_size (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	struct device_manager_full_capabilities capabilities;
	size_t max_packet = 128;
	size_t max_message = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 2;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 4] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_buffer_size_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	struct device_manager_full_capabilities capabilities;
	size_t max_packet = 128;
	size_t max_message = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 2;
	uint8_t data[(MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 2) + 15] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 16;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[payload_offset + sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	header->msg_header.msg_type = 0x7e;
	header->msg_header.integrity_check = 0;
	header->pci_vendor_id = 0x1414;

	msft_header->rq = 0;

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
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, message_type);

	/* TODO:  Update the payload to point to the Microsoft message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, &message.data[payload_offset], message.payload);
	CuAssertIntEquals (test, message.length - payload_offset, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_static_init (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp = {
		.test = cmd_interface_protocol_mctp_msft_vdm_static_init (&mctp.device_mgr)
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_static_init_response_limit_by_capabilites (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp = {
		.test = cmd_interface_protocol_mctp_msft_vdm_static_init (&mctp.device_mgr)
	};
	struct device_manager_full_capabilities capabilities;
	size_t max_packet = 128;
	size_t max_message = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY / 2;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, &mctp);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, message_type);

	/* TODO:  Update the payload to point to the Microsoft message header. */
	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertIntEquals (test, max_message, message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 4, message.channel_id);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (NULL, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp.test.base.parse_message (&mctp.test.base, NULL, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp.test.base.parse_message (&mctp.test.base, &message, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_short_message (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_PAYLOAD_TOO_SHORT, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, sizeof (*header) + sizeof (*msft_header) - 1, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_mctp_message_type (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_with_integrity_check (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_vendor_id (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.parse_message (&mctp.test.base, &message, &message_type);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (data), message.length);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type = 0;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	CuAssertIntEquals (test, 0x7e, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1414, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_payload_offset (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	size_t payload_offset = 9;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) &data[payload_offset];
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[payload_offset + sizeof (*header)];
	int status;
	uint32_t message_type = 1;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	CuAssertIntEquals (test, 0x7e, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1414, header->pci_vendor_id);
	CuAssertIntEquals (test, 1, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_success_no_payload (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_success_zero_data_length (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 1;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, &message);
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
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, 0, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_request_failure (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 0;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CERBERUS_REQUEST_FAIL,
		.arg1 = 0x04840a07,
		.arg2 = CMD_HANDLER_PROCESS_FAILED
	};

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

	header->msg_header.msg_type = 0x13;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	msft_header->rq = 1;
	msft_header->command = 0x84;

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

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.handle_request_result (&mctp.test.base, CMD_HANDLER_PROCESS_FAILED,
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_request_failure_type_1 (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) data;
	int status;
	uint32_t message_type = 1;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_CMD_INTERFACE,
		.msg_index = CMD_LOGGING_CERBERUS_REQUEST_FAIL,
		.arg1 = 0x04144502,
		.arg2 = CMD_HANDLER_UNKNOWN_REQUEST
	};

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

	header->msg_header.msg_type = 0x13;
	header->msg_header.integrity_check = 1;
	header->pci_vendor_id = 0x1234;

	msft_header->command = 0x14;

	memset (&message, 0, sizeof (message));
	message.data = data;
	message.length = sizeof (data);
	message.max_response = sizeof (data);
	message.payload = data;
	message.payload_length = sizeof (data);
	message.source_eid = 0x45;
	message.source_addr = 0x55;
	message.target_eid = 0x54;
	message.channel_id = 2;

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.handle_request_result (&mctp.test.base, CMD_HANDLER_UNKNOWN_REQUEST,
		message_type, &message);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, message.data);
	CuAssertIntEquals (test, sizeof (*error), message.length);
	CuAssertIntEquals (test, sizeof (data), message.max_response);
	CuAssertPtrEquals (test, message.data, message.payload);
	CuAssertIntEquals (test, message.length, message.payload_length);
	CuAssertIntEquals (test, 0x45, message.source_eid);
	CuAssertIntEquals (test, 0x55, message.source_addr);
	CuAssertIntEquals (test, 0x54, message.target_eid);
	CuAssertIntEquals (test, false, message.is_encrypted);
	CuAssertIntEquals (test, false, message.crypto_timeout);
	CuAssertIntEquals (test, 2, message.channel_id);

	CuAssertIntEquals (test, 0x7e, error->header.msg_type);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0x1414, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, 0x7f, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_REQUEST, error->error_data);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_static_init (
	CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp = {
		.test = cmd_interface_protocol_mctp_msft_vdm_static_init (&mctp.device_mgr)
	};
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	struct cerberus_protocol_msft_header *msft_header =
		(struct cerberus_protocol_msft_header*) &data[sizeof (*header)];
	int status;
	uint32_t message_type = 0;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init_dependencies (test, &mctp);

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

	CuAssertIntEquals (test, 0x7e, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x1414, header->pci_vendor_id);
	CuAssertIntEquals (test, 0, msft_header->rq);

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}

static void cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_null (CuTest *test)
{
	struct cmd_interface_protocol_mctp_msft_vdm_testing mctp;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg message;
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) data;
	int status;
	uint32_t message_type = 0x76;

	TEST_START;

	cmd_interface_protocol_mctp_msft_vdm_testing_init (test, &mctp);

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

	status = mctp.test.base.handle_request_result (NULL, 0, message_type, &message);
	CuAssertIntEquals (test, CMD_HANDLER_INVALID_ARGUMENT, status);

	status = mctp.test.base.handle_request_result (&mctp.test.base, 0, message_type, NULL);
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

	cmd_interface_protocol_mctp_msft_vdm_testing_release (test, &mctp);
}


TEST_SUITE_START (cmd_interface_protocol_mctp_msft_vdm);

TEST (cmd_interface_protocol_mctp_msft_vdm_test_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_init_null);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_static_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_release_null);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_payload_offset);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_minimum_length);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_capabilites);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_capabilites_payload_offset);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_buffer_size);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_response_limit_by_buffer_size_payload_offset);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_static_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_static_init_response_limit_by_capabilites);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_null);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_short_message);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_mctp_message_type);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_with_integrity_check);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_parse_message_wrong_vendor_id);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_payload_offset);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_success_no_payload);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_success_zero_data_length);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_request_failure);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_request_failure_type_1);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_static_init);
TEST (cmd_interface_protocol_mctp_msft_vdm_test_handle_request_result_null);

TEST_SUITE_END;
