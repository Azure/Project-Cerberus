// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "platform.h"
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cmd_interface_system.h"
#include "mctp/mctp_interface.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "common/unused.h"
#include "crypto/checksum.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"


TEST_SUITE_LABEL ("mctp_interface");


/**
 * Length of the MCTP header.
 */
#define	MCTP_HEADER_LENGTH		7

/**
 * Length of an MCTP error message.
 */
#define	MCTP_ERROR_MSG_LENGTH	(MCTP_HEADER_LENGTH + sizeof (struct cerberus_protocol_error) + 1)


/**
 * Dependencies for testing the MCTP interface.
 */
struct mctp_interface_testing {
	struct cmd_channel_mock channel;				/**< Command channel mock instance. */
	struct cmd_interface_mock cmd_cerberus;			/**< Cerberus protocol command interface mock instance. */
	struct cmd_interface_mock cmd_mctp;				/**< MCTP control protocol command interface mock instance. */
	struct device_manager device_mgr;				/**< Device manager. */
	struct mctp_interface mctp;						/**< MCTP interface instance */
};

/**
 * Response callback context.
 */
struct mctp_interface_test_callback_context {
	struct mctp_interface_testing *testing;			/**< Testing instances to utilize. */
	struct cmd_packet *rsp_packet;					/**< Response packet to send back. */
	CuTest *test;									/**< Test framework. */
	int expected_status;							/**< Expected process_packet completion status. */
};


/**
 * Helper function to setup the MCTP interface to use mock instances
 *
 * @param test The test framework.
 * @param mctp The instances to initialize for testing.
 */
static void setup_mctp_interface_with_interface_mock_test (CuTest *test,
	struct mctp_interface_testing *mctp)
{
	struct device_manager_full_capabilities capabilities;
	int status;

	status = cmd_interface_mock_init (&mctp->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&mctp->cmd_mctp);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&mctp->device_mgr, 2, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&mctp->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&mctp->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp->device_mgr, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;

	status = device_manager_update_device_capabilities (&mctp->device_mgr, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp->mctp, &mctp->cmd_cerberus.base, &mctp->cmd_mctp.base,
		&mctp->device_mgr);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_init (&mctp->channel, 0);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to complete MCTP test
 *
 * @param test The test framework.
 * @param mctp The instances to release.
 */
static void complete_mctp_interface_with_interface_mock_test (CuTest *test,
	struct mctp_interface_testing *mctp)
{
	int status;

	status = cmd_interface_mock_validate_and_release (&mctp->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&mctp->cmd_mctp);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&mctp->channel);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&mctp->device_mgr);
	mctp_interface_deinit (&mctp->mctp);
}

/**
 * Callback function which sends an MCTP response message to process_packet
 *
 * @param expected The expectation that is being used to validate the current call on the mock.
 * @param called The context for the actual call on the mock.
 *
 * @return This function always returns 0
 */
static intptr_t mctp_interface_testing_process_packet_callback (const struct mock_call *expected,
	const struct mock_call *called)
{
	struct mctp_interface_test_callback_context *context = expected->context;
	struct cmd_message *tx;
	int status;

	UNUSED (called);

	status = mctp_interface_process_packet (&context->testing->mctp, context->rsp_packet, &tx);
	CuAssertIntEquals (context->test, context->expected_status, status);

	return 0;
}

/**
 * Helper function that generates an MCTP request and calls issue_request.
 *
 * @param test The test framework.
 * @param mctp The testing instances to utilize.
 * @param context Callback context to utilize.
 * @param issue_request_status Expected issue_request completion status.
 * @param msg_type Message type to use in request.
 */
static void mctp_interface_testing_generate_and_issue_request (CuTest *test,
	struct mctp_interface_testing *mctp, struct mctp_interface_test_callback_context *context,
	int issue_request_status, uint8_t msg_type)
{
 	uint8_t buf[6] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) tx_packet.data;
	int status;

    buf[0] = msg_type;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], buf, sizeof (buf));

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	status = mock_expect (&mctp->channel.mock, mctp->channel.base.send_packet, &mctp->channel, 0,
		MOCK_ARG_VALIDATOR_TMP (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect_external_action (&mctp->channel.mock,
		mctp_interface_testing_process_packet_callback, context);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp->mctp, &mctp->channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 100);
	CuAssertIntEquals (test, issue_request_status, status);
}

/*******************
 * Test cases
 *******************/

static void mctp_interface_test_init (CuTest *test)
{
	int status;
	struct mctp_interface_testing mctp;

	TEST_START;

	status = cmd_interface_mock_init (&mctp.cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&mctp.device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp.mctp, &mctp.cmd_cerberus.base, &mctp.cmd_mctp.base,
		&mctp.device_mgr);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&mctp.cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&mctp.device_mgr);
	mctp_interface_deinit (&mctp.mctp);
}

static void mctp_interface_test_init_null (CuTest *test)
{
	int status;
	struct mctp_interface_testing mctp;

	TEST_START;

	status = cmd_interface_mock_init (&mctp.cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&mctp.device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (NULL, &mctp.cmd_cerberus.base, &mctp.cmd_mctp.base,
		&mctp.device_mgr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.mctp, NULL, &mctp.cmd_mctp.base, &mctp.device_mgr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.mctp, &mctp.cmd_cerberus.base, NULL, &mctp.device_mgr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.mctp, &mctp.cmd_cerberus.base, &mctp.cmd_mctp.base,
		NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = cmd_interface_mock_validate_and_release (&mctp.cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&mctp.device_mgr);
}

static void mctp_interface_test_deinit_null (CuTest *test)
{
	TEST_START;

	mctp_interface_deinit (NULL);
}

static void mctp_interface_test_set_channel_id (CuTest *test)
{
	int status;
	struct mctp_interface_testing mctp;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_set_channel_id (&mctp.mctp, 1);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_set_channel_id_null (CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_interface_set_channel_id (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);
}

static void mctp_interface_test_process_packet_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (NULL, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&mctp.mctp, NULL, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_invalid_req (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = 0x01;
	error->error_data = 0x7F001606;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (0x7F001606), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, error->error_code);
	CuAssertIntEquals (test, 0x7F001606, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_unsupported_message (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = 0xAA;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = 0x01;
	error->error_data = 0x7F00160B;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (0x7F00160B), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, error->error_code);
	CuAssertIntEquals (test, 0x7F00160B, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_invalid_crc (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = 0x00;
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM;
	error->error_data = checksum_crc8 (0xBA, rx.data, 17);

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM),
		MOCK_ARG (checksum_crc8 (0xBA, rx.data, 17)), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM, error->error_code);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, rx.data, 17),	error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_packet_too_small (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	rx.pkt_size = 1;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_not_intended_target (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0C;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_interpret_fail_not_intended_target (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0C;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_out_of_order (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx[3];
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx[0].data[8] = 0x00;
	rx[0].data[9] = 0x00;
	rx[0].data[10] = 0x00;
	rx[0].data[17] = checksum_crc8 (0xBA, rx[0].data, 17);
	rx[0].pkt_size = 18;
	rx[0].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rx[1].pkt_size = 5;
	rx[1].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	rx[2].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx[2].data[8] = 0x00;
	rx[2].data[9] = 0x00;
	rx[2].data[10] = 0x00;
	rx[2].data[17] = checksum_crc8 (0xBA, rx[2].data, 17);
	rx[2].pkt_size = 18;
	rx[2].dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx[0], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.mctp, &rx[1], &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx[2], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_no_som (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (rx.data, 0, sizeof (rx.data));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_invalid_msg_tag (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = 0x01;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x01;
	header->packet_seq = 1;

	rx.data[sizeof (struct mctp_base_protocol_transport_header)] = 0x11;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 1, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_invalid_src_eid (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->source_eid = 0x0C;
	header->som = 0;
	header->eom = 1;
	header->packet_seq = 1;

	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_invalid_packet_seq (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->som = 0;
	header->packet_seq = 2;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_invalid_msg_size (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN;
	error->error_data = 9;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->byte_count = 14;
	header->som = 0;
	header->packet_seq = 1;

	rx.data[16] = checksum_crc8 (0xBA, rx.data, 16);
	rx.pkt_size = 17;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN),
		MOCK_ARG (9), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN, error->error_code);
	CuAssertIntEquals (test, 9, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_msg_overflow (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 237;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);
	rx.pkt_size = 240;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW;
	error->error_data = 4097;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->som = 0;
	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->byte_count = 158;
	header->packet_seq = 1;
	header->eom = 1;
	rx.data[160] = checksum_crc8 (0xBA, rx.data, 160);
	rx.pkt_size = 161;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW),
		MOCK_ARG (4097), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW, error->error_code);
	CuAssertIntEquals (test, 4097, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_cmd_interface_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_UNSPECIFIED;
	error->error_data = CMD_HANDLER_PROCESS_FAILED;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (CMD_HANDLER_PROCESS_FAILED), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_cmd_interface_fail_cmd_set_1 (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error =
		(struct cerberus_protocol_error*) &rx.data[MCTP_HEADER_LENGTH];
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	error->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.rq = 1;

	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error = (struct cerberus_protocol_error*) error_packet.data;

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 1;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_UNSPECIFIED;
	error->error_data = CMD_HANDLER_PROCESS_FAILED;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (CMD_HANDLER_PROCESS_FAILED), MOCK_ARG (1));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_no_response_non_zero_message_tag (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x02;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 2, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_no_response_cmd_set_1 (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error =
		(struct cerberus_protocol_error*) &rx.data[MCTP_HEADER_LENGTH];
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	error->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	error->header.rq = 1;

	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error = (struct cerberus_protocol_error*) error_packet.data;

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 1;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (1));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 1, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_unsupported_type (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = 0x0A;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_INVALID_REQ;
	error->error_data = MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, error->error_code);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_mctp_control_request (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_request, &mctp.cmd_mctp,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_mctp.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, 10, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, 0, tx->data[7]);
	CuAssertIntEquals (test, 0x12, tx->data[8]);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_mctp_control_request_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_request, &mctp.cmd_mctp,
		CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_mctp_control_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_response,
		&mctp.cmd_mctp, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_mctp_control_response_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_response,
		&mctp.cmd_mctp, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = CMD_HANDLER_NO_MEMORY;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_one_packet_request (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, 10, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, 0x7E, tx->data[7]);
	CuAssertIntEquals (test, 0x12, tx->data[8]);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_one_packet_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, 10, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, 0x7E, tx->data[7]);
	CuAssertIntEquals (test, 0x12, tx->data[8]);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_one_packet_response_non_zero_message_tag (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x03;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, 10, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 3, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, 0x7E, tx->data[7]);
	CuAssertIntEquals (test, 0x12, tx->data[8]);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_two_packet_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT + 48];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;
	int first_pkt = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	int second_pkt = 48;
	int second_pkt_total = second_pkt + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;
	int response_size = first_pkt + second_pkt;
	int i;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	for (i = 1; i < response_size; i++) {
		response.data[i] = i;
	}
	response.length = response_size;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN + second_pkt_total, tx->msg_size);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 0, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	status = testing_validate_array (response.data, &tx->data[MCTP_HEADER_LENGTH], first_pkt);
	CuAssertIntEquals (test, 0, status);

	header = (struct mctp_base_protocol_transport_header*) &tx->data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, second_pkt_total - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 1, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, &tx->data[tx->pkt_size], second_pkt_total - 1),
		tx->data[tx->msg_size - 1]);

	status = testing_validate_array (&response.data[first_pkt],
		&tx->data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN + MCTP_HEADER_LENGTH], second_pkt);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_channel_id_reset_next_som (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);
	error_packet.source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	error_packet.target_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	error_packet.crypto_timeout = false;
	error_packet.channel_id = 1;
	error_packet.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_set_channel_id (&mctp.mctp, 1);
	CuAssertIntEquals (test, 0, status);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_normal_timeout (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus,	0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, 10, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, 0x7E, tx->data[7]);
	CuAssertIntEquals (test, 0x12, tx->data[8]);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_crypto_timeout (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[2];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = true;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, 10, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, 0x7E, tx->data[7]);
	CuAssertIntEquals (test, 0x12, tx->data[8]);
	CuAssertIntEquals (test, false, platform_has_timeout_expired (&rx.pkt_timeout));

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_max_message (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	uint8_t msg_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	int status;
	int i;

	TEST_START;

	msg_data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	for (i = 1; i < (int) sizeof (msg_data); i++) {
		msg_data[i] = i;
	}

	i = 0;
	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 237;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);
	rx.pkt_size = 240;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->som = 0;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->byte_count = 157;
	header->packet_seq = 1;
	header->eom = 1;
	memcpy (&rx.data[7], &msg_data[i], 152);
	rx.data[159] = checksum_crc8 (0xBA, rx.data, 159);
	rx.pkt_size = 160;

	request.data = data;
	request.length = sizeof (msg_data);
	memcpy (request.data, msg_data, request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_max_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	size_t max_packets =
		ceil ((MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY * 1.0) / MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	size_t remain =
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - (MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * (max_packets - 1));
	int status;
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	for (i = 1; i < MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY; i++) {
		response.data[i] = i;
	}
	response.length = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	CuAssertIntEquals (test, max_packets, MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test,
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * max_packets),
		tx->msg_size);
	CuAssertIntEquals (test, pkt_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	for (i = 0; i < max_packets - 1; i++) {
		header =
			(struct mctp_base_protocol_transport_header*) &tx->data[i * MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

		CuAssertIntEquals (test, 0x0F, header->cmd_code);
		CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
		CuAssertIntEquals (test, 0xBB, header->source_addr);
		CuAssertIntEquals (test, 0x0A, header->destination_eid);
		CuAssertIntEquals (test, 0x0B, header->source_eid);
		CuAssertIntEquals (test, !i, header->som);
		CuAssertIntEquals (test, 0, header->eom);
		CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
		CuAssertIntEquals (test, 0, header->msg_tag);
		CuAssertIntEquals (test, i % 4, header->packet_seq);
		CuAssertIntEquals (test,
			checksum_crc8 (0xAA, &tx->data[i * tx->pkt_size], tx->pkt_size - 1),
			tx->data[((i + 1) * tx->pkt_size) - 1]);

		status = testing_validate_array (&response.data[i * MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT],
			&tx->data[(i * pkt_size) + MCTP_HEADER_LENGTH], MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
		CuAssertIntEquals (test, 0, status);
	}

	header = (struct mctp_base_protocol_transport_header*) &tx->data[i * pkt_size];

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, i % 4, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, &tx->data[i * tx->pkt_size], last_pkt_size - 1),
		tx->data[tx->msg_size - 1]);

	status = testing_validate_array (&response.data[i * MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT],
		&tx->data[(i * pkt_size) + MCTP_HEADER_LENGTH], remain);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_max_response_min_packets (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct device_manager_full_capabilities remote;
	size_t max_packets =
		ceil ((MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY * 1.0) / MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT);
	size_t remain =
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - (MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * (max_packets - 1));
	int status;
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MIN_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	for (i = 1; i < MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY; i++) {
		response.data[i] = i;
	}
	response.length = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	CuAssertIntEquals (test, max_packets,
		MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY,
			MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT));
	CuAssertIntEquals (test, sizeof (mctp.mctp.msg_buffer),
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * max_packets));

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test,
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * max_packets),
		tx->msg_size);
	CuAssertIntEquals (test, pkt_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	for (i = 0; i < max_packets - 1; i++) {
		header =
			(struct mctp_base_protocol_transport_header*) &tx->data[i * pkt_size];

		CuAssertIntEquals (test, 0x0F, header->cmd_code);
		CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
		CuAssertIntEquals (test, 0xBB, header->source_addr);
		CuAssertIntEquals (test, 0x0A, header->destination_eid);
		CuAssertIntEquals (test, 0x0B, header->source_eid);
		CuAssertIntEquals (test, !i, header->som);
		CuAssertIntEquals (test, 0, header->eom);
		CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
		CuAssertIntEquals (test, 0, header->msg_tag);
		CuAssertIntEquals (test, i % 4, header->packet_seq);
		CuAssertIntEquals (test,
			checksum_crc8 (0xAA, &tx->data[i * tx->pkt_size], tx->pkt_size - 1),
			tx->data[((i + 1) * tx->pkt_size) - 1]);

		status = testing_validate_array (&response.data[i * MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT],
			&tx->data[(i * pkt_size) + MCTP_HEADER_LENGTH], MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT);
		CuAssertIntEquals (test, 0, status);
	}

	header = (struct mctp_base_protocol_transport_header*) &tx->data[i * pkt_size];

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, i % 4, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, &tx->data[i * tx->pkt_size], last_pkt_size - 1),
		tx->data[tx->msg_size - 1]);

	status = testing_validate_array (&response.data[i * MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT],
		&tx->data[(i * pkt_size) + MCTP_HEADER_LENGTH], remain);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_no_eom (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_reset_message_processing (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx[2];
	struct cmd_message *tx;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx[0].data[8] = 0x00;
	rx[0].data[9] = 0x00;
	rx[0].data[10] = 0x00;
	rx[0].data[17] = checksum_crc8 (0xBA, rx[0].data, 17);
	rx[0].pkt_size = 18;
	rx[0].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx[1].data[7] = 0x00;
	rx[1].data[8] = 0x00;
	rx[1].data[9] = 0x00;
	rx[1].data[10] = 0x00;
	rx[1].data[17] = checksum_crc8 (0xBA, rx[1].data, 17);
	rx[1].pkt_size = 18;
	rx[1].dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_process_packet (&mctp.mctp, &rx[0], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_reset_message_processing (&mctp.mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx[1], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, error->error_code);
	CuAssertIntEquals (test, 0, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_response_length_limited (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	struct device_manager_full_capabilities remote;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, error->error_code);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_response_too_large (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + 1];
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_UNSPECIFIED;
	error->error_data = 0x7F001605;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (0x7F001605), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, 0x7F001605, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_response_too_large_length_limited (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	struct device_manager_full_capabilities remote;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_ERROR_UNSPECIFIED;
	error->error_data = 0x7F001605;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;

	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = remote.request.max_message_size + 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (0x7F001605), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, MCTP_ERROR_MSG_LENGTH, tx->msg_size);
	CuAssertIntEquals (test, tx->msg_size, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;
	error = (struct cerberus_protocol_error*) &tx->data[MCTP_HEADER_LENGTH];

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, tx->pkt_size - 3, header->byte_count);
	CuAssertIntEquals (test, 0x5D << 1 | 1, header->source_addr);
	CuAssertIntEquals (test, 0, header->rsvd);
	CuAssertIntEquals (test, 1, header->header_version);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, header->destination_eid);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, error->header.msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, error->header.pci_vendor_id);
	CuAssertIntEquals (test, 0, error->header.crypt);
	CuAssertIntEquals (test, 0, error->header.reserved2);
	CuAssertIntEquals (test, 0, error->header.integrity_check);
	CuAssertIntEquals (test, 0, error->header.reserved1);
	CuAssertIntEquals (test, 0, error->header.rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, error->header.command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, error->error_code);
	CuAssertIntEquals (test, 0x7F001605, error->error_data);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_two_packet_response_length_limited (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[48 + 10];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct device_manager_full_capabilities remote;
	int status;
	int first_pkt = 48;	// This is not a valid max packet size, but ensures test portability.
	int first_pkt_total = first_pkt + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;
	int second_pkt = 10;
	int second_pkt_total = second_pkt + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;
	int response_size = first_pkt + second_pkt;
	int i;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = first_pkt;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (response_data, 0, sizeof (response_data));
	response.data = response_data;
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	for (i = 1; i < response_size; i++) {
		response.data[i] = i;
	}
	response.length = response_size;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	CuAssertIntEquals (test, first_pkt_total + second_pkt_total, tx->msg_size);
	CuAssertIntEquals (test, first_pkt_total, tx->pkt_size);
	CuAssertIntEquals (test, 0x55, tx->dest_addr);

	header = (struct mctp_base_protocol_transport_header*) tx->data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, first_pkt_total - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 0, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, tx->data, tx->pkt_size - 1),
		tx->data[tx->pkt_size - 1]);

	status = testing_validate_array (response.data, &tx->data[MCTP_HEADER_LENGTH], first_pkt);
	CuAssertIntEquals (test, 0, status);

	header = (struct mctp_base_protocol_transport_header*) &tx->data[first_pkt_total];

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, second_pkt_total - 3, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 1, header->packet_seq);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, &tx->data[first_pkt_total], second_pkt_total - 1),
		tx->data[tx->msg_size - 1]);

	status = testing_validate_array (&response.data[first_pkt],
		&tx->data[first_pkt_total + MCTP_HEADER_LENGTH], second_pkt);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_error_message_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, CMD_HANDLER_ERROR_MSG_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MSG_FAILED, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_error_too_large (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT + 1];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	error_packet.data = error_data;
	error_packet.length = sizeof (error_data);

	error->header.msg_type = 0x7E;
	error->header.pci_vendor_id = 0x1414;
	error->header.crypt = 0;
	error->header.reserved2 = 0;
	error->header.integrity_check = 0;
	error->header.reserved1 = 0;
	error->header.rq = 0;
	error->header.command = 0x7F;
	error->error_code = CERBERUS_PROTOCOL_NO_ERROR;
	error->error_data = 0;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request, &mctp.cmd_cerberus,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_LARGE, status);
	CuAssertPtrEquals (test, NULL, tx);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_unexpected_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_UNEXPECTED_PKT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_process_packet_response_with_unexpected_msg_tag (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x01;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	context.expected_status = MCTP_BASE_PROTOCOL_UNEXPECTED_PKT;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_then_process_packet_response_from_unexpected_eid (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = 0x1D;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	context.expected_status = MCTP_BASE_PROTOCOL_UNEXPECTED_PKT;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_then_process_packet_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_then_process_packet_multiple_response_for_same_request (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF);

	status = mctp_interface_process_packet (&mctp.mctp, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_UNEXPECTED_PKT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_then_process_error_packet (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = CERBERUS_PROTOCOL_ERROR;
	rx.data[12] = CERBERUS_PROTOCOL_ERROR_INVALID_REQ;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;
	rx.timeout_valid = true;
	platform_init_timeout (10, &rx.pkt_timeout);

	memset (&response, 0, sizeof (response));

	response.data = data;
	response.length = sizeof (data);
	memcpy (response.data, &rx.data[7], response.length);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;
	response.channel_id = 0;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.test = test;
	context.testing = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[6] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], buf, sizeof (buf));

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_state_clean_after_completion_no_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[6] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet tx_packet2;
	struct mctp_base_protocol_transport_header *header;
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], buf, sizeof (buf));

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	memset (&tx_packet2, 0, sizeof (tx_packet2));

	header = (struct mctp_base_protocol_transport_header*) tx_packet2.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0F;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x01;
	header->packet_seq = 0;

	memcpy (&tx_packet2.data[7], buf, sizeof (buf));

	tx_packet2.data[13] = checksum_crc8 (0xAA, tx_packet2.data, 13);
	tx_packet2.pkt_size = 14;
	tx_packet2.state = CMD_VALID_PACKET;
	tx_packet2.dest_addr = 0x55;
	tx_packet2.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet2, sizeof (tx_packet2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55, 0x0F, buf,
		sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_multiple_packets_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t payload[300];
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct mctp_base_protocol_transport_header *header;
	int status;
	int i;

	payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	for (i = 1; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[sizeof (struct mctp_base_protocol_transport_header)], payload,
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	tx_packet[0].data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] = checksum_crc8 (0xAA, tx_packet[0].data,
		MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);
	tx_packet[0].pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = (sizeof (payload) - MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT) + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[sizeof (struct mctp_base_protocol_transport_header)],
		&payload[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT],
		sizeof (payload) - MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	tx_packet[1].data[i - 1] = checksum_crc8 (0xAA, tx_packet[1].data, i - 1);
	tx_packet[1].pkt_size = i;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;
	tx_packet[1].timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, payload, sizeof (payload), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_maximum_packet_length_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], buf, sizeof (buf));

	tx_packet.data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] =
		checksum_crc8 (0xAA, tx_packet.data, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);
	tx_packet.pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_maximum_num_packets_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT)];
	struct mctp_base_protocol_transport_header *header;
	size_t i_packet;
	size_t num_packets = sizeof (tx_packet) / sizeof (tx_packet[0]);
	uint8_t packet_seq = 0;
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	for (i_packet = 0; i_packet < (num_packets - 1); ++i_packet) {
		memset (&tx_packet[i_packet], 0, sizeof (tx_packet[i_packet]));

		header = (struct mctp_base_protocol_transport_header*) tx_packet[i_packet].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 3;
		header->source_addr = 0xBB;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->som = (i_packet == 0);
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
		header->msg_tag = 0x00;
		header->packet_seq = packet_seq;

		if (i_packet == 0) {
			tx_packet[i_packet].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		}

		tx_packet[i_packet].data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] =
			checksum_crc8 (0xAA, tx_packet[i_packet].data, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);
		tx_packet[i_packet].pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
		tx_packet[i_packet].state = CMD_VALID_PACKET;
		tx_packet[i_packet].dest_addr = 0x55;
		tx_packet[i_packet].timeout_valid = false;

		packet_seq = (packet_seq + 1) % 8;
	}

	memset (&tx_packet[i_packet], 0, sizeof (tx_packet[i_packet]));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[i_packet].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 0x98 - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = packet_seq;

	if (i_packet == 0) {
		tx_packet[i_packet].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	}

	tx_packet[i_packet].data[0x98 - 1] =
		checksum_crc8 (0xAA, tx_packet[i_packet].data, 0x98 - 1);
	tx_packet[i_packet].pkt_size = 0x98;
	tx_packet[i_packet].state = CMD_VALID_PACKET;
	tx_packet[i_packet].dest_addr = 0x55;
	tx_packet[i_packet].timeout_valid = false;

	packet_seq = (packet_seq + 1) % 8;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	for (i_packet = 0; i_packet < num_packets; ++i_packet) {
		status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i_packet],
				sizeof (tx_packet[i_packet])));
	}

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_limited_packet_length_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t payload[300];
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct mctp_base_protocol_transport_header *header;
	struct device_manager_full_capabilities remote;
	int status;
	int i;

	payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	for (i = 1; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 200 - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[sizeof (struct mctp_base_protocol_transport_header)], payload,
		200 - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD);
	tx_packet[0].data[200 - 1] = checksum_crc8 (0xAA, tx_packet[0].data, 200 - 1);
	tx_packet[0].pkt_size = 200;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = (sizeof (payload) - (200 - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD)) + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[sizeof (struct mctp_base_protocol_transport_header)],
		&payload[200 - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD],
		sizeof (payload) - (200 - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD));
	tx_packet[1].data[i - 1] = checksum_crc8 (0xAA, tx_packet[1].data, i - 1);
	tx_packet[1].pkt_size = i;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;
	tx_packet[1].timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	remote.request.max_packet_size = 200 - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, payload, sizeof (payload), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_limited_message_length_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t payload[300];
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct mctp_base_protocol_transport_header *header;
	struct device_manager_full_capabilities remote;
	int status;
	int i;

	payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	for (i = 1; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[sizeof (struct mctp_base_protocol_transport_header)], payload,
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	tx_packet[0].data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] =
		checksum_crc8 (0xAA, tx_packet[0].data, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);
	tx_packet[0].pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = (sizeof (payload) - MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT) + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[sizeof (struct mctp_base_protocol_transport_header)],
		&payload[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT],
		sizeof (payload) - MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	tx_packet[1].data[i - 1] = checksum_crc8 (0xAA, tx_packet[1].data, i - 1);
	tx_packet[1].pkt_size = i;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;
	tx_packet[1].timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	memset (&remote, 0, sizeof (remote));
	remote.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;
	remote.request.max_packet_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	remote.request.security_mode = DEVICE_MANAGER_SECURITY_AUTHENTICATION;
	remote.request.bus_role = DEVICE_MANAGER_SLAVE_BUS_ROLE;
	remote.request.hierarchy_role = DEVICE_MANAGER_AC_ROT_MODE;
	remote.max_timeout = MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS / 10;
	remote.max_sig = MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS / 100;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &remote);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, payload, sizeof (payload), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_control_packet_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[6] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], buf, sizeof (buf));

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_end_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], &msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6], 6);

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, &msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6], 6, msg_buf,
		sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_same_pointer_no_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	msg_buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], &msg_buf[0], 6);

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, msg_buf, 6, msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_before_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	msg_buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], &msg_buf[0], 6);

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, msg_buf, 6, &msg_buf[2], sizeof (msg_buf) - 2, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_within_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	msg_buf[2] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], &msg_buf[2], 6);

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, &msg_buf[2], 6, msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_after_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], &msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6], 6);

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, &msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6], 6, msg_buf,
		sizeof (msg_buf) - 2, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_cmd_channel_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[6] = {0};
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], buf, sizeof (buf));

	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;
	tx_packet.timeout_valid = false;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_NO_MEMORY,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, CMD_CHANNEL_NO_MEMORY, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_invalid_arg (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_issue_request (NULL, &mctp.channel.base, 0x77, 0xFF, buf, sizeof (buf),
		msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.mctp, NULL, 0x77, 0xFF, buf, sizeof (buf), msg_buf,
		sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x77, 0xFF, NULL,
		sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x77, 0xFF, buf, 0,
		msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x77, 0xFF, buf,
		sizeof (buf), NULL, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_output_buf_too_small (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[248];
 	uint8_t msg_buf[255];
	int status;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}

static void mctp_interface_test_issue_request_request_payload_too_large (CuTest *test)
{
	struct mctp_interface_testing mctp;
 	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + 1];
 	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &mctp);

	status = mctp_interface_issue_request (&mctp.mctp, &mctp.channel.base, 0x77, 0xFF, buf,
		sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_LARGE, status);

	complete_mctp_interface_with_interface_mock_test (test, &mctp);
}


TEST_SUITE_START (mctp_interface);

TEST (mctp_interface_test_init);
TEST (mctp_interface_test_init_null);
TEST (mctp_interface_test_deinit_null);
TEST (mctp_interface_test_set_channel_id);
TEST (mctp_interface_test_set_channel_id_null);
TEST (mctp_interface_test_process_packet_null);
TEST (mctp_interface_test_process_packet_invalid_req);
TEST (mctp_interface_test_process_packet_unsupported_message);
TEST (mctp_interface_test_process_packet_invalid_crc);
TEST (mctp_interface_test_process_packet_packet_too_small);
TEST (mctp_interface_test_process_packet_not_intended_target);
TEST (mctp_interface_test_process_packet_interpret_fail_not_intended_target);
TEST (mctp_interface_test_process_packet_out_of_order);
TEST (mctp_interface_test_process_packet_no_som);
TEST (mctp_interface_test_process_packet_invalid_msg_tag);
TEST (mctp_interface_test_process_packet_invalid_src_eid);
TEST (mctp_interface_test_process_packet_invalid_packet_seq);
TEST (mctp_interface_test_process_packet_invalid_msg_size);
TEST (mctp_interface_test_process_packet_msg_overflow);
TEST (mctp_interface_test_process_packet_cmd_interface_fail);
TEST (mctp_interface_test_process_packet_cmd_interface_fail_cmd_set_1);
TEST (mctp_interface_test_process_packet_no_response);
TEST (mctp_interface_test_process_packet_no_response_non_zero_message_tag);
TEST (mctp_interface_test_process_packet_no_response_cmd_set_1);
TEST (mctp_interface_test_process_packet_unsupported_type);
TEST (mctp_interface_test_process_packet_mctp_control_request);
TEST (mctp_interface_test_process_packet_mctp_control_request_fail);
TEST (mctp_interface_test_process_packet_mctp_control_response);
TEST (mctp_interface_test_process_packet_mctp_control_response_fail);
TEST (mctp_interface_test_process_packet_one_packet_request);
TEST (mctp_interface_test_process_packet_one_packet_response);
TEST (mctp_interface_test_process_packet_one_packet_response_non_zero_message_tag);
TEST (mctp_interface_test_process_packet_two_packet_response);
TEST (mctp_interface_test_process_packet_channel_id_reset_next_som);
TEST (mctp_interface_test_process_packet_normal_timeout);
TEST (mctp_interface_test_process_packet_crypto_timeout);
TEST (mctp_interface_test_process_packet_max_message);
TEST (mctp_interface_test_process_packet_max_response);
TEST (mctp_interface_test_process_packet_max_response_min_packets);
TEST (mctp_interface_test_process_packet_no_eom);
TEST (mctp_interface_test_process_packet_reset_message_processing);
TEST (mctp_interface_test_process_packet_response_length_limited);
TEST (mctp_interface_test_process_packet_response_too_large);
TEST (mctp_interface_test_process_packet_response_too_large_length_limited);
TEST (mctp_interface_test_process_packet_two_packet_response_length_limited);
TEST (mctp_interface_test_process_packet_error_message_fail);
TEST (mctp_interface_test_process_packet_error_too_large);
TEST (mctp_interface_test_process_packet_unexpected_response);
TEST (mctp_interface_test_process_packet_response_with_unexpected_msg_tag);
TEST (mctp_interface_test_issue_request_then_process_packet_response_from_unexpected_eid);
TEST (mctp_interface_test_issue_request_then_process_packet_response);
TEST (mctp_interface_test_issue_request_then_process_packet_multiple_response_for_same_request);
TEST (mctp_interface_test_issue_request_then_process_error_packet);
TEST (mctp_interface_test_issue_request_no_response);
TEST (mctp_interface_test_issue_request_state_clean_after_completion_no_response);
TEST (mctp_interface_test_issue_request_multiple_packets_no_response);
TEST (mctp_interface_test_issue_request_maximum_packet_length_no_response);
TEST (mctp_interface_test_issue_request_maximum_num_packets_no_response);
TEST (mctp_interface_test_issue_request_limited_packet_length_no_response);
TEST (mctp_interface_test_issue_request_limited_message_length_no_response);
TEST (mctp_interface_test_issue_request_control_packet_no_response);
TEST (mctp_interface_test_issue_request_buffers_overlapping_end_no_response);
TEST (mctp_interface_test_issue_request_buffers_overlapping_same_pointer_no_response);
TEST (mctp_interface_test_issue_request_buffers_overlapping_before_no_response);
TEST (mctp_interface_test_issue_request_buffers_overlapping_within_no_response);
TEST (mctp_interface_test_issue_request_buffers_overlapping_after_no_response);
TEST (mctp_interface_test_issue_request_cmd_channel_fail);
TEST (mctp_interface_test_issue_request_invalid_arg);
TEST (mctp_interface_test_issue_request_output_buf_too_small);
TEST (mctp_interface_test_issue_request_request_payload_too_large);

TEST_SUITE_END;
