// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform_api.h"
#include "cmd_interface/cmd_channel_handler.h"
#include "cmd_interface/cmd_channel_handler_static.h"
#include "crypto/checksum.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_interface.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("cmd_channel_handler");


/**
 * Dependencies for testing.
 */
struct cmd_channel_handler_testing {
	struct cmd_channel_mock channel;		/**< Command channel mock instance. */
	struct cmd_interface_mock cmd_cerberus;	/**< Cerberus protocol command interface mock instance. */
	struct cmd_interface_mock cmd_mctp;		/**< MCTP control protocol command interface mock instance. */
	struct device_manager device_mgr;		/**< Device manager. */
	struct mctp_interface mctp;				/**< MCTP interface instance */
	struct cmd_channel_handler test;		/**< Command processor for testing. */
};

/**
 * Initialize testing dependencies.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_channel_handler_testing_init_dependencies (CuTest *test,
	struct cmd_channel_handler_testing *handler)
{
	int status;

	status = cmd_channel_mock_init (&handler->channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&handler->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&handler->cmd_mctp);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&handler->device_mgr, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x51, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&handler->mctp, &handler->cmd_cerberus.base,
		&handler->cmd_mctp.base, NULL, &handler->device_mgr);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_channel_handler_testing_init (CuTest *test,
	struct cmd_channel_handler_testing *handler)
{
	int status;

	cmd_channel_handler_testing_init_dependencies (test, handler);

	status = cmd_channel_handler_init (&handler->test, &handler->channel.base, &handler->mctp);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing dependencies to release.
 */
static void cmd_channel_handler_testing_release_dependencies (CuTest *test,
	struct cmd_channel_handler_testing *handler)
{
	int status;

	status = cmd_channel_mock_validate_and_release (&handler->channel);
	status |= cmd_interface_mock_validate_and_release (&handler->cmd_cerberus);
	status |= cmd_interface_mock_validate_and_release (&handler->cmd_mctp);

	CuAssertIntEquals (test, 0, status);

	device_manager_release (&handler->device_mgr);
	mctp_interface_deinit (&handler->mctp);
}

/**
 * Release a test instance and validate all mocks.
 *
 * @param test The testing framework.
 * @param handler The testing components to release.
 */
static void cmd_channel_handler_testing_validate_and_release (CuTest *test,
	struct cmd_channel_handler_testing *handler)
{
	cmd_channel_handler_testing_release_dependencies (test, handler);
	cmd_channel_handler_release (&handler->test);
}

/*******************
 * Test cases
 *******************/

static void cmd_channel_handler_test_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	status = cmd_channel_handler_init (&handler.test, &handler.channel.base, &handler.mctp);
	CuAssertIntEquals (test, 0, status);

#ifdef CMD_ENABLE_ISSUE_REQUEST
	CuAssertPtrNotNull (test, handler.test.base.prepare);
#else
	CuAssertPtrEquals (test, NULL, handler.test.base.prepare);
#endif
	CuAssertPtrNotNull (test, handler.test.base.get_next_execution);
	CuAssertPtrNotNull (test, handler.test.base.execute);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_init_null (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	status = cmd_channel_handler_init (NULL, &handler.channel.base, &handler.mctp);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init (&handler.test, NULL, &handler.mctp);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init (&handler.test, &handler.channel.base, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_handler_testing_release_dependencies(test, &handler);
}

static void cmd_channel_handler_test_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp);

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

#ifdef CMD_ENABLE_ISSUE_REQUEST
	CuAssertPtrNotNull (test, test_static.base.prepare);
#else
	CuAssertPtrEquals (test, NULL, test_static.base.prepare);
#endif
	CuAssertPtrNotNull (test, test_static.base.get_next_execution);
	CuAssertPtrNotNull (test, test_static.base.execute);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_channel_handler_release (NULL);
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
static void cmd_channel_handler_test_prepare (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	uint8_t buf[3] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init (test, &handler);

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0x80;
	buf[2] = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 8;
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

	tx_packet.data[10] = checksum_crc8 (0xA2, tx_packet.data, 10);
	tx_packet.pkt_size = 11;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.send_packet, &handler.channel,
		0, MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	CuAssertIntEquals (test, 0, status);

	handler.test.base.prepare (&handler.test.base);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_prepare_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp);
	uint8_t buf[3] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0x80;
	buf[2] = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 8;
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

	tx_packet.data[10] = checksum_crc8 (0xA2, tx_packet.data, 10);
	tx_packet.pkt_size = 11;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.send_packet, &handler.channel,
		0, MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	CuAssertIntEquals (test, 0, status);

	test_static.base.prepare (&test_static.base);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}
#endif

static void cmd_channel_handler_test_get_next_execution (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	const platform_clock *next_time;

	TEST_START;

	cmd_channel_handler_testing_init (test, &handler);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_get_next_execution_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp);
	const platform_clock *next_time;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}

static void cmd_channel_handler_test_execute (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[6];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init (test, &handler);

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x00;
	rx_packet.data[9] = 0x00;
	rx_packet.data[10] = 0x00;
	rx_packet.data[11] = 0x0B;
	rx_packet.data[12] = 0x0A;
	rx_packet.data[13] = 0x01;
	rx_packet.data[14] = 0x02;
	rx_packet.data[15] = 0x03;
	rx_packet.data[16] = 0x04;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.state = CMD_VALID_PACKET;
	rx_packet.dest_addr = 0x5D;

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
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet.data[8] = 0x00;
	tx_packet.data[9] = 0x00;
	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x0B;
	tx_packet.data[12] = 0x0A;
	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.length = sizeof (response_data);
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	response.data[4] = 0x0B;
	response.data[5] = 0x0A;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.receive_packet,
		&handler.channel, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&handler.channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&handler.cmd_cerberus.mock, handler.cmd_cerberus.base.process_request,
		&handler.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&handler.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&handler.channel.mock, handler.channel.base.send_packet,
		&handler.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_execute_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp);
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[6];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x00;
	rx_packet.data[9] = 0x00;
	rx_packet.data[10] = 0x00;
	rx_packet.data[11] = 0x0B;
	rx_packet.data[12] = 0x0A;
	rx_packet.data[13] = 0x01;
	rx_packet.data[14] = 0x02;
	rx_packet.data[15] = 0x03;
	rx_packet.data[16] = 0x04;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.state = CMD_VALID_PACKET;
	rx_packet.dest_addr = 0x5D;

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
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet.data[8] = 0x00;
	tx_packet.data[9] = 0x00;
	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x0B;
	tx_packet.data[12] = 0x0A;
	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = response_data;
	response.length = sizeof (response_data);
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	response.data[4] = 0x0B;
	response.data[5] = 0x0A;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.receive_packet,
		&handler.channel, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&handler.channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&handler.cmd_cerberus.mock, handler.cmd_cerberus.base.process_request,
		&handler.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&handler.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&handler.channel.mock, handler.channel.base.send_packet,
		&handler.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	test_static.base.execute (&test_static.base);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}


TEST_SUITE_START (cmd_channel_handler);

TEST (cmd_channel_handler_test_init);
TEST (cmd_channel_handler_test_init_null);
TEST (cmd_channel_handler_test_static_init);
TEST (cmd_channel_handler_test_release_null);
#ifdef CMD_ENABLE_ISSUE_REQUEST
TEST (cmd_channel_handler_test_prepare);
TEST (cmd_channel_handler_test_prepare_static_init);
#endif
TEST (cmd_channel_handler_test_get_next_execution);
TEST (cmd_channel_handler_test_get_next_execution_static_init);
TEST (cmd_channel_handler_test_execute);
TEST (cmd_channel_handler_test_execute_static_init);

TEST_SUITE_END;
