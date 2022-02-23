// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform.h"
#include "mctp/mctp_interface.h"
#include "crypto/checksum.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"


TEST_SUITE_LABEL ("cmd_channel");


/**
 * Dependencies for testing the command channel.
 */
struct cmd_channel_testing {
	struct cmd_channel_mock test;					/**< Command channel mock instance. */
	struct cmd_interface_mock cmd_cerberus;			/**< Cerberus protocol command interface mock instance. */
	struct cmd_interface_mock cmd_mctp;				/**< MCTP control protocol command interface mock instance. */
	struct device_manager device_mgr;				/**< Device manager. */
	struct mctp_interface mctp;						/**< MCTP interface instance */
};

/**
 * Helper function to setup the command channel to use a mock interfaces
 *
 * @param test The test framework
 * @param channel The instances to initialize for testing
 */
static void setup_mock_cmd_channel_test (CuTest *test, struct cmd_channel_testing *channel)
{
	int status;

	status = cmd_channel_mock_init (&channel->test, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&channel->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&channel->cmd_mctp);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&channel->device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&channel->device_mgr, 0, 
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&channel->mctp, &channel->cmd_cerberus.base, 
		&channel->cmd_mctp.base, &channel->device_mgr);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to complete command channel test
 *
 * @param test The test framework
 * @param channel The instances to release
 */
static void complete_mock_cmd_channel_test (CuTest *test, struct cmd_channel_testing *channel)
{
	int status;

	status = cmd_channel_mock_validate_and_release (&channel->test);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&channel->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&channel->cmd_mctp);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&channel->device_mgr);
	mctp_interface_deinit (&channel->mctp);
}

/*******************
 * Test cases
 *******************/

static void cmd_channel_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_channel_init (NULL, 0);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);
}

static void cmd_channel_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_channel_release (NULL);
}

static void cmd_channel_test_get_id (CuTest *test)
{
	struct cmd_channel_mock channel;
	int status;

	TEST_START;

	status = cmd_channel_mock_init (&channel, 10);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_get_id (&channel.base);
	CuAssertIntEquals (test, 10, status);

	cmd_channel_mock_release (&channel);
}

static void cmd_channel_test_get_id_null (CuTest *test)
{
	struct cmd_channel_mock channel;
	int status;

	TEST_START;

	status = cmd_channel_mock_init (&channel, 10);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_get_id (NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_mock_release (&channel);
}

static void cmd_channel_test_receive_and_process_single_packet_response (CuTest *test)
{
	struct cmd_channel_testing channel;
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

	setup_mock_cmd_channel_test (test, &channel);

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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_multi_packet_response (CuTest *test)
{
	struct cmd_channel_testing channel;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet[2];
	uint8_t data[10];
	struct cmd_interface_msg request;
	const int msg_size = 300;
	uint8_t response_data[msg_size + 4];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

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

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	tx_packet[1].data[i] = checksum_crc8 (0xAA, tx_packet[1].data, i);
	tx_packet[1].pkt_size = i + 1;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;

	setup_mock_cmd_channel_test (test, &channel);

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
	memcpy (&response.data[4], payload, msg_size);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_max_response (CuTest *test)
{
	struct cmd_channel_testing channel;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE];
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;
	uint8_t payload[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	int status;
	size_t i;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT *
		(MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE - 1));
	size_t last_pkt_len = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	payload[1] = 0;
	payload[2] = 0;
	payload[3] = 0;
	for (i = 4; i < sizeof (payload); i++) {
		payload[i] = i;
	}

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

	memset (tx_packet, 0, sizeof (tx_packet));

	for (i = 0; i < MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE; i++) {
		uint8_t len = (i == (MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE - 1)) ?
			last_pkt_len : MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;

		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = len - 3;
		header->source_addr = 0xBB;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->som = !i;
		header->eom = (len == last_pkt_len);
		header->tag_owner = 0;
		header->msg_tag = 0x00;
		header->packet_seq = i % 4;

		memcpy (&tx_packet[i].data[7], &payload[i * MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT], len);
		tx_packet[i].data[len - 1] = checksum_crc8 (0xAA, tx_packet[i].data, len - 1);
		tx_packet[i].pkt_size = len;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x55;
	}

	setup_mock_cmd_channel_test (test, &channel);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	response.data = payload;
	response.length = sizeof (payload);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	for (i = 0; i < MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE; i++) {
		status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (struct cmd_packet)));
	}

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_multi_packet_message (CuTest *test)
{
	struct cmd_channel_testing channel;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	const int msg_size = 300;
	uint8_t data[msg_size + 4];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[1].data[i] = checksum_crc8 (0xBA, rx_packet[1].data, i);
	rx_packet[1].pkt_size = i + 1;
	rx_packet[1].state = CMD_VALID_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0x00;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

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

	setup_mock_cmd_channel_test (test, &channel);

	request.data = data;
	request.length = sizeof (data);
	request.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus, 0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_request_processing_timeout (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[6];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;

	TEST_START;

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
	rx_packet.timeout_valid = true;
	platform_init_timeout (10, &rx_packet.pkt_timeout);

	setup_mock_cmd_channel_test (test, &channel);

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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx_packet.pkt_timeout));

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_request_processing_timeout_not_valid (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[6];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;

	TEST_START;

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
	rx_packet.timeout_valid = false;
	platform_init_timeout (10, &rx_packet.pkt_timeout);

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

	setup_mock_cmd_channel_test (test, &channel);

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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx_packet.pkt_timeout));

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_set_receive_timeout (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	uint8_t data[10];
	struct cmd_interface_msg request;
	uint8_t response_data[6];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;

	TEST_START;

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

	setup_mock_cmd_channel_test (test, &channel);

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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (50));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, 50);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_channel_rx_error (CuTest *test)
{
	struct cmd_channel_testing channel;
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
	rx_packet.state = CMD_RX_ERROR;
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

	setup_mock_cmd_channel_test (test, &channel);

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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_null (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	const int msg_size = 300;
	uint8_t data[msg_size + 4];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[1].data[i] = checksum_crc8 (0xBA, rx_packet[1].data, i);
	rx_packet[1].pkt_size = i + 1;
	rx_packet[1].state = CMD_VALID_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0x00;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	setup_mock_cmd_channel_test (test, &channel);

	request.data = data;
	request.length = sizeof (data);
	request.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (NULL, &channel.mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_receive_and_process (&channel.test.base, NULL, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus, 0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_send_failure (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet[2];
	uint8_t data[10];
	struct cmd_interface_msg request;
	const int msg_size = 300;
	uint8_t response_data[msg_size + 4];
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet.data;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

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

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	tx_packet[1].data[i] = checksum_crc8 (0xAA, tx_packet[1].data, i);
	tx_packet[1].pkt_size = i + 1;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;

	setup_mock_cmd_channel_test (test, &channel);

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
	memcpy (&response.data[4], payload, msg_size);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel,
		CMD_CHANNEL_TX_FAILED, MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_mctp_fatal_error (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet[3];
	struct cmd_packet tx_packet;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[1].pkt_size = 5;
	rx_packet[1].state = CMD_VALID_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[2].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[2].data[i] = checksum_crc8 (0xBA, rx_packet[2].data, i);
	rx_packet[2].pkt_size = i + 1;
	rx_packet[2].state = CMD_VALID_PACKET;
	rx_packet[2].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0xF1;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

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

	setup_mock_cmd_channel_test (test, &channel);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[2],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus, 0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_receive_failure (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	const int msg_size = 300;
	uint8_t data[msg_size + 4];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[1].data[i] = checksum_crc8 (0xBA, rx_packet[1].data, i);
	rx_packet[1].pkt_size = i + 1;
	rx_packet[1].state = CMD_VALID_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0x00;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	setup_mock_cmd_channel_test (test, &channel);

	request.data = data;
	request.length = sizeof (data);
	request.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel,
		CMD_CHANNEL_RX_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_RX_FAILED, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus, 0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_receive_timeout (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	const int msg_size = 300;
	uint8_t data[msg_size + 4];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[1].data[i] = checksum_crc8 (0xBA, rx_packet[1].data, i);
	rx_packet[1].pkt_size = i + 1;
	rx_packet[1].state = CMD_VALID_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0x00;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	setup_mock_cmd_channel_test (test, &channel);

	request.data = data;
	request.length = sizeof (data);
	request.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
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

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel,
		CMD_CHANNEL_RX_TIMEOUT, MOCK_ARG_NOT_NULL, MOCK_ARG (50));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, 50);
	CuAssertIntEquals (test, CMD_CHANNEL_RX_TIMEOUT, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, channel.cmd_cerberus.base.process_request, 
		&channel.cmd_cerberus, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus, 0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_overflow_packet (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet[4];
	struct cmd_packet tx_packet;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[1].pkt_size = 5;
	rx_packet[1].state = CMD_OVERFLOW_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[2].pkt_size = 5;
	rx_packet[2].state = CMD_VALID_PACKET;
	rx_packet[2].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[3].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[3].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[3].data[i] = checksum_crc8 (0xBA, rx_packet[3].data, i);
	rx_packet[3].pkt_size = i + 1;
	rx_packet[3].state = CMD_VALID_PACKET;
	rx_packet[3].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0xF1;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

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

	setup_mock_cmd_channel_test (test, &channel);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_PKT_OVERFLOW, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[2],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[3],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus,	0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_receive_and_process_multiple_overflow_packet (CuTest *test)
{
	struct cmd_channel_testing channel;
	int status;
	struct cmd_packet rx_packet[5];
	struct cmd_packet tx_packet;
	uint8_t error_data[sizeof (struct cerberus_protocol_error)];
	struct cmd_interface_msg error_packet;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx_packet[0].data;
	struct cerberus_protocol_error *error = (struct cerberus_protocol_error*) error_data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[1].pkt_size = 5;
	rx_packet[1].state = CMD_OVERFLOW_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[2].pkt_size = 5;
	rx_packet[2].state = CMD_OVERFLOW_PACKET;
	rx_packet[2].dest_addr = 0x5D;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[3].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[3].pkt_size = 5;
	rx_packet[3].state = CMD_VALID_PACKET;
	rx_packet[3].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_base_protocol_transport_header*) rx_packet[4].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&rx_packet[4].data[7], &payload[255 - 12], msg_size - (255 - 12));
	rx_packet[4].data[i] = checksum_crc8 (0xBA, rx_packet[4].data, i);
	rx_packet[4].pkt_size = i + 1;
	rx_packet[4].state = CMD_VALID_PACKET;
	rx_packet[4].dest_addr = 0x5D;

	memset (&tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	memcpy (&tx_packet.data[8], &pci_vid, sizeof (pci_vid));

	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x7F;
	tx_packet.data[12] = 0xF1;
	tx_packet.data[13] = 0x00;
	tx_packet.data[14] = 0x00;
	tx_packet.data[15] = 0x00;
	tx_packet.data[16] = 0x00;
	tx_packet.data[17] = checksum_crc8 (0xAA, tx_packet.data, 17);
	tx_packet.pkt_size = 18;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

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

	setup_mock_cmd_channel_test (test, &channel);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[0],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[1],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_PKT_OVERFLOW, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[2],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_PKT_OVERFLOW, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[3],
		sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.test.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.cmd_cerberus.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.test.mock, channel.test.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.test.mock, 0, &rx_packet[4],
		sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.cmd_cerberus.mock, 
		channel.cmd_cerberus.base.generate_error_packet, &channel.cmd_cerberus, 0, 
		MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG), MOCK_ARG (0),
		MOCK_ARG (0));
	status |= mock_expect_output (&channel.cmd_cerberus.mock, 0, &error_packet, 
		sizeof (error_packet), -1);

	status |= mock_expect (&channel.test.mock, channel.test.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.test.base, &channel.mctp, -1);
	CuAssertIntEquals (test, 0, status);

	complete_mock_cmd_channel_test (test, &channel);
}

static void cmd_channel_test_send_message_single_packet (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_packet tx_packet;
	struct cmd_message tx_message;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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
	tx_packet.timeout_valid = false;

	tx_message.data = tx_packet.data;
	tx_message.msg_size = tx_packet.pkt_size;
	tx_message.pkt_size = tx_packet.pkt_size;
	tx_message.dest_addr = tx_packet.dest_addr;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}

static void cmd_channel_test_send_message_multiple_packets (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_packet tx_packet[2];
	struct cmd_message tx_message;
	const int msg_size = 300;
	uint8_t msg_data[msg_size + (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * 2) + 4];
	struct mctp_base_protocol_transport_header *header;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	tx_packet[1].data[i] = checksum_crc8 (0xAA, tx_packet[1].data, i);
	tx_packet[1].pkt_size = i + 1;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;
	tx_packet[1].timeout_valid = false;

	memcpy (msg_data, tx_packet[0].data, tx_packet[0].pkt_size);
	memcpy (&msg_data[tx_packet[0].pkt_size], tx_packet[1].data, tx_packet[1].pkt_size);

	tx_message.data = msg_data;
	tx_message.msg_size = sizeof (msg_data);
	tx_message.pkt_size = tx_packet[0].pkt_size;
	tx_message.dest_addr = tx_packet[0].dest_addr;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}

static void cmd_channel_test_send_message_multiple_messages (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_packet tx_packet[2];
	struct cmd_message tx_message[2];
	const int msg_size = 300;
	struct mctp_base_protocol_transport_header *header;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	tx_packet[1].data[i] = checksum_crc8 (0xAA, tx_packet[1].data, i);
	tx_packet[1].pkt_size = i + 1;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;
	tx_packet[1].timeout_valid = false;

	tx_message[0].data = tx_packet[0].data;
	tx_message[0].msg_size = tx_packet[0].pkt_size;
	tx_message[0].pkt_size = tx_packet[0].pkt_size;
	tx_message[0].dest_addr = tx_packet[0].dest_addr;

	tx_message[1].data = tx_packet[1].data;
	tx_message[1].msg_size = tx_packet[1].pkt_size;
	tx_message[1].pkt_size = tx_packet[1].pkt_size;
	tx_message[1].dest_addr = tx_packet[1].dest_addr;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message[0]);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message[1]);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}

static void cmd_channel_test_send_message_max_message (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE];
	struct cmd_message tx_message;
	struct mctp_base_protocol_transport_header *header;
	uint8_t payload[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t msg_data[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY +
		(MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE)];
	int status;
	size_t i;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT *
		(MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE - 1));
	size_t last_pkt_len = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	payload[1] = 0;
	payload[2] = 0;
	payload[3] = 0;
	for (i = 4; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	for (i = 0; i < MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE; i++) {
		uint8_t len = (i == (MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE - 1)) ?
			last_pkt_len : MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;

		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = len - 3;
		header->source_addr = 0xBB;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->som = !i;
		header->eom = (len == last_pkt_len);
		header->tag_owner = 0;
		header->msg_tag = 0x00;
		header->packet_seq = i % 4;

		memcpy (&tx_packet[i].data[7], &payload[i * MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT], len);
		tx_packet[i].data[len - 1] = checksum_crc8 (0xAA, tx_packet[i].data, len - 1);
		tx_packet[i].pkt_size = len;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x55;
		tx_packet[1].timeout_valid = false;

		memcpy (&msg_data[i * MCTP_BASE_PROTOCOL_MAX_PACKET_LEN], tx_packet[i].data,
			tx_packet[i].pkt_size);
	}

	tx_message.data = msg_data;
	tx_message.msg_size = sizeof (msg_data);
	tx_message.pkt_size = tx_packet[0].pkt_size;
	tx_message.dest_addr = tx_packet[0].dest_addr;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE; i++) {
		status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (struct cmd_packet)));
	}

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}

static void cmd_channel_test_send_message_null (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_message tx_message;
	int status;

	TEST_START;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (NULL, &tx_message);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_send_message (&channel.base, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}

static void cmd_channel_test_send_message_send_failure (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_packet tx_packet;
	struct cmd_message tx_message;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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
	tx_packet.timeout_valid = false;

	tx_message.data = tx_packet.data;
	tx_message.msg_size = tx_packet.pkt_size;
	tx_message.pkt_size = tx_packet.pkt_size;
	tx_message.dest_addr = tx_packet.dest_addr;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.send_packet, &channel, CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}

static void cmd_channel_test_send_message_multiple_packets_send_failure (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_packet tx_packet[2];
	struct cmd_message tx_message;
	const int msg_size = 300;
	uint8_t msg_data[msg_size + (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * 2) + 4];
	struct mctp_base_protocol_transport_header *header;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (tx_packet, 0, sizeof (tx_packet));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	memcpy (&tx_packet[1].data[7], &payload[255 - 12], msg_size - (255 - 12));
	tx_packet[1].data[i] = checksum_crc8 (0xAA, tx_packet[1].data, i);
	tx_packet[1].pkt_size = i + 1;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x55;
	tx_packet[1].timeout_valid = false;

	memcpy (msg_data, tx_packet[0].data, tx_packet[0].pkt_size);
	memcpy (&msg_data[tx_packet[0].pkt_size], tx_packet[1].data, tx_packet[1].pkt_size);

	tx_message.data = msg_data;
	tx_message.msg_size = sizeof (msg_data);
	tx_message.pkt_size = tx_packet[0].pkt_size;
	tx_message.dest_addr = tx_packet[0].dest_addr;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.send_packet, &channel, CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_send_message (&channel.base, &tx_message);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START (cmd_channel);

TEST (cmd_channel_test_init_null);
TEST (cmd_channel_test_release_null);
TEST (cmd_channel_test_get_id);
TEST (cmd_channel_test_get_id_null);
TEST (cmd_channel_test_receive_and_process_single_packet_response);
TEST (cmd_channel_test_receive_and_process_multi_packet_response);
TEST (cmd_channel_test_receive_and_process_max_response);
TEST (cmd_channel_test_receive_and_process_multi_packet_message);
TEST (cmd_channel_test_receive_and_process_request_processing_timeout);
TEST (cmd_channel_test_receive_and_process_request_processing_timeout_not_valid);
TEST (cmd_channel_test_receive_and_process_set_receive_timeout);
TEST (cmd_channel_test_receive_and_process_channel_rx_error);
TEST (cmd_channel_test_receive_and_process_null);
TEST (cmd_channel_test_receive_and_process_receive_failure);
TEST (cmd_channel_test_receive_and_process_receive_timeout);
TEST (cmd_channel_test_receive_and_process_mctp_fatal_error);
TEST (cmd_channel_test_receive_and_process_send_failure);
TEST (cmd_channel_test_receive_and_process_overflow_packet);
TEST (cmd_channel_test_receive_and_process_multiple_overflow_packet);
TEST (cmd_channel_test_send_message_single_packet);
TEST (cmd_channel_test_send_message_multiple_packets);
TEST (cmd_channel_test_send_message_multiple_messages);
TEST (cmd_channel_test_send_message_max_message);
TEST (cmd_channel_test_send_message_null);
TEST (cmd_channel_test_send_message_send_failure);
TEST (cmd_channel_test_send_message_multiple_packets_send_failure);

TEST_SUITE_END;
