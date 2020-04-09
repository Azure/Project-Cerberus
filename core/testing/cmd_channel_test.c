// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "platform.h"
#include "mock/cmd_channel_mock.h"
#include "mock/cmd_interface_mock.h"
#include "mctp/mctp_interface.h"
#include "crypto/checksum.h"


static const char *SUITE = "cmd_channel";


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
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet.data;
	int status;

	TEST_START;

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet.data[8] = 0x00;
	tx_packet.data[9] = 0x00;
	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x0B;
	tx_packet.data[12] = 0x0A;
	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	response.data[4] = 0x0B;
	response.data[5] = 0x0A;
	response.length = 6;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_multi_packet_response (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet[2];
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet.data;
	const int msg_size = 300;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	header = (struct mctp_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;

	header = (struct mctp_protocol_transport_header*) tx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	response.length = msg_size + 4;
	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	memcpy (&response.data[4], payload, msg_size);
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_multi_packet_message (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	i = msg_size - (255 - 12) + 7;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = msg_size + 4;
	request.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_request_processing_timeout (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet.data;

	TEST_START;

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	response.data[0] = 0x0B;
	response.data[1] = 0x0A;
	response.length = 2;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx_packet.pkt_timeout));

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_request_processing_timeout_not_valid (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet.data;

	TEST_START;

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet.data[8] = 0x00;
	tx_packet.data[9] = 0x00;
	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x0B;
	tx_packet.data[12] = 0x0A;
	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	response.data[4] = 0x0B;
	response.data[5] = 0x0A;
	response.length = 6;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx_packet.pkt_timeout));

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_set_receive_timeout (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet.data;

	TEST_START;

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet.data[8] = 0x00;
	tx_packet.data[9] = 0x00;
	tx_packet.data[10] = 0x00;
	tx_packet.data[11] = 0x0B;
	tx_packet.data[12] = 0x0A;
	tx_packet.data[13] = checksum_crc8 (0xAA, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x55;

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	response.data[4] = 0x0B;
	response.data[5] = 0x0A;
	response.length = 6;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (50));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, 50);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_null (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = msg_size + 4;
	request.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (NULL, &mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_receive_and_process (&channel.base, NULL, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_send_failure (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet[2];
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet.data;
	const int msg_size = 300;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	header = (struct mctp_protocol_transport_header*) tx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	tx_packet[0].data[8] = 0x00;
	tx_packet[0].data[9] = 0x00;
	tx_packet[0].data[10] = 0x00;
	memcpy (&tx_packet[0].data[11], payload, 255 - 12);
	tx_packet[0].data[254] = checksum_crc8 (0xAA, tx_packet[0].data, 254);
	tx_packet[0].pkt_size = 255;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) tx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx_packet.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	response.length = msg_size + 4;
	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0;
	response.data[2] = 0;
	response.data[3] = 0;
	memcpy (&response.data[4], payload, msg_size);
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_mctp_fatal_error (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet[3];
	struct cmd_packet tx_packet;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[1].pkt_size = 5;
	rx_packet[1].state = CMD_VALID_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) rx_packet[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TOO_SHORT, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[2], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_receive_failure (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = msg_size + 4;
	request.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel,
		CMD_CHANNEL_RX_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_RX_FAILED, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_receive_timeout (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet[2];
	struct cmd_packet tx_packet;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	request.length = msg_size + 4;
	request.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.data[1] = 0;
	request.data[2] = 0;
	request.data[3] = 0;
	memcpy (&request.data[4], payload, request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel,
		CMD_CHANNEL_RX_TIMEOUT, MOCK_ARG_NOT_NULL, MOCK_ARG (50));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, 50);
	CuAssertIntEquals (test, CMD_CHANNEL_RX_TIMEOUT, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&cmd.mock, cmd.base.process_request, &cmd, 0,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_overflow_packet (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet[4];
	struct cmd_packet tx_packet;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[1].pkt_size = 5;
	rx_packet[1].state = CMD_OVERFLOW_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[2].pkt_size = 5;
	rx_packet[2].state = CMD_VALID_PACKET;
	rx_packet[2].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) rx_packet[3].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_PKT_OVERFLOW, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[2], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[3], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}

static void cmd_channel_test_receive_and_process_multiple_overflow_packet (CuTest *test)
{
	struct cmd_channel_mock channel;
	struct cmd_interface_mock cmd;
	struct device_manager device_mgr;
	struct mctp_interface mctp;
	int status;
	struct cmd_packet rx_packet[5];
	struct cmd_packet tx_packet;
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) rx_packet[0].data;
	const int msg_size = 300;
	uint16_t pci_vid = 0x1414;
	uint8_t payload[msg_size];
	int i;

	TEST_START;

	for (i = 0; i < sizeof (payload); i++) {
		payload[i] = i;
	}

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x00;
	rx_packet[0].data[10] = 0x00;
	memcpy (&rx_packet[0].data[11], payload, 255 - 12);
	rx_packet[0].data[254] = checksum_crc8 (0xBA, rx_packet[0].data, 254);
	rx_packet[0].pkt_size = 255;
	rx_packet[0].state = CMD_VALID_PACKET;
	rx_packet[0].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[1].pkt_size = 5;
	rx_packet[1].state = CMD_OVERFLOW_PACKET;
	rx_packet[1].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 252;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[2].pkt_size = 5;
	rx_packet[2].state = CMD_OVERFLOW_PACKET;
	rx_packet[2].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx_packet[3].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	rx_packet[3].pkt_size = 5;
	rx_packet[3].state = CMD_VALID_PACKET;
	rx_packet[3].dest_addr = 0x5D;

	i = msg_size - (255 - 12) + 7;

	header = (struct mctp_protocol_transport_header*) rx_packet[4].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = i - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
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

	header = (struct mctp_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	tx_packet.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

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

	status = cmd_channel_mock_init (&channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&cmd);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&mctp, &cmd.base, &device_mgr, MCTP_PROTOCOL_PA_ROT_CTRL_EID,
		CERBERUS_PROTOCOL_MSFT_PCI_VID, CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[0], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[1], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_PKT_OVERFLOW, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[2], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, CMD_CHANNEL_PKT_OVERFLOW, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[3], sizeof (struct cmd_packet), -1);

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&channel.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&cmd.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&channel.mock, channel.base.receive_packet, &channel, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&channel.mock, 0, &rx_packet[4], sizeof (struct cmd_packet), -1);

	status |= mock_expect (&channel.mock, channel.base.send_packet, &channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_receive_and_process (&channel.base, &mctp, -1);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_validate_and_release (&channel);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_validate_and_release (&cmd);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);

	mctp_interface_deinit (&mctp);
}


CuSuite* get_cmd_channel_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, cmd_channel_test_init_null);
	SUITE_ADD_TEST (suite, cmd_channel_test_release_null);
	SUITE_ADD_TEST (suite, cmd_channel_test_get_id);
	SUITE_ADD_TEST (suite, cmd_channel_test_get_id_null);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_single_packet_response);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_multi_packet_response);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_multi_packet_message);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_request_processing_timeout);
	SUITE_ADD_TEST (suite,
		cmd_channel_test_receive_and_process_request_processing_timeout_not_valid);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_set_receive_timeout);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_null);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_receive_failure);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_receive_timeout);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_mctp_fatal_error);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_send_failure);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_overflow_packet);
	SUITE_ADD_TEST (suite, cmd_channel_test_receive_and_process_multiple_overflow_packet);

	return suite;
}
