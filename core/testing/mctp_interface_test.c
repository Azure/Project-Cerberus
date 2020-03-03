// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "crypto/checksum.h"
#include "mock/cmd_interface_mock.h"
#include "mctp/mctp_interface.h"
#include "mctp/mctp_protocol.h"
#include "mctp/mctp_interface_control.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "cmd_interface/cmd_interface_system.h"


static const char *SUITE = "mctp_interface";


/**
 * Helper function to setup the MCTP interface to use a mock cmd_interface
 *
 * @param test The test framework
 * @param cmd_interface The cmd interface mock instance to initialize
 * @param device_mgr The device manager instance to initialize
 * @param interface The MCTP interface instance to initialize
 */
static void setup_mctp_interface_with_interface_mock_test (CuTest *test,
	struct cmd_interface_mock *cmd_interface, struct device_manager *device_mgr,
	struct mctp_interface *interface)
{
	struct device_manager_capabilities capabilities = {0};
	int status;

	capabilities.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;

	status = cmd_interface_mock_init (cmd_interface);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (device_mgr, 2);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (device_mgr, 0, DEVICE_MANAGER_SELF,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (device_mgr, 1, DEVICE_MANAGER_UPSTREAM,
		MCTP_PROTOCOL_BMC_EID, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_capabilities (device_mgr, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (interface, &cmd_interface->base, device_mgr,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to complete MCTP test
 *
 * @param test The test framework
 * @param cmd_interface The cmd interface mock instance to release
 * @param device_mgr The device manager instance to release
 * @param interface The MCTP interface instance to release
 */
static void complete_mctp_interface_with_interface_mock_test (CuTest *test,
	struct cmd_interface_mock *cmd_interface, struct device_manager *device_mgr,
	struct mctp_interface *interface)
{
	int status;

	status = cmd_interface_mock_validate_and_release (cmd_interface);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (device_mgr);
	mctp_interface_deinit (interface);
}


/*******************
 * Test cases
 *******************/

static void mctp_interface_test_init (CuTest *test)
{
	int status;
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;

	TEST_START;

	status = cmd_interface_mock_init (&cmd_interface);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&interface, &cmd_interface.base, &device_mgr,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_init_null (CuTest *test)
{
	int status;
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;

	TEST_START;

	status = cmd_interface_mock_init (&cmd_interface);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&device_mgr, 1);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (NULL, &cmd_interface.base, &device_mgr,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&interface, NULL, &device_mgr,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&interface, &cmd_interface.base, NULL,
		MCTP_PROTOCOL_PA_ROT_CTRL_EID, CERBERUS_PROTOCOL_MSFT_PCI_VID,
		CERBERUS_PROTOCOL_PROTOCOL_VERSION);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = cmd_interface_mock_validate_and_release (&cmd_interface);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&device_mgr);
}

static void mctp_interface_test_deinit_null (CuTest *test)
{
	TEST_START;

	mctp_interface_deinit (NULL);
}

static void mctp_interface_test_set_channel_id (CuTest *test)
{
	int status;
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_set_channel_id (&interface, 1);
	CuAssertIntEquals (test, 0, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_set_channel_id_null (CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_interface_set_channel_id (NULL, 1);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);
}

static void mctp_interface_test_process_packet_null (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	size_t num_packets;
	struct cmd_packet rx;
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (NULL, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&interface, NULL, &packets, &num_packets);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&interface, &rx, NULL, &num_packets);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, NULL);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_req (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0x7F001606, *((uint32_t*) &packets[0].data[13]));
	CuAssertIntEquals (test, 0, status);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_unsupported_message (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = 0xAA;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0x7F00160B, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_crc (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = 0x00;
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, rx.data, 17),
		*((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_packet_too_small (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	rx.pkt_size = 1;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TOO_SHORT, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_not_intended_target (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets;
	size_t num_packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	int status;


	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0C;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_interpret_fail_not_intended_target (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets;
	size_t num_packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	int status;


	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0C;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_out_of_order (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
 	struct cmd_packet rx[3];
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx[0].data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx[0].data[8] = 0x00;
	rx[0].data[9] = 0x00;
	rx[0].data[10] = 0x00;
	rx[0].data[17] = checksum_crc8 (0xBA, rx[0].data, 17);
	rx[0].pkt_size = 18;
	rx[0].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;

	rx[1].pkt_size = 5;
	rx[1].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx[2].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx[2].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx[2].data[8] = 0x00;
	rx[2].data[9] = 0x00;
	rx[2].data[10] = 0x00;
	rx[2].data[17] = checksum_crc8 (0xBA, rx[2].data, 17);
	rx[2].pkt_size = 18;
	rx[2].dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx[0], &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);
	CuAssertPtrEquals (test, NULL, packets);

	status = mctp_interface_process_packet (&interface, &rx[1], &packets, &num_packets);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TOO_SHORT, status);
	CuAssertIntEquals (test, 0, num_packets);
	CuAssertPtrEquals (test, NULL, packets);

	status = mctp_interface_process_packet (&interface, &rx[2], &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_no_som (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (rx.data, 0, sizeof (rx.data));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_msg_tag (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	size_t num_packets;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->som = 0;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x01;
	header->packet_seq = 1;

	rx.data[6] = 0x11;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_REQ, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_dest_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->destination_eid = 0x0C;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 1;

	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_src_eid (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->source_eid = 0x0C;
	header->som = 0;
	header->packet_seq = 1;

	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_packet_seq (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	size_t num_packets;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->som = 0;
	header->packet_seq = 2;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_invalid_msg_size (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->byte_count = 14;
	header->som = 0;
	header->packet_seq = 1;

	rx.data[16] = checksum_crc8 (0xBA, rx.data, 16);
	rx.pkt_size = 17;

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 9, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_msg_overflow (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 237;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);
	rx.pkt_size = 240;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->som = 0;
	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	header->byte_count = 154;
	header->packet_seq = 1;
	header->eom = 1;
	rx.data[156] = checksum_crc8 (0xBA, rx.data, 156);
	rx.pkt_size = 157;

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 4093, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_cmd_interface_fail (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	size_t num_packets;
	int status;


	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, *((uint32_t*)&packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_cmd_interface_fail_cmd_set_1 (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	size_t num_packets;
	int status;


	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	cerberus_header = (struct cerberus_protocol_header*) &rx.data[7];
	cerberus_header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	cerberus_header->rq = 1;

	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 1, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, CMD_HANDLER_PROCESS_FAILED, *((uint32_t*)&packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_error_packet (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[11] = CERBERUS_PROTOCOL_ERROR;
	rx.data[12] = CERBERUS_PROTOCOL_ERROR_INVALID_REQ;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		CMD_ERROR_MESSAGE_ESCAPE_SEQ,
		MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_no_response (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	struct cmd_packet *packets;
	size_t num_packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	int status;
	struct cmd_interface_request request;
	struct cmd_interface_request response;

	TEST_START;

	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.length = 6;
	request.new_request = true;
	request.channel_id = 0;
	memset (request.data, 0, sizeof (request.data));

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_no_response_cmd_set_1 (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	struct cmd_packet *packets;
	size_t num_packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	int status;
	struct cmd_interface_request request;
	struct cmd_interface_request response;

	TEST_START;

	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.length = 6;
	request.new_request = true;
	request.channel_id = 0;
	memset (request.data, 0, sizeof (request.data));

	memset (&rx, 0, sizeof (rx));

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

	cerberus_header = (struct cerberus_protocol_header*) &rx.data[7];
	cerberus_header->msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	cerberus_header->rq = 1;
	
	rx.data[11] = 0x01;
	rx.data[12] = 0x02;
	rx.data[13] = 0x03;
	rx.data[14] = 0x04;
	rx.data[15] = 0x05;
	rx.data[16] = 0x06;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 1, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_unsupported_type (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	size_t num_packets;
	int status;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

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
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_mctp_control_msg (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct mctp_protocol_control_header *ctrl_header =
		(struct mctp_protocol_control_header*) &rx.data[MCTP_PROTOCOL_MIN_PACKET_LEN - 1];
	struct mctp_control_set_eid_request_packet *rq = (struct mctp_control_set_eid_request_packet*)
		&rx.data[MCTP_PROTOCOL_MIN_PACKET_LEN - 1 + MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	struct mctp_control_set_eid_response_packet *response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = sizeof (struct mctp_protocol_transport_header) +
		sizeof (struct mctp_protocol_control_header) +
		sizeof (struct mctp_control_set_eid_request_packet) - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	ctrl_header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	ctrl_header->command_code = MCTP_PROTOCOL_SET_EID;
	ctrl_header->rq = 1;

	rq->operation = MCTP_CONTROL_SET_EID_OPERATION_SET_ID;
	rq->eid = 0xAA;

	rx.pkt_size = sizeof (struct mctp_protocol_transport_header) +
		sizeof (struct mctp_protocol_control_header) +
		sizeof (struct mctp_control_set_eid_request_packet);
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) +
		sizeof (struct mctp_protocol_control_header) +
		sizeof (struct mctp_control_set_eid_response_packet), packets[0].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[0].data;
	ctrl_header =
		(struct mctp_protocol_control_header*) &packets[0].data[MCTP_PROTOCOL_MIN_PACKET_LEN - 1];
	response = (struct mctp_control_set_eid_response_packet*)
		&packets[0].data[MCTP_PROTOCOL_MIN_PACKET_LEN - 1 + MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) +
		sizeof (struct mctp_protocol_control_header) +
		sizeof (struct mctp_control_set_eid_response_packet) - 2, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 0, ctrl_header->msg_type);
	CuAssertIntEquals (test, 1, ctrl_header->command_code);
	CuAssertIntEquals (test, 0, ctrl_header->rq);
	CuAssertIntEquals (test, 0, response->completion_code);
	CuAssertIntEquals (test, 1, response->eid_assignment_status);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_mctp_control_msg_fail (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct mctp_protocol_control_header *ctrl_header =
		(struct mctp_protocol_control_header*) &rx.data[MCTP_PROTOCOL_MIN_PACKET_LEN - 1];
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = sizeof (struct mctp_protocol_transport_header) +
		sizeof (struct mctp_protocol_control_header) - 2;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	ctrl_header->msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	ctrl_header->rsvd = 1;

	rx.pkt_size = sizeof (struct mctp_protocol_transport_header) +
		sizeof (struct mctp_protocol_control_header);
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, CMD_HANDLER_UNSUPPORTED_MSG, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_one_packet_request (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = 2;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = true;
	response.crypto_timeout = false;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 10, packets[0].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[0].data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 0x7E, packets[0].data[7]);
	CuAssertIntEquals (test, 0x12, packets[0].data[8]);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, packets[0].data, 9), packets[0].data[9]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_one_packet_response (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = 2;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 10, packets[0].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[0].data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 0x7E, packets[0].data[7]);
	CuAssertIntEquals (test, 0x12, packets[0].data[8]);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, packets[0].data, 9), packets[0].data[9]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_two_packet_response (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	memset (response.data, 0, sizeof (response.data));
	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[10] = 0x0B;
	response.data[20] = 0x0C;
	response.data[242] = 0x0D;
	response.data[243] = 0xAA;
	response.data[253] = 0xBB;
	response.data[297] = 0xCC;
	response.data[298] = 0xDD;
	response.length = 300;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 255, packets[0].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[0].data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 252, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 0, header->eom);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);

	status = testing_validate_array (response.data, &packets[0].data[7],
		response.length - MCTP_PROTOCOL_MAX_PAYLOAD_PER_PKT);

	CuAssertIntEquals (test, checksum_crc8 (0xAA, packets[0].data, 254), packets[0].data[254]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	CuAssertIntEquals (test, 0, packets[1].state);
	CuAssertIntEquals (test, 61, packets[1].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[1].data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 58, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 1, header->packet_seq);

	status = testing_validate_array (&response.data[247], &packets[1].data[7], 53);

	CuAssertIntEquals (test, checksum_crc8 (0xAA, packets[1].data, 60), packets[1].data[60]);
	CuAssertIntEquals (test, 0x55, packets[1].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_channel_id_reset_next_som (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_set_channel_id (&interface, 1);
	CuAssertIntEquals (test, 0, status);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 1;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	platform_free (packets);

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_normal_timeout (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = 2;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = false;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 10, packets[0].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[0].data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 0x7E, packets[0].data[7]);
	CuAssertIntEquals (test, 0x12, packets[0].data[8]);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, packets[0].data, 9), packets[0].data[9]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_crypto_timeout (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	size_t num_packets;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
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

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	request.length = 10;
	memcpy (request.data, &rx.data[7], request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	response.data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = 2;
	response.source_eid = 0x0A;
	response.target_eid = 0x0B;
	response.new_request = false;
	response.crypto_timeout = true;

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 10, packets[0].pkt_size);

	header = (struct mctp_protocol_transport_header*) packets[0].data;

	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 7, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0x0A, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 0x7E, packets[0].data[7]);
	CuAssertIntEquals (test, 0x12, packets[0].data[8]);
	CuAssertIntEquals (test, checksum_crc8 (0xAA, packets[0].data, 9), packets[0].data[9]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, false, platform_has_timeout_expired (&rx.pkt_timeout));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_max_message (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cerberus_protocol_header* cerberus_header;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cmd_interface_request request;
	struct cmd_interface_request response;
	uint8_t msg_data[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG];
	size_t num_packets;
	int status;
	int i;

	TEST_START;

	msg_data[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	for (i = 1; i < sizeof (msg_data); i++) {
		msg_data[i] = i;
	}

	i = 0;
	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 237;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = 0;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);
	rx.pkt_size = 240;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->som = 0;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);

	i += 232;
	header->byte_count = 144;
	header->packet_seq = 1;
	header->eom = 1;
	memcpy (&rx.data[7], &msg_data[i], 139);
	rx.data[146] = checksum_crc8 (0xBA, rx.data, 146);
	rx.pkt_size = 147;

	request.length = sizeof (msg_data);
	memcpy (request.data, msg_data, request.length);
	request.source_eid = 0x0A;
	request.target_eid = 0x0B;
	request.new_request = false;
	request.crypto_timeout = false;
	request.channel_id = 0;

	memset (&response, 0, sizeof (response));

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.process_request, &cmd_interface,
		0, MOCK_ARG_VALIDATOR (cmd_interface_mock_validate_request, &request, sizeof (request)));
	status |= mock_expect_output (&cmd_interface.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_NO_ERROR, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_no_eom (CuTest *test)
{
	struct mctp_interface interface;
 	struct cmd_packet rx;
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx.data;
	struct cmd_packet *packets = &rx;
	size_t num_packets = 1;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx.data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx.data[8] = 0x00;
	rx.data[9] = 0x00;
	rx.data[10] = 0x00;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);
	rx.pkt_size = 18;
	rx.dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx, &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);
	CuAssertPtrEquals (test, NULL, packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_process_packet_reset_message_processing (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_packet *packets;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
 	struct cmd_packet rx[2];
	struct mctp_protocol_transport_header* header =
		(struct mctp_protocol_transport_header*) rx[0].data;
	struct cerberus_protocol_header* cerberus_header;
	size_t num_packets;
	int status;

	TEST_START;

	memset (rx, 0, sizeof (rx));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
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

	rx[0].data[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx[0].data[8] = 0x00;
	rx[0].data[9] = 0x00;
	rx[0].data[10] = 0x00;
	rx[0].data[17] = checksum_crc8 (0xBA, rx[0].data, 17);
	rx[0].pkt_size = 18;
	rx[0].dest_addr = 0x5D;

	header = (struct mctp_protocol_transport_header*) rx[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = 1;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx[1].data[7] = 0x00;
	rx[1].data[8] = 0x00;
	rx[1].data[9] = 0x00;
	rx[1].data[10] = 0x00;
	rx[1].data[17] = checksum_crc8 (0xBA, rx[1].data, 17);
	rx[1].pkt_size = 18;
	rx[1].dest_addr = 0x5D;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_process_packet (&interface, &rx[0], &packets, &num_packets);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, num_packets);
	CuAssertPtrEquals (test, NULL, packets);

	mctp_interface_reset_message_processing (&interface);

	status = mctp_interface_process_packet (&interface, &rx[1], &packets, &num_packets);
	cerberus_header = (struct cerberus_protocol_header*) &packets[0].data[7];

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, num_packets);
	CuAssertIntEquals (test, 0, packets[0].state);
	CuAssertIntEquals (test, 18, packets[0].pkt_size);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, cerberus_header->msg_type);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_MSFT_PCI_VID, cerberus_header->pci_vendor_id);
	CuAssertIntEquals (test, 0, cerberus_header->crypt);
	CuAssertIntEquals (test, 0, cerberus_header->d_bit);
	CuAssertIntEquals (test, 0, cerberus_header->integrity_check);
	CuAssertIntEquals (test, 0, cerberus_header->seq_num);
	CuAssertIntEquals (test, 0, cerberus_header->rq);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR, cerberus_header->command);
	CuAssertIntEquals (test, CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, packets[0].data[12]);
	CuAssertIntEquals (test, 0x55, packets[0].dest_addr);
	CuAssertIntEquals (test, 0, *((uint32_t*) &packets[0].data[13]));

	platform_free (packets);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	uint8_t params;
	uint8_t request[5] = {MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, 1, 2, 3, 4};
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	struct mctp_protocol_transport_header* header = (struct mctp_protocol_transport_header*) buf;
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.issue_request, &cmd_interface,
		sizeof (request), MOCK_ARG (CERBERUS_PROTOCOL_GET_CERTIFICATE), MOCK_ARG (&params),
		MOCK_ARG_NOT_NULL, MOCK_ARG (MCTP_PROTOCOL_MAX_PAYLOAD_PER_PKT));
	status |= mock_expect_output (&cmd_interface.mock, 2, request, sizeof (request), -1);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, &params, buf, sizeof (buf),
		MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF);
	CuAssertIntEquals (test, 13, status);
	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 10, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0xFF, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, buf[7]);
	CuAssertIntEquals (test, 1, buf[8]);
	CuAssertIntEquals (test, 2, buf[9]);
	CuAssertIntEquals (test, 3, buf[10]);
	CuAssertIntEquals (test, 4, buf[11]);
	CuAssertIntEquals (test, checksum_crc8 (0xEE, buf, 12), buf[12]);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request_mctp_ctrl_msg (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	uint8_t params = 0xAA;
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	struct mctp_protocol_transport_header* header = (struct mctp_protocol_transport_header*) buf;
	struct mctp_protocol_control_header* ctrl_header = (struct mctp_protocol_control_header*)
		&buf[MCTP_PROTOCOL_MIN_PACKET_LEN - 1];
	struct mctp_control_set_eid_request_packet* request =
		(struct mctp_control_set_eid_request_packet*)
		&buf[MCTP_PROTOCOL_MIN_PACKET_LEN - 1 + MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN];
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B,
		MCTP_PROTOCOL_SET_EID, &params, buf, sizeof (buf), MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG);
	CuAssertIntEquals (test, 12, status);
	CuAssertIntEquals (test, 0x0F, header->cmd_code);
	CuAssertIntEquals (test, 10, header->byte_count);
	CuAssertIntEquals (test, 0xBB, header->source_addr);
	CuAssertIntEquals (test, 0xFF, header->destination_eid);
	CuAssertIntEquals (test, 0x0B, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0, header->msg_tag);
	CuAssertIntEquals (test, 0, header->packet_seq);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, 0, ctrl_header->msg_type);
	CuAssertIntEquals (test, 1, ctrl_header->command_code);
	CuAssertIntEquals (test, 1, ctrl_header->rq);
	CuAssertIntEquals (test, 0, ctrl_header->rsvd);
	CuAssertIntEquals (test, 0, ctrl_header->instance_id);
	CuAssertIntEquals (test, 0, ctrl_header->integrity_check);
	CuAssertIntEquals (test, 0, ctrl_header->d_bit);
	CuAssertIntEquals (test, 0, request->operation);
	CuAssertIntEquals (test, params, request->eid);
	CuAssertIntEquals (test, 0, request->reserved);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request_null (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	struct cerberus_protocol_cert_req_params params = {0};
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_issue_request (NULL, 0x77, 0xFF, 0x5D, 0x0B, 0x82, &params,
		buf, sizeof (buf), MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B, 0x82, &params,
		NULL, sizeof (buf), MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request_fail (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.issue_request, &cmd_interface,
		CMD_HANDLER_NO_MEMORY, MOCK_ARG (CERBERUS_PROTOCOL_GET_CERTIFICATE), MOCK_ARG_ANY,
		MOCK_ARG_NOT_NULL, MOCK_ARG (MCTP_PROTOCOL_MAX_PAYLOAD_PER_PKT));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, NULL, buf, sizeof (buf),
		MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request_mctp_ctrl_msg_fail (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	uint8_t params;
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B, 0xFF,
		(void*) &params, buf, sizeof (buf), MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG);
	CuAssertIntEquals (test, CMD_HANDLER_UNKNOWN_COMMAND, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request_unsupported_msg_type (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, NULL, buf, sizeof (buf), 0xFF);
	CuAssertIntEquals (test, MCTP_PROTOCOL_UNSUPPORTED_MSG, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

static void mctp_interface_test_issue_request_construct_packet_fail (CuTest *test)
{
	struct mctp_interface interface;
	struct cmd_interface_mock cmd_interface;
	struct device_manager device_mgr;
	uint8_t cert_digest_request[5] = {MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, 1, 2, 3, 4};
 	uint8_t buf[MCTP_PROTOCOL_MAX_MESSAGE_LEN];
	int status;

	TEST_START;

	setup_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr, &interface);

	status = mock_expect (&cmd_interface.mock, cmd_interface.base.issue_request, &cmd_interface,
		MCTP_PROTOCOL_MAX_PAYLOAD_PER_PKT + 1, MOCK_ARG (CERBERUS_PROTOCOL_GET_CERTIFICATE),
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL, MOCK_ARG (MCTP_PROTOCOL_MAX_PAYLOAD_PER_PKT));
	status |= mock_expect_output (&cmd_interface.mock, 2, cert_digest_request, 5, -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&interface, 0x77, 0xFF, 0x5D, 0x0B,
		CERBERUS_PROTOCOL_GET_CERTIFICATE, &cert_digest_request, buf, sizeof (buf),
		MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF);
	CuAssertIntEquals (test, MCTP_PROTOCOL_BAD_BUFFER_LENGTH, status);

	complete_mctp_interface_with_interface_mock_test (test, &cmd_interface, &device_mgr,
		&interface);
}

CuSuite* get_mctp_interface_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, mctp_interface_test_init);
	SUITE_ADD_TEST (suite, mctp_interface_test_init_null);
	SUITE_ADD_TEST (suite, mctp_interface_test_deinit_null);
	SUITE_ADD_TEST (suite, mctp_interface_test_set_channel_id);
	SUITE_ADD_TEST (suite, mctp_interface_test_set_channel_id_null);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_null);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_req);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_unsupported_message);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_crc);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_packet_too_small);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_not_intended_target);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_interpret_fail_not_intended_target);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_out_of_order);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_no_som);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_msg_tag);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_dest_eid);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_src_eid);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_packet_seq);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_invalid_msg_size);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_msg_overflow);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_cmd_interface_fail);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_cmd_interface_fail_cmd_set_1);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_error_packet);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_no_response);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_no_response_cmd_set_1);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_unsupported_type);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_mctp_control_msg);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_mctp_control_msg_fail);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_one_packet_request);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_one_packet_response);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_two_packet_response);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_channel_id_reset_next_som);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_normal_timeout);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_crypto_timeout);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_max_message);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_no_eom);
	SUITE_ADD_TEST (suite, mctp_interface_test_process_packet_reset_message_processing);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request_mctp_ctrl_msg);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request_null);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request_fail);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request_mctp_ctrl_msg_fail);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request_unsupported_msg_type);
	SUITE_ADD_TEST (suite, mctp_interface_test_issue_request_construct_packet_fail);

	return suite;
}
