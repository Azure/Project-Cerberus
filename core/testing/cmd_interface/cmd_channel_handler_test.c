// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "cmd_interface/cmd_channel_handler.h"
#include "cmd_interface/cmd_channel_handler_static.h"
#include "cmd_interface/msg_transport.h"
#include "crypto/checksum.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_interface.h"
#include "mctp/msg_transport_mctp_message.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/cmd_interface_multi_handler_mock.h"
#include "testing/mock/cmd_interface/msg_transport_mock.h"

TEST_SUITE_LABEL ("cmd_channel_handler");


/**
 * Dependencies for testing.
 */
struct cmd_channel_handler_testing {
	struct cmd_channel_mock channel;						/**< Command channel mock instance. */
	struct cmd_interface_multi_handler_mock req_handler;	/**< Handler for MCTP requests. */
	struct cmd_interface_mock cmd_cerberus;					/**< Cerberus protocol command interface mock instance. */
	struct device_manager device_mgr;						/**< Device manager. */
	struct mctp_interface_state mctp_state;					/**< Variable context for the MCTP handler. */
	struct mctp_interface mctp;								/**< MCTP message handler. */
	struct cmd_channel_handler test;						/**< Command processor for testing. */
	struct msg_transport_mock mctp_control;					/**< MCTP control message transport API for sending requests. */
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

	status = cmd_interface_multi_handler_mock_init (&handler->req_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&handler->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = msg_transport_mock_init (&handler->mctp_control);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&handler->device_mgr, 3, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x51, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 2,
		MCTP_BASE_PROTOCOL_NULL_EID, 0x54, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&handler->mctp, &handler->mctp_state, &handler->req_handler.base,
		&handler->device_mgr, &handler->channel.base, &handler->cmd_cerberus.base, NULL, NULL);
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

	status = cmd_channel_handler_init (&handler->test, &handler->channel.base, &handler->mctp,
		&handler->mctp_control.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an instance for testing.
 *
 * @param test The testing framework.
 * @param handler The testing components to initialize.
 */
static void cmd_channel_handler_testing_init_notify_null_eid (CuTest *test,
	struct cmd_channel_handler_testing *handler)
{
	int status;

	cmd_channel_handler_testing_init_dependencies (test, handler);

	status = cmd_channel_handler_init_notify_null_eid (&handler->test, &handler->channel.base,
		&handler->mctp, &handler->mctp_control.base);
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
	status |= cmd_interface_multi_handler_mock_validate_and_release (&handler->req_handler);
	status |= cmd_interface_mock_validate_and_release (&handler->cmd_cerberus);
	status |= msg_transport_mock_validate_and_release (&handler->mctp_control);

	CuAssertIntEquals (test, 0, status);

	device_manager_release (&handler->device_mgr);
	mctp_interface_release (&handler->mctp);
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

static void cmd_channel_handler_test_prepare_1 (CuTest *test,
	struct cmd_channel_handler_testing *handler, struct msg_transport_mctp_message *mctp_message,
	struct cmd_interface_protocol_mctp *mctp_protocol, struct cmd_packet *tx_packet)
{
	uint8_t data[10];
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) tx_packet->data;
	int status;

	TEST_START;

	status = cmd_channel_mock_init (&handler->channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_multi_handler_mock_init (&handler->req_handler);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&handler->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&handler->device_mgr, 3, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x51, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_protocol_mctp_init (mctp_protocol);
	CuAssertIntEquals (test, 0, status);

	status = msg_transport_mctp_message_init (mctp_message, &handler->mctp.base, mctp_protocol,
		MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_init (&handler->mctp, &handler->mctp_state, &handler->req_handler.base,
		&handler->device_mgr, &handler->channel.base, &handler->cmd_cerberus.base, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_handler_init (&handler->test, &handler->channel.base, &handler->mctp,
		&mctp_message->base.base);
	CuAssertIntEquals (test, 0, status);

	/* Change the MCTP bridge EID. */
	status = device_manager_update_not_attestable_device_entry (&handler->device_mgr, 1, 0x78, 0x56,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	data[1] = 0x80;
	data[2] = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;

	memset (tx_packet, 0, sizeof (*tx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 8;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x78;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	memcpy (&tx_packet->data[7], data, 3);

	tx_packet->data[10] = checksum_crc8 (0xAC, tx_packet->data, 10);
	tx_packet->pkt_size = 11;
	tx_packet->state = CMD_VALID_PACKET;
	tx_packet->dest_addr = 0x56;
	tx_packet->timeout_valid = false;

	status = mock_expect (&handler->channel.mock, handler->channel.base.send_packet,
		&handler->channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, tx_packet, sizeof (*tx_packet)));
	CuAssertIntEquals (test, 0, status);
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

	status = cmd_channel_handler_init (&handler.test, &handler.channel.base, &handler.mctp,
		&handler.mctp_control.base);
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

	status = cmd_channel_handler_init (NULL, &handler.channel.base, &handler.mctp,
		&handler.mctp_control.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init (&handler.test, NULL, &handler.mctp,
		&handler.mctp_control.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init (&handler.test, &handler.channel.base, NULL,
		&handler.mctp_control.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init (&handler.test, &handler.channel.base, &handler.mctp, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}

static void cmd_channel_handler_test_init_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	status = cmd_channel_handler_init_notify_null_eid (&handler.test, &handler.channel.base,
		&handler.mctp, &handler.mctp_control.base);
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

static void cmd_channel_handler_test_init_notify_null_eid_null (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	int status;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	status = cmd_channel_handler_init_notify_null_eid (NULL, &handler.channel.base, &handler.mctp,
		&handler.mctp_control.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init_notify_null_eid (&handler.test, NULL, &handler.mctp,
		&handler.mctp_control.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init_notify_null_eid (&handler.test, &handler.channel.base, NULL,
		&handler.mctp_control.base);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	status = cmd_channel_handler_init_notify_null_eid (&handler.test, &handler.channel.base,
		&handler.mctp, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}

static void cmd_channel_handler_test_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp, &handler.mctp_control.base);

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

static void cmd_channel_handler_test_static_init_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static =
		cmd_channel_handler_static_init_notify_null_eid (&handler.channel.base,	&handler.mctp,
		&handler.mctp_control.base);

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

static void cmd_channel_handler_test_send_discovery_notify_no_response (
	CuTest *test, struct cmd_channel_handler_testing *hanlder, uint8_t bridge_eid)
{
	struct mctp_control_discovery_notify *request;
	uint8_t *tx_message = NULL;
	struct cmd_interface_msg *req_expected = NULL;
	uint32_t timeout_ms = 0;
	int status = 0;

	TEST_START;

	/* Request contruction starts */
	tx_message = platform_calloc (1, sizeof (struct mctp_control_discovery_notify));
	req_expected = platform_calloc (1, sizeof (struct cmd_interface_msg));
	req_expected->data = (uint8_t*) tx_message;
	req_expected->length = sizeof (struct mctp_control_discovery_notify);
	req_expected->max_response = MCTP_BASE_PROTOCOL_MIN_MESSAGE_LEN;
	req_expected->payload = tx_message;
	req_expected->payload_length = sizeof (struct mctp_control_discovery_notify);
	req_expected->target_eid = bridge_eid;

	request = (struct mctp_control_discovery_notify*) req_expected->payload;
	request->header.command_code = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;
	request->header.rq = 1;
	/* Request contruction ends. */

	status = mock_expect (&hanlder->mctp_control.mock,
		hanlder->mctp_control.base.get_buffer_overhead,	&hanlder->mctp_control, 0,
		MOCK_ARG (bridge_eid), MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hanlder->mctp_control.mock,
		hanlder->mctp_control.base.get_max_message_payload_length, &hanlder->mctp_control,
		MCTP_BASE_PROTOCOL_MIN_MESSAGE_LEN, MOCK_ARG (bridge_eid));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hanlder->mctp_control.mock,
		hanlder->mctp_control.base.send_request_message, &hanlder->mctp_control.base,
		MSG_TRANSPORT_NO_WAIT_RESPONSE,
		MOCK_ARG_VALIDATOR_DEEP_COPY_TMP (cmd_interface_mock_validate_request, req_expected,
		sizeof (*req_expected), cmd_interface_mock_save_request, cmd_interface_mock_free_request,
		cmd_interface_mock_duplicate_request), MOCK_ARG (timeout_ms), MOCK_ARG_ANY);

	cmd_interface_mock_free_request (req_expected);
	CuAssertIntEquals (test, 0, status);
}


#ifdef CMD_ENABLE_ISSUE_REQUEST
static void cmd_channel_handler_test_prepare (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct msg_transport_mctp_message mctp_message;
	struct cmd_interface_protocol_mctp mctp_protocol;
	struct cmd_packet tx_packet;

	TEST_START;

	cmd_channel_handler_test_prepare_1 (test, &handler, &mctp_message, &mctp_protocol, &tx_packet);

	handler.test.base.prepare (&handler.test.base);

	int status;

	status = cmd_channel_mock_validate_and_release (&handler.channel);
	status |= cmd_interface_multi_handler_mock_validate_and_release (&handler.req_handler);
	status |= cmd_interface_mock_validate_and_release (&handler.cmd_cerberus);

	CuAssertIntEquals (test, 0, status);

	device_manager_release (&handler.device_mgr);
	mctp_interface_release (&handler.mctp);
}

static void cmd_channel_handler_test_prepare_stack (CuTest *test)
{
	struct cmd_channel_handler_testing handler;

	TEST_START;

	cmd_channel_handler_testing_init (test, &handler);
	cmd_channel_handler_test_send_discovery_notify_no_response (test, &handler, 0x0A);

	handler.test.base.prepare (&handler.test.base);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_prepare_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;

	TEST_START;

	cmd_channel_handler_testing_init_notify_null_eid (test, &handler);
	cmd_channel_handler_test_send_discovery_notify_no_response (test, &handler, 0x0);

	handler.test.base.prepare (&handler.test.base);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_prepare_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp, &handler.mctp_control.base);

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);
	cmd_channel_handler_test_send_discovery_notify_no_response (test, &handler, 0x0A);

	test_static.base.prepare (&test_static.base);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}

static void cmd_channel_handler_test_prepare_static_init_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static =
		cmd_channel_handler_static_init_notify_null_eid (&handler.channel.base,	&handler.mctp,
		&handler.mctp_control.base);

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);
	cmd_channel_handler_test_send_discovery_notify_no_response (test, &handler, 0x0);

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

static void cmd_channel_handler_test_get_next_execution_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	const platform_clock *next_time;

	TEST_START;

	cmd_channel_handler_testing_init_notify_null_eid (test, &handler);

	next_time = handler.test.base.get_next_execution (&handler.test.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_get_next_execution_static_init (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static = cmd_channel_handler_static_init (&handler.channel.base,
		&handler.mctp, &handler.mctp_control.base);
	const platform_clock *next_time;

	TEST_START;

	cmd_channel_handler_testing_init_dependencies (test, &handler);

	next_time = test_static.base.get_next_execution (&test_static.base);
	CuAssertPtrEquals (test, NULL, (void*) next_time);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}

static void cmd_channel_handler_test_get_next_execution_static_init_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static =
		cmd_channel_handler_static_init_notify_null_eid (&handler.channel.base,	&handler.mctp,
		&handler.mctp_control.base);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.receive_packet,
		&handler.channel, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&handler.channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&handler.req_handler.mock,
		handler.req_handler.base.is_message_type_supported, &handler.req_handler, 0,
		MOCK_ARG (0x7e));

	status |= mock_expect (&handler.req_handler.mock, handler.req_handler.base.base.process_request,
		&handler.req_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output_deep_copy (&handler.req_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&handler.channel.mock, handler.channel.base.send_packet,
		&handler.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	handler.test.base.execute (&handler.test.base);

	cmd_channel_handler_testing_validate_and_release (test, &handler);
}

static void cmd_channel_handler_test_execute_notify_null_eid (CuTest *test)
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

	cmd_channel_handler_testing_init_notify_null_eid (test, &handler);

	memset (&rx_packet, 0, sizeof (rx_packet));
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.receive_packet,
		&handler.channel, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&handler.channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&handler.req_handler.mock,
		handler.req_handler.base.is_message_type_supported, &handler.req_handler, 0,
		MOCK_ARG (0x7e));

	status |= mock_expect (&handler.req_handler.mock, handler.req_handler.base.base.process_request,
		&handler.req_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output_deep_copy (&handler.req_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

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
		&handler.mctp, &handler.mctp_control.base);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.receive_packet,
		&handler.channel, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&handler.channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&handler.req_handler.mock,
		handler.req_handler.base.is_message_type_supported, &handler.req_handler, 0,
		MOCK_ARG (0x7e));

	status |= mock_expect (&handler.req_handler.mock, handler.req_handler.base.base.process_request,
		&handler.req_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output_deep_copy (&handler.req_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&handler.channel.mock, handler.channel.base.send_packet,
		&handler.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	test_static.base.execute (&test_static.base);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}

static void cmd_channel_handler_test_execute_static_init_notify_null_eid (CuTest *test)
{
	struct cmd_channel_handler_testing handler;
	struct cmd_channel_handler test_static =
		cmd_channel_handler_static_init_notify_null_eid (&handler.channel.base,	&handler.mctp,
		&handler.mctp_control.base);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&handler.channel.mock, handler.channel.base.receive_packet,
		&handler.channel, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (-1));
	status |= mock_expect_output (&handler.channel.mock, 0, &rx_packet, sizeof (rx_packet), -1);

	status |= mock_expect (&handler.req_handler.mock,
		handler.req_handler.base.is_message_type_supported, &handler.req_handler, 0,
		MOCK_ARG (0x7e));

	status |= mock_expect (&handler.req_handler.mock, handler.req_handler.base.base.process_request,
		&handler.req_handler, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
		sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	status |= mock_expect_output_deep_copy (&handler.req_handler.mock, 0, &response,
		sizeof (response), cmd_interface_mock_copy_request);

	status |= mock_expect (&handler.channel.mock, handler.channel.base.send_packet,
		&handler.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	test_static.base.execute (&test_static.base);

	cmd_channel_handler_testing_release_dependencies (test, &handler);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_channel_handler);

TEST (cmd_channel_handler_test_init);
TEST (cmd_channel_handler_test_init_null);
TEST (cmd_channel_handler_test_init_notify_null_eid);
TEST (cmd_channel_handler_test_init_notify_null_eid_null);
TEST (cmd_channel_handler_test_static_init);
TEST (cmd_channel_handler_test_static_init_notify_null_eid);
TEST (cmd_channel_handler_test_release_null);
#ifdef CMD_ENABLE_ISSUE_REQUEST
TEST (cmd_channel_handler_test_prepare);
TEST (cmd_channel_handler_test_prepare_notify_null_eid);
TEST (cmd_channel_handler_test_prepare_static_init);
TEST (cmd_channel_handler_test_prepare_static_init_notify_null_eid);
#endif
TEST (cmd_channel_handler_test_prepare_stack);
TEST (cmd_channel_handler_test_get_next_execution);
TEST (cmd_channel_handler_test_get_next_execution_notify_null_eid);
TEST (cmd_channel_handler_test_get_next_execution_static_init);
TEST (cmd_channel_handler_test_get_next_execution_static_init_notify_null_eid);
TEST (cmd_channel_handler_test_execute);
TEST (cmd_channel_handler_test_execute_notify_null_eid);
TEST (cmd_channel_handler_test_execute_static_init);
TEST (cmd_channel_handler_test_execute_static_init_notify_null_eid);

TEST_SUITE_END;
// *INDENT-ON*
