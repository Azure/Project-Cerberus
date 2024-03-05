// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include "platform_api.h"
#include "testing.h"
#include "cmd_interface/cerberus_protocol_master_commands.h"
#include "common/array_size.h"
#include "common/common_math.h"
#include "common/unused.h"
#include "crypto/checksum.h"
#include "mctp/mctp_base_protocol.h"
#include "mctp/mctp_control_protocol.h"
#include "mctp/mctp_control_protocol_commands.h"
#include "mctp/mctp_interface.h"
#include "mctp/mctp_interface_static.h"
#include "mctp/mctp_logging.h"
#include "spdm/cmd_interface_spdm.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/cmd_interface/cmd_channel_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/logging/debug_log_testing.h"


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
	struct cmd_channel_mock channel;			/**< Command channel mock instance. */
	struct cmd_interface_mock cmd_cerberus;		/**< Command interface for Cerberus protocol mock instance. */
	struct cmd_interface_mock cmd_mctp;			/**< MCTP control protocol command interface mock instance. */
	struct cmd_interface_mock cmd_spdm;			/**< Command interface for SPDM protocol mock instance. */
	struct logging_mock log;					/**< Mock for the debug log. */
	struct device_manager device_mgr;			/**< Device manager. */
	struct mctp_interface_state state;			/**< Variable context for the MCTP handler. */
	struct mctp_interface test;					/**< MCTP handler being tested. */
};

/**
 * Response callback context.
 */
struct mctp_interface_test_callback_context {
	struct mctp_interface_testing *mctp;		/**< Testing components to utilize. */
	struct cmd_packet *rsp_packet;				/**< Response packet to send back. */
	size_t packet_count;						/**< The number of response packets. */
	CuTest *test;								/**< Test framework. */
	int expected_status;						/**< Expected process_packet completion status. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to initialize.
 */
static void mctp_interface_testing_init_dependencies (CuTest *test,
	struct mctp_interface_testing *mctp)
{
	struct device_manager_full_capabilities capabilities;
	int status;

	status = cmd_interface_mock_init (&mctp->cmd_cerberus);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&mctp->cmd_mctp);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&mctp->cmd_spdm);
	CuAssertIntEquals (test, 0, status);

	status = cmd_channel_mock_init (&mctp->channel, 0);
	CuAssertIntEquals (test, 0, status);

	status = logging_mock_init (&mctp->log);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&mctp->device_mgr, 2, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp->device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp->device_mgr, 1,
		MCTP_BASE_PROTOCOL_BMC_EID, 0x51, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp->device_mgr, 0, &capabilities);
	capabilities.request.hierarchy_role = DEVICE_MANAGER_PA_ROT_MODE;

	status = device_manager_update_device_capabilities (&mctp->device_mgr, 0, &capabilities);
	CuAssertIntEquals (test, 0, status);

	debug_log = &mctp->log.base;
}

/**
 * Release all testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing dependencies to release.
 */
static void mctp_interface_testing_release_dependencies (CuTest *test,
	struct mctp_interface_testing *mctp)
{
	int status;

	debug_log = NULL;

	status = cmd_interface_mock_validate_and_release (&mctp->cmd_cerberus);
	status |= cmd_interface_mock_validate_and_release (&mctp->cmd_mctp);
	status |= cmd_interface_mock_validate_and_release (&mctp->cmd_spdm);
	status |= cmd_channel_mock_validate_and_release (&mctp->channel);
	status |= logging_mock_validate_and_release (&mctp->log);

	CuAssertIntEquals (test, 0, status);

	device_manager_release (&mctp->device_mgr);
}

/**
 * Initialize an MCTP handler for testing.
 *
 * @param test The test framework.
 * @param mctp Testing components to initialize.
 */
static void mctp_interface_testing_init (CuTest *test, struct mctp_interface_testing *mctp)
{
	int status;

	mctp_interface_testing_init_dependencies (test, mctp);

	status = mctp_interface_init (&mctp->test, &mctp->state, &mctp->cmd_cerberus.base,
		&mctp->cmd_mctp.base, &mctp->cmd_spdm.base, &mctp->device_mgr, &mctp->channel.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static MCTP handler for testing.
 *
 * @param test The test framework.
 * @param mctp Testing components to initialize.
 */
static void mctp_interface_testing_init_static (CuTest *test, struct mctp_interface_testing *mctp)
{
	int status;

	mctp_interface_testing_init_dependencies (test, mctp);

	status = mctp_interface_init_state (&mctp->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release MCTP test components and validate all mocks.
 *
 * @param test The test framework.
 * @param mctp Testing components to release.
 */
static void mctp_interface_testing_release (CuTest *test, struct mctp_interface_testing *mctp)
{
	mctp_interface_release (&mctp->test);
	mctp_interface_testing_release_dependencies (test, mctp);
}

/**
 * Callback function which sends an MCTP response message to process_packet
 *
 * @param expected The expectation that is being used to validate the current call on the mock.
 * @param called The context for the actual call on the mock.
 *
 * @return This function always returns 0
 */
static int64_t mctp_interface_testing_process_packet_callback (const struct mock_call *expected,
	const struct mock_call *called)
{
	struct mctp_interface_test_callback_context *context = expected->context;
	struct cmd_message *tx;
	size_t i;
	int status;

	UNUSED (called);

	for (i = 0; i < context->packet_count; i++) {
		status = mctp_interface_process_packet (&context->mctp->test, &context->rsp_packet[i], &tx);
		CuAssertIntEquals (context->test, context->expected_status, status);
	}

	return 0;
}

/**
 * Helper function that generates an MCTP request and calls issue_request.
 *
 * @param test The test framework.
 * @param mctp The testing instances to utilize.
 * @param context Callback context to utilize.
 * @param issue_request_status Expected issue_request completion status.
 * @param msg_type Message type of request.
 * @param msg_tag Message tag to use in request.
 */
static void mctp_interface_testing_generate_and_issue_request (CuTest *test,
	struct mctp_interface_testing *mctp, struct mctp_interface_test_callback_context *context,
	int issue_request_status, uint8_t msg_type, uint8_t msg_tag)
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
	header->msg_tag = msg_tag;
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

	status = mctp_interface_issue_request (&mctp->test, &mctp->channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 100);
	CuAssertIntEquals (test, issue_request_status, status);
}

/*******************
 * Test cases
 *******************/

static void mctp_interface_test_init (CuTest *test)
{
	struct mctp_interface_testing mctp;
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, 0, status);

#ifdef CMD_ENABLE_ISSUE_REQUEST
	CuAssertPtrNotNull (test, mctp.test.base.get_max_message_overhead);
	CuAssertPtrNotNull (test, mctp.test.base.get_max_message_payload_length);
	CuAssertPtrNotNull (test, mctp.test.base.get_max_encapsulated_message_length);
	CuAssertPtrNotNull (test, mctp.test.base.send_request_message);
#endif

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_init_spdm_not_supported (CuTest *test)
{
	struct mctp_interface_testing mctp;
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, NULL, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_init_no_cmd_channel (CuTest *test)
{
	struct mctp_interface_testing mctp;
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, NULL);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_init_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init (NULL, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.test, NULL, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.test, &mctp.state, NULL,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		NULL, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, NULL, &mctp.channel.base);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	mctp_interface_testing_release_dependencies (test, &mctp);
}

static void mctp_interface_test_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	int status;

	TEST_START;

#ifdef CMD_ENABLE_ISSUE_REQUEST
	CuAssertPtrNotNull (test, mctp.test.base.get_max_message_overhead);
	CuAssertPtrNotNull (test, mctp.test.base.get_max_message_payload_length);
	CuAssertPtrNotNull (test, mctp.test.base.get_max_encapsulated_message_length);
	CuAssertPtrNotNull (test, mctp.test.base.send_request_message);
#endif

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init_state (&mctp.test);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_static_init_spdm_not_supported (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, NULL, &mctp.device_mgr, &mctp.channel.base)
	};
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init_state (&mctp.test);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_static_init_no_cmd_channel (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, NULL)
	};
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init_state (&mctp.test);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_static_init_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface no_state = mctp_interface_static_init (NULL, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	struct mctp_interface no_cerberus = mctp_interface_static_init (&mctp.state, NULL,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	struct mctp_interface no_mctp = mctp_interface_static_init (&mctp.state,
		&mctp.cmd_cerberus.base, NULL, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base);
	struct mctp_interface no_dev_mgr = mctp_interface_static_init (&mctp.state,
		&mctp.cmd_cerberus.base, &mctp.cmd_mctp.base, &mctp.cmd_spdm.base, NULL,
		&mctp.channel.base);
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init_state (NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init_state (&no_state);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init_state (&no_cerberus);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init_state (&no_mctp);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_init_state (&no_dev_mgr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	mctp_interface_testing_release_dependencies (test, &mctp);
}

static void mctp_interface_test_release_null (CuTest *test)
{
	TEST_START;

	mctp_interface_release (NULL);
}

static void mctp_interface_test_set_channel_id (CuTest *test)
{
	struct mctp_interface_testing mctp;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_set_channel_id (&mctp.test, 1);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_set_channel_id_null (CuTest *test)
{
	int status;

	TEST_START;

	status = mctp_interface_set_channel_id (NULL, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus,	0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus,	0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (1));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
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
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
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

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
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
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_set_channel_id (&mctp.test, 1);
	CuAssertIntEquals (test, 0, status);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 1;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, tx);

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
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
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
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
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = sizeof (response_data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = true;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	platform_msleep (20);
	CuAssertIntEquals (test, true, platform_has_timeout_expired (&rx.pkt_timeout));

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->som = 0;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 1;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 2;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 3;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	i += 232;
	header->packet_seq = 0;
	memcpy (&rx.data[7], &msg_data[i], 232);
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	size_t max_packets = ceil ((MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY * 1.0) /
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * (max_packets - 1));
	int status;
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	size_t max_packets = ceil ((MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY * 1.0) /
		MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT);
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * (max_packets - 1));
	int status;
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MIN_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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

	mctp_interface_testing_init (test, &mctp);

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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
	/* TODO:  Do we really need to be inspecting internal MCTP state?  Is there no way to verify
	 * this is correct through verification of external interactions? */
	CuAssertIntEquals (test, sizeof (mctp.test.state->msg_buffer),
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * max_packets));

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf10a0b00,
		.arg2 = 0
	};

	TEST_START;

	memset (rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx[0], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_reset_message_processing (&mctp.test);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx[1], &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - 128;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_spdm_request (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));

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

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	/* TODO:  Will add support for SPDM requests. */
	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_drop_unexpected_response_message (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_UNEXPECTED,
		.arg2 = 0
	};

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	/* The unknown response message will get silently dropped. */
	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init_static (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus,	0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_static_init_mctp_control_request (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
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

	mctp_interface_testing_init_static (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_static_init_spdm_request (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));

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

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
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

	mctp_interface_testing_init_static (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	/* TODO:  Will add support for SPDM requests. */
	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (NULL, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&mctp.test, NULL, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x01ab0f00,
		.arg2 = 0x12c80a0b
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x010a0b00,
		.arg2 = MCTP_BASE_PROTOCOL_INVALID_MSG
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (0x7F001606), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x01ab0f0f,
		.arg2 = 0x12c80a0b
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x010a0b00,
		.arg2 = MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (0x7F00160B), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x01ab0f0f,
		.arg2 = 0x12c80a0b
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf00a0b00,
		.arg2 = 0x00000086
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM),
		MOCK_ARG (checksum_crc8 (0xBA, rx.data, 17)), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_packet_too_small (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x00000000,
		.arg2 = 0x01000000
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));

	rx.pkt_size = 1;
	rx.dest_addr = 0x5D;

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_interpret_fail_not_intended_target (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x01ab0f00,
		.arg2 = 0x12c80a0c
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x010a0c00,
		.arg2 = MCTP_BASE_PROTOCOL_INVALID_MSG
	};

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x01ab020f,
		.arg2 = 0x0500000b
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf10a0b00,
		.arg2 = 0
	};

	TEST_START;

	memset (rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx[0], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx[1], &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_SHORT, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx[2], &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf10a0b00,
		.arg2 = 0
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x010a0b01,
		.arg2 = 0
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x01;
	header->packet_seq = 1;

	rx.data[sizeof (struct mctp_base_protocol_transport_header)] = 0x11;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->source_eid = 0x0C;
	header->som = 0;
	header->eom = 1;
	header->packet_seq = 1;

	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf30a0b00,
		.arg2 = 0
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->som = 0;
	header->packet_seq = 2;
	rx.data[17] = checksum_crc8 (0xBA, rx.data, 17);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW), MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf40a0b00,
		.arg2 = 9
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->byte_count = 14;
	header->som = 0;
	header->packet_seq = 1;

	rx.data[16] = checksum_crc8 (0xBA, rx.data, 16);
	rx.pkt_size = 17;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN), MOCK_ARG (9), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0xf50a0b00,
		.arg2 = 4097
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->som = 0;
	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 1;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 2;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 3;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	header->packet_seq = 0;
	rx.data[239] = checksum_crc8 (0xBA, rx.data, 239);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PKT_DROPPED,
		.arg1 = 0x01ab0f0f,
		.arg2 = 0x12c80a0b
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x010a0b00,
		.arg2 = MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&error_packet, 0, sizeof (error_packet));

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
	error->error_code = CERBERUS_PROTOCOL_ERROR_INVALID_REQ;
	error->error_data = MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG;

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_INVALID_REQ),
		MOCK_ARG (MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x040a0b00,
		.arg2 = CMD_HANDLER_PROCESS_FAILED
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus,	CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (CMD_HANDLER_PROCESS_FAILED), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x040a0b00,
		.arg2 = CMD_HANDLER_PROCESS_FAILED
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus,	CMD_HANDLER_PROCESS_FAILED,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (CMD_HANDLER_PROCESS_FAILED), MOCK_ARG (1));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_process_packet_mctp_control_request_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx;
	struct cmd_message *tx;
	uint8_t data[10];
	struct cmd_interface_msg request;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL,
		.arg1 = CMD_HANDLER_NO_MEMORY,
		.arg2 = 0
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_request, &mctp.cmd_mctp,
		CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &request,
			sizeof (request), cmd_interface_mock_save_request, cmd_interface_mock_free_request));

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, CMD_HANDLER_NO_MEMORY, status);

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x040a0b00,
		.arg2 = MCTP_BASE_PROTOCOL_MSG_TOO_LARGE
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
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
	response.data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	response.data[1] = 0x12;
	response.length = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.crypto_timeout = false;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (0x7F001605), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_CHANNEL,
		.arg1 = 0,
		.arg2 = 0
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_PROTOCOL_ERROR,
		.arg1 = 0x040a0b00,
		.arg2 = MCTP_BASE_PROTOCOL_MSG_TOO_LARGE
	};

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

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
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
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

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_ERROR_UNSPECIFIED),
		MOCK_ARG (0x7F001605), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
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

	mctp_interface_testing_release (test, &mctp);
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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, CMD_HANDLER_ERROR_MSG_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR), MOCK_ARG (0), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, CMD_HANDLER_ERROR_MSG_FAILED, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
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
	memset (&request, 0, sizeof (request));
	memset (&response, 0, sizeof (response));
	memset (&error_packet, 0, sizeof (error_packet));

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

	mctp_interface_testing_init (test, &mctp);

	request.data = data;
	request.length = sizeof (data);
	memcpy (request.data, &rx.data[7], request.length);
	request.payload = data;
	request.payload_length = sizeof (data);
	request.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	request.source_addr = 0x55;
	request.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	request.is_encrypted = false;
	request.crypto_timeout = false;
	request.channel_id = 0;
	request.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	memset (&response, 0, sizeof (response));
	response.data = data;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_request,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&request, sizeof (request), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &response, sizeof (response), -1);

	status |= mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.generate_error_packet,
		&mctp.cmd_cerberus, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (CERBERUS_PROTOCOL_NO_ERROR),
		MOCK_ARG (0), MOCK_ARG (0));
	status |= mock_expect_output (&mctp.cmd_cerberus.mock, 0, &error_packet, sizeof (error_packet),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx, &tx);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_LARGE, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_reset_message_processing_null (CuTest *test)
{
	struct mctp_interface_testing mctp;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	mctp_interface_reset_message_processing (NULL);

	mctp_interface_testing_release (test, &mctp);
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
static void mctp_interface_test_get_max_message_overhead (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0x12;
	size_t max_packet = 128;
	size_t max_message = 1024;
	int status;
	size_t smbus_overhead = 8;
	size_t pkt_size = min (max_packet, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	size_t msg_size = min (max_message, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY);
	size_t max_packets = (msg_size + (pkt_size - 1)) / pkt_size;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, eid, 0x51,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.get_max_message_overhead (&mctp.test.base, eid);
	CuAssertIntEquals (test, max_packets * smbus_overhead, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_overhead_unknown_device (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t eid = 0x34;
	int status;
	size_t smbus_overhead = 8;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	size_t msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	size_t max_packets = (msg_size + (pkt_size - 1)) / pkt_size;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.get_max_message_overhead (&mctp.test.base, eid);
	CuAssertIntEquals (test, max_packets * smbus_overhead, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_overhead_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0x24;
	size_t max_packet = 75;
	size_t max_message = 955;
	int status;
	size_t smbus_overhead = 8;
	size_t pkt_size = min (max_packet, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	size_t msg_size = min (max_message, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY);
	size_t max_packets = (msg_size + (pkt_size - 1)) / pkt_size;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, eid, 0x51,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.get_max_message_overhead (&mctp.test.base, eid);
	CuAssertIntEquals (test, max_packets * smbus_overhead, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_overhead_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t eid = 0x34;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.get_max_message_overhead (NULL, eid);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_payload_length (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0x12;
	size_t max_packet = 128;
	size_t max_message = 1024;
	int status;
	size_t msg_size = min (max_message, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY);

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, eid, 0x51,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.get_max_message_payload_length (&mctp.test.base, eid);
	CuAssertIntEquals (test, msg_size, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_payload_length_unknown_device (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t eid = 0x34;
	int status;
	size_t msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.get_max_message_payload_length (&mctp.test.base, eid);
	CuAssertIntEquals (test, msg_size, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_payload_length_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0x24;
	size_t max_packet = 75;
	size_t max_message = 955;
	int status;
	size_t msg_size = min (max_message, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY);

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, eid, 0x51,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.get_max_message_payload_length (&mctp.test.base, eid);
	CuAssertIntEquals (test, msg_size, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_message_payload_length_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t eid = 0x34;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.get_max_message_payload_length (NULL, eid);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_encapsulated_message_length (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0x12;
	size_t max_packet = 128;
	size_t max_message = 1024;
	int status;
	size_t smbus_overhead = 8;
	size_t pkt_size = min (max_packet, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	size_t msg_size = min (max_message, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY);
	size_t max_packets = (msg_size + (pkt_size - 1)) / pkt_size;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, eid, 0x51,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.get_max_encapsulated_message_length (&mctp.test.base, eid);
	CuAssertIntEquals (test, (max_packets * smbus_overhead) + msg_size, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_encapsulated_message_length_unknown_device (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t eid = 0x34;
	int status;
	size_t smbus_overhead = 8;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT;
	size_t msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	size_t max_packets = (msg_size + (pkt_size - 1)) / pkt_size;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.get_max_encapsulated_message_length (&mctp.test.base, eid);
	CuAssertIntEquals (test, (max_packets * smbus_overhead) + msg_size, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_encapsulated_message_length_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct device_manager_full_capabilities capabilities;
	uint8_t eid = 0x24;
	size_t max_packet = 75;
	size_t max_message = 955;
	int status;
	size_t smbus_overhead = 8;
	size_t pkt_size = min (max_packet, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	size_t msg_size = min (max_message, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY);
	size_t max_packets = (msg_size + (pkt_size - 1)) / pkt_size;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, eid, 0x51,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = max_packet;
	capabilities.request.max_message_size = max_message;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.get_max_encapsulated_message_length (&mctp.test.base, eid);
	CuAssertIntEquals (test, (max_packets * smbus_overhead) + msg_size, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_get_max_encapsulated_message_length_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t eid = 0x34;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.get_max_encapsulated_message_length (NULL, eid);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_max_size (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * (ARRAY_SIZE (tx_packet) - 1));
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Change EID and address settings for the devices. */
	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 0, 0x23, 0x45,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, 0x78, 0x56,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		0x78, &request);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < request.payload_length; i++) {
		request.payload[i] = i;
	}

	cmd_interface_msg_set_message_payload_length (&request, request.payload_length);

	/* Construct the expected packets generated for the message. */
	memset (tx_packet, 0, sizeof (tx_packet));

	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = pkt_size - 3;
		header->source_addr = 0x8B;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = 0x78;
		header->source_eid = 0x23;
		header->som = !i;
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
		header->msg_tag = 0;
		header->packet_seq = i % 4;

		memcpy (&tx_packet[i].data[7],
			&request.payload[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i],
			MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);

		tx_packet[i].data[pkt_size - 1] = checksum_crc8 (0xAC, tx_packet[i].data, pkt_size - 1);
		tx_packet[i].pkt_size = pkt_size;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x56;
		tx_packet[i].timeout_valid = false;
	}

	header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = last_pkt_size - 3;
	header->source_addr = 0x8B;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x78;
	header->source_eid = 0x23;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0;
	header->packet_seq = i % 4;

	memcpy (&tx_packet[i].data[7],
		&request.payload[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i], remain);

	tx_packet[i].data[last_pkt_size - 1] = checksum_crc8 (0xAC, tx_packet[i].data,
		last_pkt_size - 1);
	tx_packet[i].pkt_size = last_pkt_size;
	tx_packet[i].state = CMD_VALID_PACKET;
	tx_packet[i].dest_addr = 0x56;
	tx_packet[i].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAD;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x23;
	header->source_eid = 0x78;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x11;
	rx_packet.data[9] = 0x12;
	rx_packet.data[10] = 0x13;
	rx_packet.data[11] = 0x14;
	rx_packet.data[12] = 0x15;
	rx_packet.data[13] = 0x16;
	rx_packet.data[14] = 0x17;
	rx_packet.data[15] = 0x18;
	rx_packet.data[16] = 0x19;
	rx_packet.data[17] = checksum_crc8 (0x8A, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x45;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = 0;
	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (tx_packet[i])));
	}

	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
			sizeof (tx_packet[i])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, 0x78, response.source_eid);
	CuAssertIntEquals (test, 0x56, response.source_addr);
	CuAssertIntEquals (test, 0x23, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_max_size_min_packets (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct device_manager_full_capabilities capabilities;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT)];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * (ARRAY_SIZE (tx_packet) - 1));
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MIN_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Update target device capabilities to reduce max packet size. */
	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;
	capabilities.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < request.payload_length; i++) {
		request.payload[i] = i;
	}

	cmd_interface_msg_set_message_payload_length (&request, request.payload_length);

	/* Construct the expected packets generated for the message. */
	memset (tx_packet, 0, sizeof (tx_packet));

	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = pkt_size - 3;
		header->source_addr = 0xBB;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->som = !i;
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
		header->msg_tag = 0;
		header->packet_seq = i % 4;

		memcpy (&tx_packet[i].data[7],
			&request.payload[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * i],
			MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT);

		tx_packet[i].data[pkt_size - 1] = checksum_crc8 (0xA2, tx_packet[i].data, pkt_size - 1);
		tx_packet[i].pkt_size = pkt_size;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x51;
		tx_packet[i].timeout_valid = false;
	}

	header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = last_pkt_size - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0;
	header->packet_seq = i % 4;

	memcpy (&tx_packet[i].data[7],
		&request.payload[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * i], remain);

	tx_packet[i].data[last_pkt_size - 1] = checksum_crc8 (0xA2, tx_packet[i].data,
		last_pkt_size - 1);
	tx_packet[i].pkt_size = last_pkt_size;
	tx_packet[i].state = CMD_VALID_PACKET;
	tx_packet[i].dest_addr = 0x51;
	tx_packet[i].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x11;
	rx_packet.data[9] = 0x12;
	rx_packet.data[10] = 0x13;
	rx_packet.data[11] = 0x14;
	rx_packet.data[12] = 0x15;
	rx_packet.data[13] = 0x16;
	rx_packet.data[14] = 0x17;
	rx_packet.data[15] = 0x18;
	rx_packet.data[16] = 0x19;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = 0;
	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (tx_packet[i])));
	}

	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
			sizeof (tx_packet[i])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_max_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet[MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE];
	uint8_t rx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	uint8_t rx_expected[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * (ARRAY_SIZE (rx_packet) - 1));
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Change EID and address settings for the devices. */
	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 0, 0x23, 0x45,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, 0x78, 0x56,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		0x78, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet, 0, sizeof (tx_packet));
	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0x8B;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x78;
	header->source_eid = 0x23;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xAC, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x56;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	for (i = 0; i < sizeof (rx_expected); i++) {
		rx_expected[i] = i;
	}

	memset (rx_packet, 0, sizeof (rx_packet));

	for (i = 0; i < ARRAY_SIZE (rx_packet) - 1; i++) {
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = pkt_size - 3;
		header->source_addr = 0xAD;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = 0x23;
		header->source_eid = 0x78;
		header->som = !i;
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = 0;
		header->packet_seq = i % 4;

		memcpy (&rx_packet[i].data[7],
			&rx_expected[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i],
			MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);

		rx_packet[i].data[pkt_size - 1] = checksum_crc8 (0x8A, rx_packet[i].data, pkt_size - 1);
		rx_packet[i].pkt_size = pkt_size;
		rx_packet[i].state = CMD_VALID_PACKET;
		rx_packet[i].dest_addr = 0x45;
		rx_packet[i].timeout_valid = false;
	}

	header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = last_pkt_size - 3;
	header->source_addr = 0xAD;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x23;
	header->source_eid = 0x78;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = i % 4;

	memcpy (&rx_packet[i].data[7],
		&rx_expected[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i], remain);

	rx_packet[i].data[last_pkt_size - 1] = checksum_crc8 (0x8A, rx_packet[i].data,
		last_pkt_size - 1);
	rx_packet[i].pkt_size = last_pkt_size;
	rx_packet[i].state = CMD_VALID_PACKET;
	rx_packet[i].dest_addr = 0x45;
	rx_packet[i].timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = rx_packet;
	context.packet_count = ARRAY_SIZE (rx_packet);
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, 0x78, response.source_eid);
	CuAssertIntEquals (test, 0x56, response.source_addr);
	CuAssertIntEquals (test, 0x23, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (rx_expected, response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_different_msg_tags (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[9][MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[9];
	struct cmd_packet rx_packet[9];
	uint8_t rx_message[9][10];
	struct mctp_interface_test_callback_context context[9];
	struct cmd_interface_msg request[9];
	struct cmd_interface_msg response[9];
	int status;
	size_t i;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	for (i = 0; i < ARRAY_SIZE (request); i++) {
		/* Build the request message to send. */
		status = msg_transport_create_empty_request (&mctp.test.base, tx_message[i],
			sizeof (tx_message[i]), MCTP_BASE_PROTOCOL_BMC_EID, &request[i]);
		CuAssertIntEquals (test, 0, status);

		request[i].payload[0] = 0x01 | (i << 4);
		request[i].payload[1] = 0x02 | (i << 4);
		request[i].payload[2] = 0x03 | (i << 4);
		request[i].payload[3] = 0x04 | (i << 4);
		request[i].payload[4] = 0x05 | (i << 4);
		request[i].payload[5] = 0x06 | (i << 4);
		cmd_interface_msg_set_message_payload_length (&request[i], 6);

		/* Construct the expected packet generated for the message. */
		memset (&tx_packet[i], 0, sizeof (tx_packet[i]));
		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

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
		header->msg_tag = i % 8;
		header->packet_seq = 0;

		memcpy (&tx_packet[i].data[7], request[i].payload, request[i].payload_length);

		tx_packet[i].data[13] = checksum_crc8 (0xA2, tx_packet[i].data, 13);
		tx_packet[i].pkt_size = 14;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x51;
		tx_packet[i].timeout_valid = false;

		/* Generate a response packet. */
		memset (&rx_packet[i], 0, sizeof (rx_packet[i]));
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = 15;
		header->source_addr = 0xA3;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->som = 1;
		header->eom = 1;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = i % 8;
		header->packet_seq = 0;

		rx_packet[i].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		rx_packet[i].data[8] = 0x09 | (i << 4);
		rx_packet[i].data[9] = 0x08 | (i << 4);
		rx_packet[i].data[10] = 0x07 | (i << 4);
		rx_packet[i].data[11] = 0x06 | (i << 4);
		rx_packet[i].data[12] = 0x05 | (i << 4);
		rx_packet[i].data[13] = 0x04 | (i << 4);
		rx_packet[i].data[14] = 0x03 | (i << 4);
		rx_packet[i].data[15] = 0x02 | (i << 4);
		rx_packet[i].data[16] = 0x01 | (i << 4);
		rx_packet[i].data[17] = checksum_crc8 (0xBA, rx_packet[i].data, 17);
		rx_packet[i].pkt_size = 18;
		rx_packet[i].dest_addr = 0x5D;
		rx_packet[i].timeout_valid = false;

		context[i].expected_status = 0;
		context[i].rsp_packet = &rx_packet[i];
		context[i].packet_count = 1;
		context[i].test = test;
		context[i].mctp = &mctp;

		status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (tx_packet[i])));
		status |= mock_expect_external_action (&mctp.channel.mock,
			mctp_interface_testing_process_packet_callback, &context[i]);

		CuAssertIntEquals (test, 0, status);

		/* Prepare a response structure. */
		status = msg_transport_create_empty_response (rx_message[i], sizeof (rx_message[i]),
			&response[i]);
		CuAssertIntEquals (test, 0, status);

		/* Send the request. */
		status = mctp.test.base.send_request_message (&mctp.test.base, &request[i], 100,
			&response[i]);
		CuAssertIntEquals (test, 0, status);

		CuAssertPtrEquals (test, rx_message[i], response[i].data);
		CuAssertIntEquals (test, sizeof (rx_message[i]), response[i].length);
		CuAssertPtrEquals (test, rx_message[i], response[i].payload);
		CuAssertIntEquals (test, sizeof (rx_message[i]), response[i].payload_length);
		CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response[i].source_eid);
		CuAssertIntEquals (test, 0x51, response[i].source_addr);
		CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response[i].target_eid);
		CuAssertIntEquals (test, false, response[i].is_encrypted);
		CuAssertIntEquals (test, false, response[i].crypto_timeout);
		CuAssertIntEquals (test, 0, response[i].channel_id);
		CuAssertIntEquals (test, sizeof (rx_message[i]), response[i].max_response);

		status = testing_validate_array (&rx_packet[i].data[7], response[i].data,
			response[i].length);
		CuAssertIntEquals (test, 0, status);
	}

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_same_buffer (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	size_t response_length = 10;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, tx_message, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, tx_message, request.payload);
	CuAssertIntEquals (test, response_length, request.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x51, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);
	CuAssertIntEquals (test, sizeof (tx_message), request.max_response);

	status = testing_validate_array (&rx_packet.data[7], request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_same_buffer_max_size (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE];
	struct cmd_packet rx_packet;
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	size_t response_length = 10;
	int status;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * (ARRAY_SIZE (tx_packet) - 1));
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Change EID and address settings for the devices. */
	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 0, 0x23, 0x45,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, 0x78, 0x56,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		0x78, &request);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < request.payload_length; i++) {
		request.payload[i] = i;
	}

	cmd_interface_msg_set_message_payload_length (&request, request.payload_length);

	/* Construct the expected packets generated for the message. */
	memset (tx_packet, 0, sizeof (tx_packet));

	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = pkt_size - 3;
		header->source_addr = 0x8B;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = 0x78;
		header->source_eid = 0x23;
		header->som = !i;
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
		header->msg_tag = 0;
		header->packet_seq = i % 4;

		memcpy (&tx_packet[i].data[7],
			&request.payload[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i],
			MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);

		tx_packet[i].data[pkt_size - 1] = checksum_crc8 (0xAC, tx_packet[i].data, pkt_size - 1);
		tx_packet[i].pkt_size = pkt_size;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x56;
		tx_packet[i].timeout_valid = false;
	}

	header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = last_pkt_size - 3;
	header->source_addr = 0x8B;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x78;
	header->source_eid = 0x23;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0;
	header->packet_seq = i % 4;

	memcpy (&tx_packet[i].data[7],
		&request.payload[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i], remain);

	tx_packet[i].data[last_pkt_size - 1] = checksum_crc8 (0xAC, tx_packet[i].data,
		last_pkt_size - 1);
	tx_packet[i].pkt_size = last_pkt_size;
	tx_packet[i].state = CMD_VALID_PACKET;
	tx_packet[i].dest_addr = 0x56;
	tx_packet[i].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xAD;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x23;
	header->source_eid = 0x78;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x11;
	rx_packet.data[9] = 0x12;
	rx_packet.data[10] = 0x13;
	rx_packet.data[11] = 0x14;
	rx_packet.data[12] = 0x15;
	rx_packet.data[13] = 0x16;
	rx_packet.data[14] = 0x17;
	rx_packet.data[15] = 0x18;
	rx_packet.data[16] = 0x19;
	rx_packet.data[17] = checksum_crc8 (0x8A, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x45;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = 0;
	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (tx_packet[i])));
	}

	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
			sizeof (tx_packet[i])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, tx_message, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, tx_message, request.payload);
	CuAssertIntEquals (test, response_length, request.payload_length);
	CuAssertIntEquals (test, 0x78, request.source_eid);
	CuAssertIntEquals (test, 0x56, request.source_addr);
	CuAssertIntEquals (test, 0x23, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);
	CuAssertIntEquals (test, sizeof (tx_message), request.max_response);

	status = testing_validate_array (&rx_packet.data[7], request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_same_buffer_max_size_min_packets (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct device_manager_full_capabilities capabilities;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT)];
	struct cmd_packet rx_packet;
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	size_t response_length = 10;
	int status;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * (ARRAY_SIZE (tx_packet) - 1));
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MIN_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Update target device capabilities to reduce max packet size. */
	device_manager_get_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	capabilities.request.max_packet_size = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;
	capabilities.request.max_message_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = device_manager_update_device_capabilities (&mctp.device_mgr, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < request.payload_length; i++) {
		request.payload[i] = i;
	}

	cmd_interface_msg_set_message_payload_length (&request, request.payload_length);

	/* Construct the expected packets generated for the message. */
	memset (tx_packet, 0, sizeof (tx_packet));

	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = pkt_size - 3;
		header->source_addr = 0xBB;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->som = !i;
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
		header->msg_tag = 0;
		header->packet_seq = i % 4;

		memcpy (&tx_packet[i].data[7],
			&request.payload[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * i],
			MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT);

		tx_packet[i].data[pkt_size - 1] = checksum_crc8 (0xA2, tx_packet[i].data, pkt_size - 1);
		tx_packet[i].pkt_size = pkt_size;
		tx_packet[i].state = CMD_VALID_PACKET;
		tx_packet[i].dest_addr = 0x51;
		tx_packet[i].timeout_valid = false;
	}

	header = (struct mctp_base_protocol_transport_header*) tx_packet[i].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = last_pkt_size - 3;
	header->source_addr = 0xBB;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0;
	header->packet_seq = i % 4;

	memcpy (&tx_packet[i].data[7],
		&request.payload[MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT * i], remain);

	tx_packet[i].data[last_pkt_size - 1] = checksum_crc8 (0xA2, tx_packet[i].data,
		last_pkt_size - 1);
	tx_packet[i].pkt_size = last_pkt_size;
	tx_packet[i].state = CMD_VALID_PACKET;
	tx_packet[i].dest_addr = 0x51;
	tx_packet[i].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x11;
	rx_packet.data[9] = 0x12;
	rx_packet.data[10] = 0x13;
	rx_packet.data[11] = 0x14;
	rx_packet.data[12] = 0x15;
	rx_packet.data[13] = 0x16;
	rx_packet.data[14] = 0x17;
	rx_packet.data[15] = 0x18;
	rx_packet.data[16] = 0x19;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = 0;
	for (i = 0; i < ARRAY_SIZE (tx_packet) - 1; i++) {
		status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
				sizeof (tx_packet[i])));
	}

	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i],
			sizeof (tx_packet[i])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, tx_message, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, tx_message, request.payload);
	CuAssertIntEquals (test, response_length, request.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, request.source_eid);
	CuAssertIntEquals (test, 0x51, request.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);
	CuAssertIntEquals (test, sizeof (tx_message), request.max_response);

	status = testing_validate_array (&rx_packet.data[7], request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_same_buffer_max_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet[MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE];
	uint8_t rx_expected[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	size_t response_length = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	int status;
	size_t remain = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY -
		(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * (ARRAY_SIZE (rx_packet) - 1));
	size_t i;
	size_t pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	size_t last_pkt_size = remain + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Change EID and address settings for the devices. */
	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 0, 0x23, 0x45,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, 0x78, 0x56,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		0x78, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet, 0, sizeof (tx_packet));
	header = (struct mctp_base_protocol_transport_header*) tx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0x8B;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x78;
	header->source_eid = 0x23;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xAC, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x56;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	for (i = 0; i < sizeof (rx_expected); i++) {
		rx_expected[i] = i;
	}

	memset (rx_packet, 0, sizeof (rx_packet));

	for (i = 0; i < ARRAY_SIZE (rx_packet) - 1; i++) {
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = pkt_size - 3;
		header->source_addr = 0xAD;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = 0x23;
		header->source_eid = 0x78;
		header->som = !i;
		header->eom = 0;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = 0;
		header->packet_seq = i % 4;

		memcpy (&rx_packet[i].data[7],
			&rx_expected[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i],
			MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);

		rx_packet[i].data[pkt_size - 1] = checksum_crc8 (0x8A, rx_packet[i].data, pkt_size - 1);
		rx_packet[i].pkt_size = pkt_size;
		rx_packet[i].state = CMD_VALID_PACKET;
		rx_packet[i].dest_addr = 0x45;
		rx_packet[i].timeout_valid = false;
	}

	header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = last_pkt_size - 3;
	header->source_addr = 0xAD;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x23;
	header->source_eid = 0x78;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = i % 4;

	memcpy (&rx_packet[i].data[7],
		&rx_expected[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT * i], remain);

	rx_packet[i].data[last_pkt_size - 1] = checksum_crc8 (0x8A, rx_packet[i].data,
		last_pkt_size - 1);
	rx_packet[i].pkt_size = last_pkt_size;
	rx_packet[i].state = CMD_VALID_PACKET;
	rx_packet[i].dest_addr = 0x45;
	rx_packet[i].timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = rx_packet;
	context.packet_count = ARRAY_SIZE (rx_packet);
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &request);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, tx_message, request.data);
	CuAssertIntEquals (test, response_length, request.length);
	CuAssertPtrEquals (test, tx_message, request.payload);
	CuAssertIntEquals (test, response_length, request.payload_length);
	CuAssertIntEquals (test, 0x78, request.source_eid);
	CuAssertIntEquals (test, 0x56, request.source_addr);
	CuAssertIntEquals (test, 0x23, request.target_eid);
	CuAssertIntEquals (test, false, request.is_encrypted);
	CuAssertIntEquals (test, false, request.crypto_timeout);
	CuAssertIntEquals (test, 0, request.channel_id);
	CuAssertIntEquals (test, sizeof (tx_message), request.max_response);

	status = testing_validate_array (rx_expected, request.data, request.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_drop_unexpected_response_msg_tags (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet[5];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	size_t i;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000400
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000300
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000200
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000100
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packets. */
	memset (&rx_packet, 0, sizeof (rx_packet));

	for (i = 0; i < ARRAY_SIZE (rx_packet); i++) {
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = 15;
		header->source_addr = 0xA3;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->som = 1;
		header->eom = 1;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = ARRAY_SIZE (rx_packet) - (i + 1);
		header->packet_seq = 0;

		rx_packet[i].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		rx_packet[i].data[8] = 0x01 | (i << 4);
		rx_packet[i].data[9] = 0x02 | (i << 4);
		rx_packet[i].data[10] = 0x03 | (i << 4);
		rx_packet[i].data[11] = 0x04 | (i << 4);
		rx_packet[i].data[12] = 0x05 | (i << 4);
		rx_packet[i].data[13] = 0x06 | (i << 4);
		rx_packet[i].data[14] = 0x07 | (i << 4);
		rx_packet[i].data[15] = 0x08 | (i << 4);
		rx_packet[i].data[16] = 0x09 | (i << 4);
		rx_packet[i].data[17] = checksum_crc8 (0xBA, rx_packet[i].data, 17);
		rx_packet[i].pkt_size = 18;
		rx_packet[i].dest_addr = 0x5D;
		rx_packet[i].timeout_valid = false;
	}

	context.expected_status = 0;
	context.rsp_packet = rx_packet;
	context.packet_count = ARRAY_SIZE (rx_packet);
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[4].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_drop_unexpected_response_source_eid (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet[5];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	size_t i;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510600
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510700
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510800
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510900
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packets. */
	memset (&rx_packet, 0, sizeof (rx_packet));

	for (i = 0; i < ARRAY_SIZE (rx_packet); i++) {
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = 15;
		header->source_addr = 0xA3;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID - (ARRAY_SIZE (rx_packet) - (i + 1));
		header->som = 1;
		header->eom = 1;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = 0;
		header->packet_seq = 0;

		rx_packet[i].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		rx_packet[i].data[8] = 0x01 | (i << 4);
		rx_packet[i].data[9] = 0x02 | (i << 4);
		rx_packet[i].data[10] = 0x03 | (i << 4);
		rx_packet[i].data[11] = 0x04 | (i << 4);
		rx_packet[i].data[12] = 0x05 | (i << 4);
		rx_packet[i].data[13] = 0x06 | (i << 4);
		rx_packet[i].data[14] = 0x07 | (i << 4);
		rx_packet[i].data[15] = 0x08 | (i << 4);
		rx_packet[i].data[16] = 0x09 | (i << 4);
		rx_packet[i].data[17] = checksum_crc8 (0xBA, rx_packet[i].data, 17);
		rx_packet[i].pkt_size = 18;
		rx_packet[i].dest_addr = 0x5D;
		rx_packet[i].timeout_valid = false;
	}

	context.expected_status = 0;
	context.rsp_packet = rx_packet;
	context.packet_count = ARRAY_SIZE (rx_packet);
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[4].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_receive_extra_response_message (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	struct cmd_message *tx;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_UNEXPECTED,
		.arg2 = 10
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	mctp_interface_set_channel_id (&mctp.test, 10);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 10, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait_receive_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait_receive_response_descriptor_not_null (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, 0, response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, 0, response.payload_length);
	CuAssertIntEquals (test, 0, response.source_eid);
	CuAssertIntEquals (test, 0, response.source_addr);
	CuAssertIntEquals (test, 0, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait_receive_response_drop_unexpected_response_msg_tags (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet[5];
	struct cmd_interface_msg request;
	struct cmd_message *tx;
	size_t i;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000400
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000300
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000200
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000100
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packets. */
	memset (&rx_packet, 0, sizeof (rx_packet));

	for (i = 0; i < ARRAY_SIZE (rx_packet); i++) {
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = 15;
		header->source_addr = 0xA3;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
		header->som = 1;
		header->eom = 1;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = ARRAY_SIZE (rx_packet) - (i + 1);
		header->packet_seq = 0;

		rx_packet[i].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		rx_packet[i].data[8] = 0x01 | (i << 4);
		rx_packet[i].data[9] = 0x02 | (i << 4);
		rx_packet[i].data[10] = 0x03 | (i << 4);
		rx_packet[i].data[11] = 0x04 | (i << 4);
		rx_packet[i].data[12] = 0x05 | (i << 4);
		rx_packet[i].data[13] = 0x06 | (i << 4);
		rx_packet[i].data[14] = 0x07 | (i << 4);
		rx_packet[i].data[15] = 0x08 | (i << 4);
		rx_packet[i].data[16] = 0x09 | (i << 4);
		rx_packet[i].data[17] = checksum_crc8 (0xBA, rx_packet[i].data, 17);
		rx_packet[i].pkt_size = 18;
		rx_packet[i].dest_addr = 0x5D;
		rx_packet[i].timeout_valid = false;
	}

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	/* Receive the response. */
	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[0], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[1], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[2], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[3], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[4], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait_receive_response_drop_unexpected_response_source_eid (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet[5];
	struct cmd_interface_msg request;
	struct cmd_message *tx;
	size_t i;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510607
	};
	struct debug_log_entry_info entry2 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510707
	};
	struct debug_log_entry_info entry3 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510807
	};
	struct debug_log_entry_info entry4 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_SOURCE,
		.arg2 = 0x0a510907
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	mctp_interface_set_channel_id (&mctp.test, 7);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packets. */
	memset (&rx_packet, 0, sizeof (rx_packet));

	for (i = 0; i < ARRAY_SIZE (rx_packet); i++) {
		header = (struct mctp_base_protocol_transport_header*) rx_packet[i].data;

		header->cmd_code = SMBUS_CMD_CODE_MCTP;
		header->byte_count = 15;
		header->source_addr = 0xA3;
		header->rsvd = 0;
		header->header_version = 1;
		header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
		header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID - (ARRAY_SIZE (rx_packet) - (i + 1));
		header->som = 1;
		header->eom = 1;
		header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
		header->msg_tag = 0;
		header->packet_seq = 0;

		rx_packet[i].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		rx_packet[i].data[8] = 0x01 | (i << 4);
		rx_packet[i].data[9] = 0x02 | (i << 4);
		rx_packet[i].data[10] = 0x03 | (i << 4);
		rx_packet[i].data[11] = 0x04 | (i << 4);
		rx_packet[i].data[12] = 0x05 | (i << 4);
		rx_packet[i].data[13] = 0x06 | (i << 4);
		rx_packet[i].data[14] = 0x07 | (i << 4);
		rx_packet[i].data[15] = 0x08 | (i << 4);
		rx_packet[i].data[16] = 0x09 | (i << 4);
		rx_packet[i].data[17] = checksum_crc8 (0xBA, rx_packet[i].data, 17);
		rx_packet[i].pkt_size = 18;
		rx_packet[i].dest_addr = 0x5D;
		rx_packet[i].timeout_valid = false;
	}

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	/* Receive the response. */
	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry2, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry2)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry3, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry3)));
	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry4, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry4)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[0], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[1], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[2], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[3], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet[4], &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait_then_another_request (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet[2];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x010005
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	mctp_interface_set_channel_id (&mctp.test, 5);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[0], 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x01;
	rx_packet[0].data[9] = 0x02;
	rx_packet[0].data[10] = 0x03;
	rx_packet[0].data[11] = 0x04;
	rx_packet[0].data[12] = 0x05;
	rx_packet[0].data[13] = 0x06;
	rx_packet[0].data[14] = 0x07;
	rx_packet[0].data[15] = 0x08;
	rx_packet[0].data[16] = 0x09;
	rx_packet[0].data[17] = checksum_crc8 (0xBA, rx_packet[0].data, 17);
	rx_packet[0].pkt_size = 18;
	rx_packet[0].dest_addr = 0x5D;
	rx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 1;
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[1], 0, sizeof (rx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 1;
	header->packet_seq = 0;

	rx_packet[1].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[1].data[8] = 0x11;
	rx_packet[1].data[9] = 0x12;
	rx_packet[1].data[10] = 0x13;
	rx_packet[1].data[11] = 0x14;
	rx_packet[1].data[12] = 0x15;
	rx_packet[1].data[13] = 0x16;
	rx_packet[1].data[14] = 0x17;
	rx_packet[1].data[15] = 0x18;
	rx_packet[1].data[16] = 0x19;
	rx_packet[1].data[17] = checksum_crc8 (0xBA, rx_packet[1].data, 17);
	rx_packet[1].pkt_size = 18;
	rx_packet[1].dest_addr = 0x5D;
	rx_packet[1].timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = rx_packet;
	context.packet_count = 2;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 5, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[1].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_no_response_wait_then_another_request_wrap_tag (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet[2];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
		.arg2 = 0x000700
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Adjust internal state to make the message tag need to wrap for the next message. */
	mctp.state.next_msg_tag = 7;

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 7;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[0], 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 7;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x01;
	rx_packet[0].data[9] = 0x02;
	rx_packet[0].data[10] = 0x03;
	rx_packet[0].data[11] = 0x04;
	rx_packet[0].data[12] = 0x05;
	rx_packet[0].data[13] = 0x06;
	rx_packet[0].data[14] = 0x07;
	rx_packet[0].data[15] = 0x08;
	rx_packet[0].data[16] = 0x09;
	rx_packet[0].data[17] = checksum_crc8 (0xBA, rx_packet[0].data, 17);
	rx_packet[0].pkt_size = 18;
	rx_packet[0].dest_addr = 0x5D;
	rx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 0, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_NO_WAIT_RESPONSE, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[1], 0, sizeof (rx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet[1].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[1].data[8] = 0x11;
	rx_packet[1].data[9] = 0x12;
	rx_packet[1].data[10] = 0x13;
	rx_packet[1].data[11] = 0x14;
	rx_packet[1].data[12] = 0x15;
	rx_packet[1].data[13] = 0x16;
	rx_packet[1].data[14] = 0x17;
	rx_packet[1].data[15] = 0x18;
	rx_packet[1].data[16] = 0x19;
	rx_packet[1].data[17] = checksum_crc8 (0xBA, rx_packet[1].data, 17);
	rx_packet[1].pkt_size = 18;
	rx_packet[1].dest_addr = 0x5D;
	rx_packet[1].timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = rx_packet;
	context.packet_count = 2;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[1].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init_static (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp.test.base.send_request_message (NULL, &request, 100, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = mctp.test.base.send_request_message (&mctp.test.base, NULL, 100, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_payload_too_large (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload_length++;	// Force a bad length value.

	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_REQUEST_TOO_LARGE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_unknown_destination_device (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		0x33, &request);
	CuAssertIntEquals (test, 0, status);

	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_buffer_too_small (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	/* Force the buffer to be too small. */
	request.max_response = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1;

	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_buffer_too_small_then_good_message (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* First trigger an error with a bad buffer length. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.max_response = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1;

	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);

	/* Then build a good request to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_channel_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	uint8_t rx_message[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init_dependencies (test, &mctp);

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, CMD_CHANNEL_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_channel_send_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	uint8_t rx_message[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_channel_send_fail_then_good_message (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Send a request where the transmission fails. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	/* Send another message that gets transmitted correctly. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 1;	/* The message tag is incremented after the failure. */
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 1;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_channel_send_fail_then_good_message_wrap_tag (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Adjust internal state to make the message tag need to wrap on failure. */
	mctp.state.next_msg_tag = 7;

	/* Send a request where the transmission fails. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 7;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	/* Send another message that gets transmitted correctly. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 0;	/* The message tag is incremented after the failure. */
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_channel_send_fail_receive_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	struct cmd_message *tx;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_INFO,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_DROPPED,
		.arg1 = MCTP_LOGGING_RSP_DROPPED_UNEXPECTED,
		.arg2 = 0
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	/* Response data is dropped. */
	status = mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_process_packet (&mctp.test, &rx_packet, &tx);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, NULL, tx);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_timeout (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	uint8_t rx_message[10];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_TIMEOUT,
		.arg1 = 0x0a00,
		.arg2 = 10
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 10, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_REQUEST_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_timeout_then_good_message (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_TIMEOUT,
		.arg1 = 0x0a00,
		.arg2 = 15
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Send a request that doesn't receive a response. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 15, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_REQUEST_TIMEOUT, status);

	/* Send another message that gets transmitted correctly. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 1;	/* The message tag is incremented after the failure. */
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 1;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_timeout_then_good_message_wrap_tag (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;
	struct debug_log_entry_info entry1 = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_MCTP,
		.msg_index = MCTP_LOGGING_RSP_TIMEOUT,
		.arg1 = 0x0a07,
		.arg2 = 10
	};

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Adjust internal state to make the message tag need to wrap on failure. */
	mctp.state.next_msg_tag = 7;

	/* Send a request that doesn't receive a response. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 7;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	status |= mock_expect (&mctp.log.mock, mctp.log.base.create_entry, &mctp.log, 0,
		MOCK_ARG_PTR_CONTAINS_TMP ((uint8_t*) &entry1, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry1)));

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 10, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_REQUEST_TIMEOUT, status);

	/* Send another message that gets transmitted correctly. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 0;	/* The message tag is incremented after the failure. */
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_too_large (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet.data[7], request.payload, request.payload_length);

	tx_packet.data[13] = checksum_crc8 (0xA2, tx_packet.data, 13);
	tx_packet.pkt_size = 14;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x51;
	tx_packet.timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure with insufficient buffer space. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message) - 1, &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_RESPONSE_TOO_LARGE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_too_large_then_good_message (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet[2];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context[2];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Send a request that has insufficient buffer space for the response. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 0;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[0], 0, sizeof (rx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x01;
	rx_packet[0].data[9] = 0x02;
	rx_packet[0].data[10] = 0x03;
	rx_packet[0].data[11] = 0x04;
	rx_packet[0].data[12] = 0x05;
	rx_packet[0].data[13] = 0x06;
	rx_packet[0].data[14] = 0x07;
	rx_packet[0].data[15] = 0x08;
	rx_packet[0].data[16] = 0x09;
	rx_packet[0].data[17] = checksum_crc8 (0xBA, rx_packet[0].data, 17);
	rx_packet[0].pkt_size = 18;
	rx_packet[0].dest_addr = 0x5D;
	rx_packet[0].timeout_valid = false;

	context[0].expected_status = 0;
	context[0].rsp_packet = &rx_packet[0];
	context[0].packet_count = 1;
	context[0].test = test;
	context[0].mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context[0]);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure with insufficient buffer space. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message) - 1, &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_RESPONSE_TOO_LARGE, status);

	/* Send another message that gets transmitted correctly. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 1;	/* The message tag is incremented after the failure. */
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[1], 0, sizeof (rx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 1;
	header->packet_seq = 0;

	rx_packet[1].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[1].data[8] = 0x11;
	rx_packet[1].data[9] = 0x12;
	rx_packet[1].data[10] = 0x13;
	rx_packet[1].data[11] = 0x14;
	rx_packet[1].data[12] = 0x15;
	rx_packet[1].data[13] = 0x16;
	rx_packet[1].data[14] = 0x17;
	rx_packet[1].data[15] = 0x18;
	rx_packet[1].data[16] = 0x19;
	rx_packet[1].data[17] = checksum_crc8 (0xBA, rx_packet[1].data, 17);
	rx_packet[1].pkt_size = 18;
	rx_packet[1].dest_addr = 0x5D;
	rx_packet[1].timeout_valid = false;

	context[1].expected_status = 0;
	context[1].rsp_packet = &rx_packet[1];
	context[1].packet_count = 1;
	context[1].test = test;
	context[1].mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context[1]);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[1].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_request_message_response_too_large_then_good_message_wrap_tag (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet[2];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context[2];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Adjust internal state to make the message tag need to wrap on failure. */
	mctp.state.next_msg_tag = 7;

	/* Send a request that has insufficient buffer space for the response. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0xab;
	request.payload[2] = 0xcd;
	request.payload[3] = 0xef;
	request.payload[4] = 0x11;
	request.payload[5] = 0x22;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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
	header->msg_tag = 7;
	header->packet_seq = 0;

	memcpy (&tx_packet[0].data[7], request.payload, request.payload_length);

	tx_packet[0].data[13] = checksum_crc8 (0xA2, tx_packet[0].data, 13);
	tx_packet[0].pkt_size = 14;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[0], 0, sizeof (rx_packet[0]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 7;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[0].data[8] = 0x01;
	rx_packet[0].data[9] = 0x02;
	rx_packet[0].data[10] = 0x03;
	rx_packet[0].data[11] = 0x04;
	rx_packet[0].data[12] = 0x05;
	rx_packet[0].data[13] = 0x06;
	rx_packet[0].data[14] = 0x07;
	rx_packet[0].data[15] = 0x08;
	rx_packet[0].data[16] = 0x09;
	rx_packet[0].data[17] = checksum_crc8 (0xBA, rx_packet[0].data, 17);
	rx_packet[0].pkt_size = 18;
	rx_packet[0].dest_addr = 0x5D;
	rx_packet[0].timeout_valid = false;

	context[0].expected_status = 0;
	context[0].rsp_packet = &rx_packet[0];
	context[0].packet_count = 1;
	context[0].test = test;
	context[0].mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context[0]);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure with insufficient buffer space. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message) - 1, &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, MSG_TRANSPORT_RESPONSE_TOO_LARGE, status);

	/* Send another message that gets transmitted correctly. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 0;	/* The message tag is incremented after the failure. */
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[1], 0, sizeof (rx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx_packet[1].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[1].data[8] = 0x11;
	rx_packet[1].data[9] = 0x12;
	rx_packet[1].data[10] = 0x13;
	rx_packet[1].data[11] = 0x14;
	rx_packet[1].data[12] = 0x15;
	rx_packet[1].data[13] = 0x16;
	rx_packet[1].data[14] = 0x17;
	rx_packet[1].data[15] = 0x18;
	rx_packet[1].data[16] = 0x19;
	rx_packet[1].data[17] = checksum_crc8 (0xBA, rx_packet[1].data, 17);
	rx_packet[1].pkt_size = 18;
	rx_packet[1].dest_addr = 0x5D;
	rx_packet[1].timeout_valid = false;

	context[1].expected_status = 0;
	context[1].rsp_packet = &rx_packet[1];
	context[1].packet_count = 1;
	context[1].test = test;
	context[1].mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context[1]);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[1].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[3] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

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


	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_process_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_packet rx_packet;
	struct cmd_packet tx_packet;
	uint8_t data[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg response;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) tx_packet.data;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Change the MCTP bridge EID. */
	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 1, 0x78, 0x56,
		DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	data[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	data[1] = 0x80;
	data[2] = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;

	memset (&tx_packet, 0, sizeof (tx_packet));
	memset (&response, 0, sizeof (response));

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

	memcpy (&tx_packet.data[7], data, 3);

	tx_packet.data[10] = checksum_crc8 (0xAC, tx_packet.data, 10);
	tx_packet.pkt_size = 11;
	tx_packet.state = CMD_VALID_PACKET;
	tx_packet.dest_addr = 0x56;
	tx_packet.timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	memset (&rx_packet, 0, sizeof (rx_packet));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 9;
	header->source_addr = 0xAD;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = 0x78;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rx_packet.data[8] = 0x00;
	rx_packet.data[9] = 0x0D;
	rx_packet.data[10] = 0x00;
	rx_packet.data[11] = checksum_crc8 (0xBA, rx_packet.data, 11);
	rx_packet.pkt_size = 12;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = true;
	platform_init_timeout (10, &rx_packet.pkt_timeout);

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (data, sizeof (data), &response);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, data, response.data);
	CuAssertIntEquals (test, 4, response.length);
	CuAssertPtrEquals (test, data, response.payload);
	CuAssertIntEquals (test, 4, response.payload_length);
	CuAssertIntEquals (test, 0x78, response.source_eid);
	CuAssertIntEquals (test, 0x56, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (data), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_followed_by_another_rq (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet;
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context;
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	tx_message[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	tx_message[1] = 0x80;
	tx_message[2] = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;

	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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

	memcpy (&tx_packet[0].data[7], tx_message, 3);

	tx_packet[0].data[10] = checksum_crc8 (0xA2, tx_packet[0].data, 10);
	tx_packet[0].pkt_size = 11;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 1;
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet, 0, sizeof (rx_packet));
	header = (struct mctp_base_protocol_transport_header*) rx_packet.data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 1;
	header->packet_seq = 0;

	rx_packet.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet.data[8] = 0x01;
	rx_packet.data[9] = 0x02;
	rx_packet.data[10] = 0x03;
	rx_packet.data[11] = 0x04;
	rx_packet.data[12] = 0x05;
	rx_packet.data[13] = 0x06;
	rx_packet.data[14] = 0x07;
	rx_packet.data[15] = 0x08;
	rx_packet.data[16] = 0x09;
	rx_packet.data[17] = checksum_crc8 (0xBA, rx_packet.data, 17);
	rx_packet.pkt_size = 18;
	rx_packet.dest_addr = 0x5D;
	rx_packet.timeout_valid = false;

	context.expected_status = 0;
	context.rsp_packet = &rx_packet;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet.data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_followed_discovery_notify_rsp_then_another_rq (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_base_protocol_transport_header *header;
	uint8_t tx_message[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct cmd_packet rx_packet[2];
	uint8_t rx_message[10];
	struct mctp_interface_test_callback_context context[2];
	struct cmd_interface_msg request;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	tx_message[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	tx_message[1] = 0x80;
	tx_message[2] = MCTP_CONTROL_PROTOCOL_DISCOVERY_NOTIFY;

	memset (&tx_packet[0], 0, sizeof (tx_packet[0]));

	header = (struct mctp_base_protocol_transport_header*) tx_packet[0].data;

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

	memcpy (&tx_packet[0].data[7], tx_message, 3);

	tx_packet[0].data[10] = checksum_crc8 (0xA2, tx_packet[0].data, 10);
	tx_packet[0].pkt_size = 11;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x51;
	tx_packet[0].timeout_valid = false;

	memset (&rx_packet, 0, sizeof (rx_packet));

	header = (struct mctp_base_protocol_transport_header*) rx_packet[0].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 9;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x00;
	header->packet_seq = 0;

	rx_packet[0].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	rx_packet[0].data[8] = 0x00;
	rx_packet[0].data[9] = 0x0D;
	rx_packet[0].data[10] = 0x00;
	rx_packet[0].data[11] = checksum_crc8 (0xBA, rx_packet[0].data, 11);
	rx_packet[0].pkt_size = 12;
	rx_packet[0].dest_addr = 0x5D;
	rx_packet[0].timeout_valid = true;
	platform_init_timeout (10, &rx_packet[0].pkt_timeout);

	context[0].expected_status = 0;
	context[0].rsp_packet = &rx_packet[0];
	context[0].packet_count = 1;
	context[0].test = test;
	context[0].mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (tx_packet[0])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context[0]);

	CuAssertIntEquals (test, 0, status);

	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, 4, response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, 4, response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[0].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	/* Build the request message to send. */
	status = msg_transport_create_empty_request (&mctp.test.base, tx_message, sizeof (tx_message),
		MCTP_BASE_PROTOCOL_BMC_EID, &request);
	CuAssertIntEquals (test, 0, status);

	request.payload[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	request.payload[1] = 0x12;
	request.payload[2] = 0x34;
	request.payload[3] = 0x56;
	request.payload[4] = 0x78;
	request.payload[5] = 0x90;
	cmd_interface_msg_set_message_payload_length (&request, 6);

	/* Construct the expected packet generated for the message. */
	memset (&tx_packet[1], 0, sizeof (tx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

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
	header->msg_tag = 1;
	header->packet_seq = 0;

	memcpy (&tx_packet[1].data[7], request.payload, request.payload_length);

	tx_packet[1].data[13] = checksum_crc8 (0xA2, tx_packet[1].data, 13);
	tx_packet[1].pkt_size = 14;
	tx_packet[1].state = CMD_VALID_PACKET;
	tx_packet[1].dest_addr = 0x51;
	tx_packet[1].timeout_valid = false;

	/* Generate a response packet. */
	memset (&rx_packet[1], 0, sizeof (rx_packet[1]));
	header = (struct mctp_base_protocol_transport_header*) rx_packet[1].data;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 15;
	header->source_addr = 0xA3;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 1;
	header->packet_seq = 0;

	rx_packet[1].data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	rx_packet[1].data[8] = 0x11;
	rx_packet[1].data[9] = 0x12;
	rx_packet[1].data[10] = 0x13;
	rx_packet[1].data[11] = 0x14;
	rx_packet[1].data[12] = 0x15;
	rx_packet[1].data[13] = 0x16;
	rx_packet[1].data[14] = 0x17;
	rx_packet[1].data[15] = 0x18;
	rx_packet[1].data[16] = 0x19;
	rx_packet[1].data[17] = checksum_crc8 (0xBA, rx_packet[1].data, 17);
	rx_packet[1].pkt_size = 18;
	rx_packet[1].dest_addr = 0x5D;
	rx_packet[1].timeout_valid = false;

	context[1].expected_status = 0;
	context[1].rsp_packet = &rx_packet[1];
	context[1].packet_count = 1;
	context[1].test = test;
	context[1].mctp = &mctp;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (tx_packet[1])));
	status |= mock_expect_external_action (&mctp.channel.mock,
		mctp_interface_testing_process_packet_callback, &context[1]);

	CuAssertIntEquals (test, 0, status);

	/* Prepare a response structure. */
	status = msg_transport_create_empty_response (rx_message, sizeof (rx_message), &response);
	CuAssertIntEquals (test, 0, status);

	/* Send the request. */
	status = mctp.test.base.send_request_message (&mctp.test.base, &request, 100, &response);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrEquals (test, rx_message, response.data);
	CuAssertIntEquals (test, sizeof (rx_message), response.length);
	CuAssertPtrEquals (test, rx_message, response.payload);
	CuAssertIntEquals (test, sizeof (rx_message), response.payload_length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BMC_EID, response.source_eid);
	CuAssertIntEquals (test, 0x51, response.source_addr);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, response.target_eid);
	CuAssertIntEquals (test, false, response.is_encrypted);
	CuAssertIntEquals (test, false, response.crypto_timeout);
	CuAssertIntEquals (test, 0, response.channel_id);
	CuAssertIntEquals (test, sizeof (rx_message), response.max_response);

	status = testing_validate_array (&rx_packet[1].data[7], response.data, response.length);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_static_init (CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	uint8_t buf[3] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

	mctp_interface_testing_init_static (test, &mctp);

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


	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	status = mctp_interface_send_discovery_notify (NULL, 100, &response);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 100, NULL);
	CuAssertIntEquals (test, MSG_TRANSPORT_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_no_mctp_bridge (CuTest *test)
{
	struct mctp_interface_testing mctp;
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);

	/* Re-initialize the device manager to remove the MCTP bridge. */
	device_manager_release (&mctp.device_mgr);

	status = device_manager_init (&mctp.device_mgr, 1, 0, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 1000, 1000, 0, 0, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_not_attestable_device_entry (&mctp.device_mgr, 0,
		MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID, 0x5D, DEVICE_MANAGER_NOT_PCD_COMPONENT);
	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 0, NULL);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_send_discovery_notify_cmd_channel_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[3] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_send_discovery_notify (&mctp.test, 0, NULL);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	mctp_interface_testing_release (test, &mctp);
}

/* Tests for the deprecated API.  These will get deleted when the API is removed. */
static void mctp_interface_test_issue_request_no_wait (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[6] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 0);
	CuAssertIntEquals (test, 0, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[6] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
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

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet2, sizeof (tx_packet2)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55, 0x0F, buf,
		sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_multiple_packets_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t payload[300] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct mctp_base_protocol_transport_header *header;
	int status;
	int i;

	TEST_START;

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
	tx_packet[0].data[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] = checksum_crc8 (0xAA,
		tx_packet[0].data, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);
	tx_packet[0].pkt_size = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN;
	tx_packet[0].state = CMD_VALID_PACKET;
	tx_packet[0].dest_addr = 0x55;
	tx_packet[0].timeout_valid = false;

	header = (struct mctp_base_protocol_transport_header*) tx_packet[1].data;

	i = (sizeof (payload) - MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT) +
		MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[0],
			sizeof (struct cmd_packet)));
	status |= mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[1],
			sizeof (struct cmd_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, payload, sizeof (payload), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_maximum_packet_length_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_maximum_num_packets_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (
		MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT)];
	struct mctp_base_protocol_transport_header *header;
	size_t i_packet;
	size_t num_packets = sizeof (tx_packet) / sizeof (tx_packet[0]);
	uint8_t packet_seq = 0;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	for (i_packet = 0; i_packet < num_packets; ++i_packet) {
		status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
			MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet[i_packet],
				sizeof (tx_packet[i_packet])));
	}

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_limited_packet_length_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t payload[300] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct mctp_base_protocol_transport_header *header;
	struct device_manager_full_capabilities remote;
	int status;
	int i;

	TEST_START;

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

	i = (sizeof (payload) - (200 - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD)) +
		MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

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

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, payload, sizeof (payload), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_limited_message_length_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t payload[300] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet[2];
	struct mctp_base_protocol_transport_header *header;
	struct device_manager_full_capabilities remote;
	int status;
	int i;

	TEST_START;

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

	i = (sizeof (payload) - MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT) +
		MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

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

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, payload, sizeof (payload), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_control_packet_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[6] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_end_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, &msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6], 6, msg_buf,
		sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_same_pointer_no_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, msg_buf, 6, msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_before_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, msg_buf, 6, &msg_buf[2], sizeof (msg_buf) - 2, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_within_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, &msg_buf[2], 6, msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_buffers_overlapping_after_no_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel, 0,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, &msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN - 6], 6, msg_buf,
		sizeof (msg_buf) - 2, 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, status);

	mctp_interface_testing_release (test, &mctp);
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

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&response, sizeof (response), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_then_process_response_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, CMD_HANDLER_NO_MEMORY, MOCK_ARG_VALIDATOR_DEEP_COPY (
			cmd_interface_mock_validate_request, &response,	sizeof (response),
			cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = CMD_HANDLER_NO_MEMORY;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_FAIL_RESPONSE, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0);

	mctp_interface_testing_release (test, &mctp);
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

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, CMD_HANDLER_ERROR_MESSAGE,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request,	cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_ERROR_RESPONSE, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_mctp_control_then_process_packet_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_response,
		&mctp.cmd_mctp, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_mctp_control_then_process_packet_response_fail (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_response,
		&mctp.cmd_mctp, CMD_HANDLER_NO_MEMORY,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = CMD_HANDLER_NO_MEMORY;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_FAIL_RESPONSE, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_spdm_then_process_packet_response (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
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
	response.payload = &data[1];
	response.payload_length = sizeof (data) - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_spdm.mock, mctp.cmd_spdm.base.process_response, &mctp.cmd_spdm,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request,	cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_spdm_then_process_packet_response_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
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
	response.payload = &data[1];
	response.payload_length = sizeof (data) - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init (test, &mctp);

	status = mock_expect (&mctp.cmd_spdm.mock, mctp.cmd_spdm.base.process_response, &mctp.cmd_spdm,
		CMD_HANDLER_SPDM_NO_MEMORY, MOCK_ARG_VALIDATOR_DEEP_COPY (
			cmd_interface_mock_validate_request, &response,	sizeof (response),
			cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = CMD_HANDLER_SPDM_NO_MEMORY;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_FAIL_RESPONSE, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_static_init_then_process_packet_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init_static (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_cerberus.mock, mctp.cmd_cerberus.base.process_response,
		&mctp.cmd_cerberus, 0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request,
			&response, sizeof (response), cmd_interface_mock_save_request,
			cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_static_init_mctp_control_then_process_packet_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	response.payload = data;
	response.payload_length = sizeof (data);
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init_static (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_mctp.mock, mctp.cmd_mctp.base.process_response,
		&mctp.cmd_mctp, 0,
		MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request, cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_static_init_spdm_then_process_packet_response (
	CuTest *test)
{
	struct mctp_interface_testing mctp = {
		.test = mctp_interface_static_init (&mctp.state, &mctp.cmd_cerberus.base,
			&mctp.cmd_mctp.base, &mctp.cmd_spdm.base, &mctp.device_mgr, &mctp.channel.base)
	};
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
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
	response.payload = &data[1];
	response.payload_length = sizeof (data) - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init_static (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.cmd_spdm.mock, mctp.cmd_spdm.base.process_response, &mctp.cmd_spdm,
		0, MOCK_ARG_VALIDATOR_DEEP_COPY (cmd_interface_mock_validate_request, &response,
			sizeof (response), cmd_interface_mock_save_request,	cmd_interface_mock_free_request));
	CuAssertIntEquals (test, 0, status);

	context.expected_status = 0;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context, 0,
		MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_null (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mctp_interface_issue_request (NULL, &mctp.channel.base, 0x77, 0xFF, buf, sizeof (buf),
		msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.test, NULL, 0x77, 0xFF, buf, sizeof (buf), msg_buf,
		sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x77, 0xFF, NULL,
		sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x77, 0xFF, buf, 0,
		msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x77, 0xFF, buf,
		sizeof (buf), NULL, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_output_buf_too_small (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[248] = {0};
	uint8_t msg_buf[255] = {0};
	int status;

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_request_payload_too_large (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY + 1] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	int status;

	TEST_START;

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x77, 0xFF, buf,
		sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TOO_LARGE, status);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_cmd_channel_fail (CuTest *test)
{
	struct mctp_interface_testing mctp;
	uint8_t buf[6] = {0};
	uint8_t msg_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN] = {0};
	struct cmd_packet tx_packet;
	struct mctp_base_protocol_transport_header *header;
	int status;

	TEST_START;

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	status = mock_expect (&mctp.channel.mock, mctp.channel.base.send_packet, &mctp.channel,
		CMD_CHANNEL_TX_FAILED,
		MOCK_ARG_VALIDATOR (cmd_channel_mock_validate_packet, &tx_packet, sizeof (tx_packet)));

	CuAssertIntEquals (test, 0, status);

	status = mctp_interface_issue_request (&mctp.test, &mctp.channel.base, 0x55,
		MCTP_BASE_PROTOCOL_BMC_EID, buf, sizeof (buf), msg_buf, sizeof (msg_buf), 1);
	CuAssertIntEquals (test, CMD_CHANNEL_TX_FAILED, status);

	mctp_interface_testing_release (test, &mctp);
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

	TEST_START;

	memset (&rx, 0, sizeof (rx));
	memset (&response, 0, sizeof (response));

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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	context.expected_status = MCTP_BASE_PROTOCOL_UNEXPECTED_PKT;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_request_then_process_packet_response_with_unexpected_msg_tag (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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

	mctp_interface_testing_init (test, &mctp);
	debug_log = NULL;

	context.expected_status = MCTP_BASE_PROTOCOL_UNEXPECTED_PKT;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, 0);

	mctp_interface_testing_release (test, &mctp);
}

static void mctp_interface_test_issue_spdm_request_then_process_packet_response_spdm_unsupported (
	CuTest *test)
{
	struct mctp_interface_testing mctp;
	struct mctp_interface_test_callback_context context;
	struct cmd_packet rx;
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) rx.data;
	uint8_t data[10];
	struct cmd_interface_msg response;
	int status;

	TEST_START;

	memset (&rx, 0, sizeof (rx));
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
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0;
	header->packet_seq = 0;

	rx.data[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
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
	response.payload = &data[1];
	response.payload_length = sizeof (data) - 1;
	response.source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	response.source_addr = 0x55;
	response.target_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	response.is_encrypted = false;
	response.crypto_timeout = false;
	response.channel_id = 0;
	response.max_response = 0;

	mctp_interface_testing_init_dependencies (test, &mctp);
	debug_log = NULL;

	status = mctp_interface_init (&mctp.test, &mctp.state, &mctp.cmd_cerberus.base,
		&mctp.cmd_mctp.base, NULL, &mctp.device_mgr, &mctp.channel.base);
	CuAssertIntEquals (test, 0, status);

	context.expected_status = MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION;
	context.rsp_packet = &rx;
	context.packet_count = 1;
	context.test = test;
	context.mctp = &mctp;

	mctp_interface_testing_generate_and_issue_request (test, &mctp, &context,
		MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, 0);

	mctp_interface_testing_release (test, &mctp);
}
#endif


TEST_SUITE_START (mctp_interface);

TEST (mctp_interface_test_init);
TEST (mctp_interface_test_init_spdm_not_supported);
TEST (mctp_interface_test_init_no_cmd_channel);
TEST (mctp_interface_test_init_null);
TEST (mctp_interface_test_static_init);
TEST (mctp_interface_test_static_init_spdm_not_supported);
TEST (mctp_interface_test_static_init_no_cmd_channel);
TEST (mctp_interface_test_static_init_null);
TEST (mctp_interface_test_release_null);
TEST (mctp_interface_test_set_channel_id);
TEST (mctp_interface_test_set_channel_id_null);
TEST (mctp_interface_test_process_packet_no_response);
TEST (mctp_interface_test_process_packet_no_response_non_zero_message_tag);
TEST (mctp_interface_test_process_packet_no_response_cmd_set_1);
TEST (mctp_interface_test_process_packet_one_packet_request);
TEST (mctp_interface_test_process_packet_one_packet_response);
TEST (mctp_interface_test_process_packet_one_packet_response_non_zero_message_tag);
TEST (mctp_interface_test_process_packet_two_packet_response);
TEST (mctp_interface_test_process_packet_channel_id_reset_next_som);
TEST (mctp_interface_test_process_packet_normal_timeout);
TEST (mctp_interface_test_process_packet_crypto_timeout);
TEST (mctp_interface_test_process_packet_no_eom);
TEST (mctp_interface_test_process_packet_max_message);
TEST (mctp_interface_test_process_packet_max_response);
TEST (mctp_interface_test_process_packet_max_response_min_packets);
TEST (mctp_interface_test_process_packet_reset_message_processing);
TEST (mctp_interface_test_process_packet_response_length_limited);
TEST (mctp_interface_test_process_packet_two_packet_response_length_limited);
TEST (mctp_interface_test_process_packet_mctp_control_request);
TEST (mctp_interface_test_process_packet_spdm_request);
TEST (mctp_interface_test_process_packet_static_init);
TEST (mctp_interface_test_process_packet_static_init_mctp_control_request);
TEST (mctp_interface_test_process_packet_static_init_spdm_request);
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
TEST (mctp_interface_test_process_packet_unsupported_type);
TEST (mctp_interface_test_process_packet_cmd_interface_fail);
TEST (mctp_interface_test_process_packet_cmd_interface_fail_cmd_set_1);
TEST (mctp_interface_test_process_packet_mctp_control_request_fail);
TEST (mctp_interface_test_process_packet_response_too_large);
TEST (mctp_interface_test_process_packet_response_too_large_length_limited);
TEST (mctp_interface_test_process_packet_error_message_fail);
TEST (mctp_interface_test_process_packet_error_too_large);
TEST (mctp_interface_test_process_packet_drop_unexpected_response_message);
TEST (mctp_interface_test_reset_message_processing_null);
#ifdef CMD_ENABLE_ISSUE_REQUEST
TEST (mctp_interface_test_get_max_message_overhead);
TEST (mctp_interface_test_get_max_message_overhead_unknown_device);
TEST (mctp_interface_test_get_max_message_overhead_static_init);
TEST (mctp_interface_test_get_max_message_overhead_null);
TEST (mctp_interface_test_get_max_message_payload_length);
TEST (mctp_interface_test_get_max_message_payload_length_unknown_device);
TEST (mctp_interface_test_get_max_message_payload_length_static_init);
TEST (mctp_interface_test_get_max_message_payload_length_null);
TEST (mctp_interface_test_get_max_encapsulated_message_length);
TEST (mctp_interface_test_get_max_encapsulated_message_length_unknown_device);
TEST (mctp_interface_test_get_max_encapsulated_message_length_static_init);
TEST (mctp_interface_test_get_max_encapsulated_message_length_null);
TEST (mctp_interface_test_send_request_message);
TEST (mctp_interface_test_send_request_message_max_size);
TEST (mctp_interface_test_send_request_message_max_size_min_packets);
TEST (mctp_interface_test_send_request_message_max_response);
TEST (mctp_interface_test_send_request_message_different_msg_tags);
TEST (mctp_interface_test_send_request_message_response_same_buffer);
TEST (mctp_interface_test_send_request_message_response_same_buffer_max_size);
TEST (mctp_interface_test_send_request_message_response_same_buffer_max_size_min_packets);
TEST (mctp_interface_test_send_request_message_response_same_buffer_max_response);
TEST (mctp_interface_test_send_request_message_drop_unexpected_response_msg_tags);
TEST (mctp_interface_test_send_request_message_drop_unexpected_response_source_eid);
TEST (mctp_interface_test_send_request_message_receive_extra_response_message);
TEST (mctp_interface_test_send_request_message_no_response_wait);
TEST (mctp_interface_test_send_request_message_no_response_wait_receive_response);
TEST (mctp_interface_test_send_request_message_no_response_wait_receive_response_descriptor_not_null);
TEST (mctp_interface_test_send_request_message_no_response_wait_receive_response_drop_unexpected_response_msg_tags);
TEST (mctp_interface_test_send_request_message_no_response_wait_receive_response_drop_unexpected_response_source_eid);
TEST (mctp_interface_test_send_request_message_no_response_wait_then_another_request);
TEST (mctp_interface_test_send_request_message_no_response_wait_then_another_request_wrap_tag);
TEST (mctp_interface_test_send_request_message_static_init);
TEST (mctp_interface_test_send_request_message_null);
TEST (mctp_interface_test_send_request_message_payload_too_large);
TEST (mctp_interface_test_send_request_message_unknown_destination_device);
TEST (mctp_interface_test_send_request_message_buffer_too_small);
TEST (mctp_interface_test_send_request_message_buffer_too_small_then_good_message);
TEST (mctp_interface_test_send_request_message_channel_null);
TEST (mctp_interface_test_send_request_message_channel_send_fail);
TEST (mctp_interface_test_send_request_message_channel_send_fail_then_good_message);
TEST (mctp_interface_test_send_request_message_channel_send_fail_then_good_message_wrap_tag);
TEST (mctp_interface_test_send_request_message_channel_send_fail_receive_response);
TEST (mctp_interface_test_send_request_message_timeout);
TEST (mctp_interface_test_send_request_message_timeout_then_good_message);
TEST (mctp_interface_test_send_request_message_timeout_then_good_message_wrap_tag);
TEST (mctp_interface_test_send_request_message_response_too_large);
TEST (mctp_interface_test_send_request_message_response_too_large_then_good_message);
TEST (mctp_interface_test_send_request_message_response_too_large_then_good_message_wrap_tag);
TEST (mctp_interface_test_send_discovery_notify_no_response);
TEST (mctp_interface_test_send_discovery_notify_process_response);
TEST (mctp_interface_test_send_discovery_notify_followed_by_another_rq);
TEST (mctp_interface_test_send_discovery_notify_followed_discovery_notify_rsp_then_another_rq);
TEST (mctp_interface_test_send_discovery_notify_static_init);
TEST (mctp_interface_test_send_discovery_notify_null);
TEST (mctp_interface_test_send_discovery_notify_no_mctp_bridge);
TEST (mctp_interface_test_send_discovery_notify_cmd_channel_fail);
TEST (mctp_interface_test_issue_request_no_wait);
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
TEST (mctp_interface_test_issue_request_then_process_packet_response);
TEST (mctp_interface_test_issue_request_then_process_response_fail);
TEST (mctp_interface_test_issue_request_then_process_error_packet);
TEST (mctp_interface_test_issue_request_mctp_control_then_process_packet_response);
TEST (mctp_interface_test_issue_request_mctp_control_then_process_packet_response_fail);
TEST (mctp_interface_test_issue_request_spdm_then_process_packet_response);
TEST (mctp_interface_test_issue_request_spdm_then_process_packet_response_fail);
TEST (mctp_interface_test_issue_request_static_init_then_process_packet_response);
TEST (mctp_interface_test_issue_request_static_init_mctp_control_then_process_packet_response);
TEST (mctp_interface_test_issue_request_static_init_spdm_then_process_packet_response);
TEST (mctp_interface_test_issue_request_null);
TEST (mctp_interface_test_issue_request_output_buf_too_small);
TEST (mctp_interface_test_issue_request_request_payload_too_large);
TEST (mctp_interface_test_issue_request_cmd_channel_fail);
TEST (mctp_interface_test_issue_request_then_process_packet_response_from_unexpected_eid);
TEST (mctp_interface_test_issue_request_then_process_packet_response_with_unexpected_msg_tag);
TEST (mctp_interface_test_issue_spdm_request_then_process_packet_response_spdm_unsupported);
#endif

TEST_SUITE_END;
