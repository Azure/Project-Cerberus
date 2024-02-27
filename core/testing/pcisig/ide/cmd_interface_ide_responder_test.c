// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "spdm/spdm_commands.h"
#include "pcisig/ide/cmd_interface_ide_responder_static.h"
#include "pcisig/ide/ide_driver.h"
#include "testing/mock/pcisig/ide/ide_driver_mock.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"


TEST_SUITE_LABEL ("cmd_interface_ide_responder");


/**
 * Dependencies for testing.
 */
struct cmd_interface_ide_responder_testing {
	struct cmd_interface_ide_responder ide_responder;
	struct ide_driver_mock ide_driver_mock;
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void cmd_interface_ide_responder_testing_init_dependencies (CuTest *test,
	struct cmd_interface_ide_responder_testing *testing)
{
	int status;

	status = ide_driver_mock_init (&testing->ide_driver_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all dependencies for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void cmd_interface_ide_responder_testing_release_dependencies (CuTest *test,
	struct cmd_interface_ide_responder_testing *testing)
{
	int status;

	status = ide_driver_mock_validate_and_release (&testing->ide_driver_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the IDE responder interface for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void cmd_interface_ide_responder_testing_init (CuTest *test,
	struct cmd_interface_ide_responder_testing *testing)
{
	int status;

	cmd_interface_ide_responder_testing_init_dependencies (test, testing);

	status = cmd_interface_ide_responder_init (&testing->ide_responder,
		&testing->ide_driver_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the IDE responder interface after testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void cmd_interface_ide_responder_testing_release (CuTest *test,
	struct cmd_interface_ide_responder_testing *testing)
{
	cmd_interface_ide_responder_release (&testing->ide_responder);

	cmd_interface_ide_responder_testing_release_dependencies (test, testing);
}


/*******************
 * Test cases
 *******************/


static void cmd_interface_ide_responder_test_static_init (CuTest *test)
{
	const struct ide_driver *ide_driver = (struct ide_driver*) (0xDEADBEEF);

	const struct cmd_interface_ide_responder ide_responder =
		cmd_interface_ide_responder_static_init (ide_driver);

	TEST_START;

	CuAssertPtrNotNull (test, ide_responder.base.process_request);
	CuAssertPtrNotNull (test, ide_responder.base.process_response);
	CuAssertPtrNotNull (test, ide_responder.base.generate_error_packet);
}

static void cmd_interface_ide_responder_test_init (CuTest *test)
{
	struct cmd_interface_ide_responder_testing testing;
	int status;

	TEST_START;

	cmd_interface_ide_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_ide_responder_init (&testing.ide_responder,
		&testing.ide_driver_mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.ide_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.ide_responder.base.process_response);
	CuAssertPtrNotNull (test, testing.ide_responder.base.generate_error_packet);

	cmd_interface_ide_responder_testing_release (test, &testing);
}

static void cmd_interface_ide_responder_test_init_invalid_param (CuTest *test)
{
	int status;

	TEST_START;

	status = cmd_interface_ide_responder_init (NULL, (struct ide_driver*) (0xDEADBEEF));
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_ide_responder_init ((struct cmd_interface_ide_responder*) (0xBAADF00D),
		NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);
}

static void cmd_interface_ide_responder_test_release_null (CuTest *test)
{
	TEST_START;

	cmd_interface_ide_responder_release (NULL);
}

static void cmd_interface_ide_responder_test_process_request_query (CuTest *test)
{
	struct cmd_interface_ide_responder_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	struct ide_km_query_resp *rsp = (struct ide_km_query_resp*) buf;
	int status;
	uint8_t bus_num = 1;
	uint8_t dev_func_num = 2;
	uint8_t segment = 3;
	uint8_t max_port_index = 4;
	struct ide_capability_register capability_register = {0};
	struct ide_control_register control_register = {0};
	const uint32_t selective_ide_stream_register_block_count = 100;
	struct ide_selective_ide_stream_register_block
		selective_ide_reg_block[selective_ide_stream_register_block_count];
	struct ide_link_ide_stream_register_block link_ide_reg_block[IDE_KM_LINK_IDE_REG_BLOCK_MAX_COUNT];
	int i, j;
	struct ide_link_ide_stream_register_block *rsp_link_ide_stream_register_block;
	struct ide_selective_ide_stream_register_block *rsp_selective_ide_stream_register_block;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	cmd_interface_ide_responder_testing_init (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &bus_num, sizeof (uint8_t), -1);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 2, &dev_func_num, sizeof (uint8_t),
		-1);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 3, &segment, sizeof (uint8_t), -1);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 4, &max_port_index,
		sizeof (uint8_t), -1);

	capability_register.link_ide_stream_supported = 1;
	capability_register.number_of_tcs_supported_for_link_ide = 7; /* 8 tcs supported */
	capability_register.selective_ide_streams_supported = 1;
	capability_register.number_of_selective_ide_streams_supported =
	 selective_ide_stream_register_block_count - 1; /* 100 streams supported. */

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_capability_register, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &capability_register,
		sizeof (capability_register), -1);

	control_register.flow_through_ide_stream_enabled = 1;
	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_control_register, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &control_register,
		sizeof (control_register), -1);

	for (i = 0; i < (capability_register.number_of_tcs_supported_for_link_ide + 1); i++) {

		link_ide_reg_block[i].stream_control_register.value = rand ();
		link_ide_reg_block[i].stream_status_register.value = rand ();

		status |= mock_expect (&testing.ide_driver_mock.mock,
			testing.ide_driver_mock.base.get_link_ide_register_block, &testing.ide_driver_mock, 0,
			MOCK_ARG (1), MOCK_ARG (i), MOCK_ARG_NOT_NULL);

		status |= mock_expect_output (&testing.ide_driver_mock.mock, 2, &link_ide_reg_block[i],
			sizeof (struct ide_link_ide_stream_register_block), -1);
	}

	for (i = 0; i < (capability_register.number_of_selective_ide_streams_supported + 1); i++) {

		selective_ide_reg_block[i].sel_ide_stream_cap_reg.value = rand ();
		selective_ide_reg_block[i].sel_ide_stream_cap_reg.number_of_address_association_register_blocks
			= SELECTIVE_IDE_ADDRESS_ASSOCIATION_REGISTER_BLOCK_MAX_COUNT;
		selective_ide_reg_block[i].sel_ide_stream_control_reg.value = rand ();
		selective_ide_reg_block[i].sel_ide_stream_status_reg.value = rand ();
		selective_ide_reg_block[i].ide_rid_assoc_reg_1.value = rand ();
		selective_ide_reg_block[i].ide_rid_assoc_reg_2.value = rand ();

		for (j = 0; j < SELECTIVE_IDE_ADDRESS_ASSOCIATION_REGISTER_BLOCK_MAX_COUNT; j++) {
			selective_ide_reg_block[i].addr_assoc_reg_block[j].register_1.value = rand ();
			selective_ide_reg_block[i].addr_assoc_reg_block[j].register_2 = rand ();
			selective_ide_reg_block[i].addr_assoc_reg_block[j].register_2 = rand ();
		}

		status |= mock_expect (&testing.ide_driver_mock.mock,
			testing.ide_driver_mock.base.get_selective_ide_stream_register_block,
			&testing.ide_driver_mock, 0, MOCK_ARG (1), MOCK_ARG (i), MOCK_ARG_NOT_NULL);

		status |= mock_expect_output (&testing.ide_driver_mock.mock, 2, &selective_ide_reg_block[i],
			sizeof (struct ide_selective_ide_stream_register_block), -1);
	}

	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_ide_responder_process_request (
		(const struct cmd_interface*) (&testing.ide_responder), &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, rsp->port_index);
	CuAssertIntEquals (test, IDE_KM_OBJECT_ID_QUERY_RESP, rsp->header.object_id);
	CuAssertIntEquals (test, bus_num, rsp->bus_num);
	CuAssertIntEquals (test, dev_func_num, rsp->dev_func_num);
	CuAssertIntEquals (test, segment, rsp->segment);
	CuAssertIntEquals (test, max_port_index, rsp->max_port_index);
	CuAssertIntEquals (test, capability_register.value, rsp->capability_register);
	CuAssertIntEquals (test, control_register.value, rsp->control_register);

	/* Validate the Link IDE Register Block array. */
	rsp_link_ide_stream_register_block = (struct ide_link_ide_stream_register_block *) (rsp + 1);

	for (i = 0; i < (capability_register.number_of_tcs_supported_for_link_ide + 1); i++) {
		CuAssertIntEquals (test, link_ide_reg_block[i].stream_control_register.value,
			rsp_link_ide_stream_register_block[i].stream_control_register.value);

		CuAssertIntEquals (test, link_ide_reg_block[i].stream_status_register.value,
			rsp_link_ide_stream_register_block[i].stream_status_register.value);
	}

	/* Validate the Selective IDE Register Block array. */
	rsp_selective_ide_stream_register_block = (struct ide_selective_ide_stream_register_block *)
		(rsp_link_ide_stream_register_block +
		(capability_register.number_of_tcs_supported_for_link_ide + 1));

	for (i = 0; i < (capability_register.number_of_selective_ide_streams_supported + 1); i++) {
		CuAssertIntEquals (test, selective_ide_reg_block[i].sel_ide_stream_cap_reg.value,
			rsp_selective_ide_stream_register_block[i].sel_ide_stream_cap_reg.value);

		CuAssertIntEquals (test, selective_ide_reg_block[i].sel_ide_stream_control_reg.value,
			rsp_selective_ide_stream_register_block[i].sel_ide_stream_control_reg.value);

		CuAssertIntEquals (test, selective_ide_reg_block[i].sel_ide_stream_status_reg.value,
			rsp_selective_ide_stream_register_block[i].sel_ide_stream_status_reg.value);

		CuAssertIntEquals (test, selective_ide_reg_block[i].ide_rid_assoc_reg_1.value,
			rsp_selective_ide_stream_register_block[i].ide_rid_assoc_reg_1.value);

		CuAssertIntEquals (test, selective_ide_reg_block[i].ide_rid_assoc_reg_2.value,
			rsp_selective_ide_stream_register_block[i].ide_rid_assoc_reg_2.value);

		/* Validate the Address Association Register Block array. */
		for (j = 0; j < SELECTIVE_IDE_ADDRESS_ASSOCIATION_REGISTER_BLOCK_MAX_COUNT; j++) {
			CuAssertIntEquals (test,
				selective_ide_reg_block[i].addr_assoc_reg_block[j].register_1.value,
				rsp_selective_ide_stream_register_block[i].addr_assoc_reg_block[j].register_1.value);

			CuAssertIntEquals (test, selective_ide_reg_block[i].addr_assoc_reg_block[j].register_2,
				rsp_selective_ide_stream_register_block[i].addr_assoc_reg_block[j].register_2);

			CuAssertIntEquals (test, selective_ide_reg_block[i].addr_assoc_reg_block[j].register_2,
				rsp_selective_ide_stream_register_block[i].addr_assoc_reg_block[j].register_2);
		}
	}

	cmd_interface_ide_responder_testing_release (test, &testing);
}

static void cmd_interface_ide_responder_test_process_request_invalid_params (CuTest *test)
{
	int status;

	status = cmd_interface_ide_responder_process_request (NULL,
		(struct cmd_interface_msg*)(0xDEADBEEF));
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);

	status = cmd_interface_ide_responder_process_request (
		(const struct cmd_interface*) (0xDEADBEEF), NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);
}

static void cmd_interface_ide_responder_test_process_request_invalid_msg_size (CuTest *test)
{
	struct cmd_interface_ide_responder_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_header *header = (struct ide_km_header*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) header;
	msg.payload_length = sizeof (struct ide_km_header) - 1;
	msg.max_response = ARRAY_SIZE (buf);

	cmd_interface_ide_responder_testing_init (test, &testing);

	status = cmd_interface_ide_responder_process_request (
		(const struct cmd_interface*) (&testing.ide_responder), &msg);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE, status);
}

static void cmd_interface_ide_responder_test_process_request_unkown_command (CuTest *test)
{
	struct cmd_interface_ide_responder_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_header *header = (struct ide_km_header*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) header;
	msg.payload_length = sizeof (struct ide_km_header);
	msg.max_response = ARRAY_SIZE (buf);
	header->object_id = -1;

	cmd_interface_ide_responder_testing_init (test, &testing);

	status = cmd_interface_ide_responder_process_request (
		(const struct cmd_interface*) (&testing.ide_responder), &msg);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_UNKNOWN_COMMAND, status);
}

static void cmd_interface_ide_responder_test_process_response (CuTest *test)
{
	int status;
	struct cmd_interface_ide_responder *ide_responder;
	struct cmd_interface_ide_responder_testing testing;

	TEST_START;

	cmd_interface_ide_responder_testing_init (test, &testing);

	ide_responder = &testing.ide_responder;

	status = ide_responder->base.process_response ((const struct cmd_interface*) 0xDEADBEEF,
		(struct cmd_interface_msg*) 0xBAADB00F);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_ide_responder_testing_release (test, &testing);
}

static void cmd_interface_ide_responder_test_generate_error_packet (CuTest *test)
{
	int status;
	struct cmd_interface_ide_responder *ide_responder;
	struct cmd_interface_ide_responder_testing testing;

	TEST_START;

	cmd_interface_ide_responder_testing_init (test, &testing);

	ide_responder = &testing.ide_responder;

	status = ide_responder->base.generate_error_packet ((const struct cmd_interface*) 0xDEADBEEF,
		(struct cmd_interface_msg*) 0xBAADB00F, 0, 0, 0);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_ide_responder_testing_release (test, &testing);
}


TEST_SUITE_START (cmd_interface_ide_responder);

TEST (cmd_interface_ide_responder_test_static_init);
TEST (cmd_interface_ide_responder_test_init);
TEST (cmd_interface_ide_responder_test_init_invalid_param);
TEST (cmd_interface_ide_responder_test_release_null);
TEST (cmd_interface_ide_responder_test_process_request_query);
TEST (cmd_interface_ide_responder_test_process_request_invalid_params);
TEST (cmd_interface_ide_responder_test_process_request_invalid_msg_size);
TEST (cmd_interface_ide_responder_test_process_request_unkown_command);
TEST (cmd_interface_ide_responder_test_process_response);
TEST (cmd_interface_ide_responder_test_generate_error_packet);

TEST_SUITE_END;
