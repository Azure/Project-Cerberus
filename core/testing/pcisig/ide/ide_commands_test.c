// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "cmd_interface/cmd_interface.h"
#include "pcisig/ide/ide_driver.h"
#include "pcisig/ide/ide_commands.h"
#include "testing/mock/pcisig/ide/ide_driver_mock.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"


TEST_SUITE_LABEL ("ide_commands");


/**
 * Dependencies for testing.
 */
struct ide_commands_testing {
	struct cmd_interface_ide_responder ide_responder;	/**< IDE responder interface. */
	struct ide_driver_mock ide_driver_mock;				/**< IDE driver mock. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
static void ide_commands_testing_init_dependencies (CuTest *test,
	struct ide_commands_testing *testing)
{
	int status;

	status = ide_driver_mock_init (&testing->ide_driver_mock);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_ide_responder_init (&testing->ide_responder,
		&testing->ide_driver_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to release.
 */
static void ide_commands_testing_release_dependencies (CuTest *test,
	struct ide_commands_testing *testing)
{
	int status;

	cmd_interface_ide_responder_release (&testing->ide_responder);

	status = ide_driver_mock_validate_and_release (&testing->ide_driver_mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void ide_commands_test_ide_km_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x3D, /* IDE command Id */
	};

	struct ide_km_header *header = (struct ide_km_header*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_header));

	CuAssertIntEquals (test, 0x3D, header->object_id);
}

static void ide_commands_test_ide_km_query_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xBD, /* IDE command Id */
		0xFE, /* reserved */
		0xCD, /* port index */
	};

	struct ide_km_query *query = (struct ide_km_query*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_query));

	CuAssertIntEquals (test, 0xBD, query->header.object_id);
	CuAssertIntEquals (test, 0xFE, query->reserved);
	CuAssertIntEquals (test, 0xCD, query->port_index);
}

static void ide_commands_test_ide_km_query_resp_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAD, /* IDE command Id */
		0xFA, /* reserved */
		0xAD, /* port_index */
		0x25, /* dev_func_num */
		0x3D, /* bus_num */
		0x5A, /* segment */
		0x7F, /* max_port_index */
		0xDE, 0xAD, 0xBE, 0xEF, /* capability register */
		0x01, 0x02, 0x03, 0x04, /* control register */
	};

	struct ide_km_query_resp *query_resp = (struct ide_km_query_resp*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_query_resp));

	CuAssertIntEquals (test, 0xAD, query_resp->header.object_id);
	CuAssertIntEquals (test, 0xFA, query_resp->reserved);
	CuAssertIntEquals (test, 0xAD, query_resp->port_index);
	CuAssertIntEquals (test, 0x25, query_resp->dev_func_num);
	CuAssertIntEquals (test, 0x3D, query_resp->bus_num);
	CuAssertIntEquals (test, 0x5A, query_resp->segment);
	CuAssertIntEquals (test, 0x7F, query_resp->max_port_index);
	CuAssertIntEquals (test, 0xEFBEADDE, query_resp->capability_register);
	CuAssertIntEquals (test, 0x04030201, query_resp->control_register);
}

static void ide_commands_test_ide_km_key_prog_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAB, /* IDE command Id */
		0xFB, 0xCE, /* reserved[2] */
		0xAB, /* stream_id */
		0x2B, /* reserved2 */
		0x5A, /* sub_stream_info */
		0x6F /* port_index */
	};

	struct ide_km_key_prog *key_prog = (struct ide_km_key_prog*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_key_prog));

	CuAssertIntEquals (test, 0xAB, key_prog->header.object_id);
	CuAssertIntEquals (test, 0xFB, key_prog->reserved[0]);
	CuAssertIntEquals (test, 0xCE, key_prog->reserved[1]);
	CuAssertIntEquals (test, 0xAB, key_prog->stream_id);
	CuAssertIntEquals (test, 0x2B, key_prog->reserved2);
	CuAssertIntEquals (test, 0, key_prog->sub_stream_info.key_set);
	CuAssertIntEquals (test, 1, key_prog->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, 2, key_prog->sub_stream_info.reserved);
	CuAssertIntEquals (test, 0x5, key_prog->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, 0x6F, key_prog->port_index);
}

static void ide_commands_test_ide_km_aes_256_gcm_key_buffer_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x61, 0x62, 0x63, 0x64, /* 256-bit key */
		0x65, 0x66, 0x67, 0x68,
		0x69, 0x6A, 0x6B, 0x6C,
		0x6D, 0x6E, 0x6F, 0x70,
		0x71, 0x72, 0x73, 0x74,
		0x75, 0x76, 0x77, 0x78,
		0x79, 0x7A, 0x61, 0x62,
		0x63, 0x64, 0x65, 0x66,
		0x30, 0x31, 0x32, 0x33, /* 64-bit IV */
		0x34, 0x35, 0x36, 0x37
	};

	struct ide_km_aes_256_gcm_key_buffer *key_buffer =
		(struct ide_km_aes_256_gcm_key_buffer*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_aes_256_gcm_key_buffer));

	CuAssertIntEquals (test, 0x64636261, key_buffer->key[0]);
	CuAssertIntEquals (test, 0x68676665, key_buffer->key[1]);
	CuAssertIntEquals (test, 0x6C6B6A69, key_buffer->key[2]);
	CuAssertIntEquals (test, 0x706F6E6D, key_buffer->key[3]);
	CuAssertIntEquals (test, 0x74737271, key_buffer->key[4]);
	CuAssertIntEquals (test, 0x78777675, key_buffer->key[5]);
	CuAssertIntEquals (test, 0x62617A79, key_buffer->key[6]);
	CuAssertIntEquals (test, 0x66656463, key_buffer->key[7]);
	CuAssertIntEquals (test, 0x33323130, key_buffer->iv[0]);
	CuAssertIntEquals (test, 0x37363534, key_buffer->iv[1]);
}

static void ide_commands_test_ide_km_kp_ack_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xAC, /* IDE command Id */
		0xFA, 0xAE, /* reserved[2] */
		0x65, /* stream_id */
		0x66, /* status */
		0xCB, /* sub_stream_info */
		0x8F /* port_index */
	};

	struct ide_km_kp_ack *kp_ack =  (struct ide_km_kp_ack*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_kp_ack));

	CuAssertIntEquals (test, 0xAC, kp_ack->header.object_id);
	CuAssertIntEquals (test, 0xFA, kp_ack->reserved[0]);
	CuAssertIntEquals (test, 0xAE, kp_ack->reserved[1]);
	CuAssertIntEquals (test, 0x65, kp_ack->stream_id);
	CuAssertIntEquals (test, 0x66, kp_ack->status);
	CuAssertIntEquals (test, 1, kp_ack->sub_stream_info.key_set);
	CuAssertIntEquals (test, 1, kp_ack->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, 2, kp_ack->sub_stream_info.reserved);
	CuAssertIntEquals (test, 0xC, kp_ack->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, 0x8F, kp_ack->port_index);
}

static void ide_commands_test_ide_km_k_set_go_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xBC, /* IDE command Id */
		0xBA, 0xAB, /* reserved[2] */
		0x66, /* stream_id */
		0x67, /* reserved2 */
		0xFF, /* sub_stream_info */
		0x9F /* port_index */
	};

	struct ide_km_k_set_go *k_set_go =  (struct ide_km_k_set_go*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_k_set_go));

	CuAssertIntEquals (test, 0xBC, k_set_go->header.object_id);
	CuAssertIntEquals (test, 0xBA, k_set_go->reserved[0]);
	CuAssertIntEquals (test, 0xAB, k_set_go->reserved[1]);
	CuAssertIntEquals (test, 0x66, k_set_go->stream_id);
	CuAssertIntEquals (test, 0x67, k_set_go->reserved2);
	CuAssertIntEquals (test, 1, k_set_go->sub_stream_info.key_set);
	CuAssertIntEquals (test, 1, k_set_go->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, 3, k_set_go->sub_stream_info.reserved);
	CuAssertIntEquals (test, 0xF, k_set_go->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, 0x9F, k_set_go->port_index);
}

static void ide_commands_test_ide_km_k_set_stop_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xEC, /* IDE command Id */
		0xEA, 0xEB, /* reserved[2] */
		0xE6, /* stream_id */
		0xE7, /* reserved2 */
		0xEE, /* sub_stream_info */
		0xEF /* port_index */
	};

	struct ide_km_k_set_stop *k_set_stop =  (struct ide_km_k_set_stop*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_k_set_stop));

	CuAssertIntEquals (test, 0xEC, k_set_stop->header.object_id);
	CuAssertIntEquals (test, 0xEA, k_set_stop->reserved[0]);
	CuAssertIntEquals (test, 0xEB, k_set_stop->reserved[1]);
	CuAssertIntEquals (test, 0xE6, k_set_stop->stream_id);
	CuAssertIntEquals (test, 0xE7, k_set_stop->reserved2);
	CuAssertIntEquals (test, 0, k_set_stop->sub_stream_info.key_set);
	CuAssertIntEquals (test, 1, k_set_stop->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, 3, k_set_stop->sub_stream_info.reserved);
	CuAssertIntEquals (test, 0xE, k_set_stop->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, 0xEF, k_set_stop->port_index);
}

static void ide_commands_test_ide_km_k_gostop_ack_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xBC, /* IDE command Id */
		0xBA, 0xEB, /* reserved[2] */
		0xB6, /* stream_id */
		0xB7, /* reserved2 */
		0xBD, /* sub_stream_info */
		0xBF /* port_index */
	};

	struct ide_km_k_gostop_ack *k_set_stop =  (struct ide_km_k_gostop_ack*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_km_k_gostop_ack));

	CuAssertIntEquals (test, 0xBC, k_set_stop->header.object_id);
	CuAssertIntEquals (test, 0xBA, k_set_stop->reserved[0]);
	CuAssertIntEquals (test, 0xEB, k_set_stop->reserved[1]);
	CuAssertIntEquals (test, 0xB6, k_set_stop->stream_id);
	CuAssertIntEquals (test, 0xB7, k_set_stop->reserved2);
	CuAssertIntEquals (test, 1, k_set_stop->sub_stream_info.key_set);
	CuAssertIntEquals (test, 0, k_set_stop->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, 3, k_set_stop->sub_stream_info.reserved);
	CuAssertIntEquals (test, 0xB, k_set_stop->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, 0xBF, k_set_stop->port_index);
}

static void ide_commands_test_ide_capability_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, 0xAD, 0xBE, 0xEF,
	};

	struct ide_capability_register *capability_register =
		(struct ide_capability_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_capability_register));

	CuAssertIntEquals (test, 0xEFBEADDE, capability_register->value);
	CuAssertIntEquals (test, 0, capability_register->link_ide_stream_supported);
	CuAssertIntEquals (test, 1, capability_register->selective_ide_streams_supported);
	CuAssertIntEquals (test, 1, capability_register->flow_through_ide_stream_supported);
	CuAssertIntEquals (test, 1, capability_register->reserved);
	CuAssertIntEquals (test, 1, capability_register->aggregation_supported);
	CuAssertIntEquals (test, 0, capability_register->pcrc_supported);
	CuAssertIntEquals (test, 1, capability_register->ide_km_protocol_supported);
	CuAssertIntEquals (test, 1,
		capability_register->selective_ide_for_configuration_requests_supported);
	CuAssertIntEquals (test, 0xD, capability_register->supported_algorithms);
	CuAssertIntEquals (test, 0x5, capability_register->number_of_tcs_supported_for_link_ide);
	CuAssertIntEquals (test, 0xBE, capability_register->number_of_selective_ide_streams_supported);
	CuAssertIntEquals (test, 0xEF, capability_register->reserved2);
}

static void ide_commands_test_ide_control_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, 0xAD, 0xBE, 0xEF,
	};

	struct ide_control_register *control_register = (struct ide_control_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_control_register));

	CuAssertIntEquals (test, 0xEFBEADDE, control_register->value);
	CuAssertIntEquals (test, 2, control_register->reserved);
	CuAssertIntEquals (test, 1, control_register->flow_through_ide_stream_enabled);
	CuAssertIntEquals (test, 0x1DF7D5BB, control_register->reserved2);
}

static void ide_commands_test_ide_link_ide_stream_control_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xBA, 0xAD, 0xDE, 0xEF,
	};

	struct ide_link_ide_stream_control_register *control_register =
		(struct ide_link_ide_stream_control_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_link_ide_stream_control_register));

	CuAssertIntEquals (test, 0xEFDEADBA, control_register->value);
	CuAssertIntEquals (test, 0, control_register->link_ide_stream_enable);
	CuAssertIntEquals (test, 1, control_register->reserved);
	CuAssertIntEquals (test, 2, control_register->tx_aggregation_mode_npr);
	CuAssertIntEquals (test, 3, control_register->tx_aggregation_mode_pr);
	CuAssertIntEquals (test, 2, control_register->tx_aggregation_mode_cpl);
	CuAssertIntEquals (test, 1, control_register->pcrc_enable);
	CuAssertIntEquals (test, 0x16, control_register->reserved2);
	CuAssertIntEquals (test, 0x1A, control_register->selected_algorithm);
	CuAssertIntEquals (test, 0x3, control_register->tc);
	CuAssertIntEquals (test, 0x3, control_register->reserved3);
	CuAssertIntEquals (test, 0xEF, control_register->stream_id);
}

static void ide_commands_test_ide_link_ide_stream_status_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xBA, 0xAD, 0xF0, 0xFD,
	};

	struct ide_link_ide_stream_status_register *status_register =
		(struct ide_link_ide_stream_status_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer), sizeof (struct ide_link_ide_stream_status_register));

	CuAssertIntEquals (test, 0xFDF0ADBA, status_register->value);

	CuAssertIntEquals (test, 0xA, status_register->link_ide_stream_state);
	CuAssertIntEquals (test, 0x7DF0ADB, status_register->reserved);
	CuAssertIntEquals (test, 1, status_register->received_integrity_check_fail_message);
}

static void ide_commands_test_ide_selective_ide_stream_capability_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xBA, 0xAD, 0xF0, 0x0D,
	};

	struct ide_selective_ide_stream_capability_register *capability_register =
		(struct ide_selective_ide_stream_capability_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct ide_selective_ide_stream_capability_register));

	CuAssertIntEquals (test, 0x0DF0ADBA, capability_register->value);

	CuAssertIntEquals (test, 0xA,
		capability_register->number_of_address_association_register_blocks);
	CuAssertIntEquals (test, 0x0DF0ADB, capability_register->reserved);
}

static void ide_commands_test_ide_selective_ide_stream_control_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xCA, 0xFE, 0xB0, 0xBA
	};

	struct ide_selective_ide_stream_control_register *control_register =
		(struct ide_selective_ide_stream_control_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct ide_selective_ide_stream_control_register));

	CuAssertIntEquals (test, 0xBAB0FECA, control_register->value);

	CuAssertIntEquals (test, 0, control_register->selective_ide_stream_enable);
	CuAssertIntEquals (test, 1, control_register->reserved);
	CuAssertIntEquals (test, 2, control_register->tx_aggregation_mode_npr);
	CuAssertIntEquals (test, 0, control_register->tx_aggregation_mode_pr);
	CuAssertIntEquals (test, 3, control_register->tx_aggregation_mode_cpl);
	CuAssertIntEquals (test, 0, control_register->pcrc_enable);
	CuAssertIntEquals (test, 1, control_register->selective_ide_for_configuration_requests_enable);
	CuAssertIntEquals (test, 0xF, control_register->reserved2);
	CuAssertIntEquals (test, 3, control_register->selected_algorithm);
	CuAssertIntEquals (test, 6, control_register->tc);
	CuAssertIntEquals (test, 0, control_register->default_stream);
	CuAssertIntEquals (test, 1, control_register->reserved3);
	CuAssertIntEquals (test, 0xBA, control_register->stream_id);
}

static void ide_commands_test_ide_selective_ide_stream_status_register_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, 0xAD, 0xF0, 0xFD
	};

	struct ide_selective_ide_stream_status_register *status_register =
		(struct ide_selective_ide_stream_status_register*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct ide_selective_ide_stream_status_register));

	CuAssertIntEquals (test, 0xFDF0ADDE, status_register->value);

	CuAssertIntEquals (test, 0xE, status_register->selective_ide_stream_state);
	CuAssertIntEquals (test, 0x7DF0ADD, status_register->reserved);
	CuAssertIntEquals (test, 1, status_register->received_integrity_check_fail_message);
}

static void ide_commands_test_ide_selective_ide_rid_association_register_1_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, 0xAD, 0xB0, 0xBA
	};

	struct ide_selective_ide_rid_association_register_1 *reg =
		(struct ide_selective_ide_rid_association_register_1*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct ide_selective_ide_rid_association_register_1));

	CuAssertIntEquals (test, 0xBAB0ADDE, reg->value);

	CuAssertIntEquals (test, 0xDE, reg->reserved);
	CuAssertIntEquals (test, 0xB0AD, reg->rid_limit);
	CuAssertIntEquals (test, 0xBA, reg->reserved2);
}

static void ide_commands_test_ide_selective_ide_rid_association_register_2_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, 0xAD, 0xB0, 0xBA
	};

	struct ide_selective_ide_rid_association_register_2 *reg =
		(struct ide_selective_ide_rid_association_register_2*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct ide_selective_ide_rid_association_register_2));

	CuAssertIntEquals (test, 0xBAB0ADDE, reg->value);

	CuAssertIntEquals (test, 0, reg->valid);
	CuAssertIntEquals (test, 0x6F, reg->reserved);
	CuAssertIntEquals (test, 0xB0AD, reg->rid_base);
	CuAssertIntEquals (test, 0xBA, reg->reserved2);
}

static void ide_commands_test_ide_selective_ide_address_association_register_block_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0xDE, 0xAD, 0xB0, 0xBA, /* register_1 */
		0xDE, 0xAD, 0xBE, 0xEF, /* register_2 */
		0xCA, 0xFE, 0xB0, 0xBA, /* register_3 */
	};

	struct ide_selective_ide_address_association_register_block *register_block =
		(struct ide_selective_ide_address_association_register_block*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct ide_selective_ide_address_association_register_block));

	CuAssertIntEquals (test, 0xBAB0ADDE, register_block->register_1.value);
	CuAssertIntEquals (test, 0, register_block->register_1.valid);
	CuAssertIntEquals (test, 0x6F, register_block->register_1.reserved);
	CuAssertIntEquals (test, 0x0AD, register_block->register_1.memory_base_lower);
	CuAssertIntEquals (test, 0xBAB, register_block->register_1.memory_limit_lower);
	CuAssertIntEquals (test, 0xEFBEADDE, register_block->register_2);
	CuAssertIntEquals (test, 0xBAB0FECA, register_block->register_3);
}

static void ide_commands_test_ide_km_query (CuTest *test)
{
	struct ide_commands_testing testing;
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

	ide_commands_testing_init_dependencies (test, &testing);

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

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

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

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_invalid_params (CuTest *test)
{
	int status;

	TEST_START;

	status = ide_km_query ((struct ide_driver*) NULL, (struct cmd_interface_msg *) 0xDEADBEEF);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);

	status = ide_km_query ((struct ide_driver*) 0xDEADBEEF, (struct cmd_interface_msg *) NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);
}

static void ide_commands_test_ide_km_query_invalid_msg_size (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query) - 1;
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_bus_device_segment_info_fail (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock,
		IDE_DRIVER_GET_BUS_DEVICE_SEGMENT_INFO_FAILED, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);
	CuAssertIntEquals (test, IDE_DRIVER_GET_BUS_DEVICE_SEGMENT_INFO_FAILED, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_capability_register_fail (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock,
		0, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_capability_register, &testing.ide_driver_mock,
		IDE_DRIVER_GET_CAPABILITY_REGISTER_FAILED, MOCK_ARG (1), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, IDE_DRIVER_GET_CAPABILITY_REGISTER_FAILED, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_control_register_fail (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock,
		0, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_capability_register, &testing.ide_driver_mock,
		0, MOCK_ARG (1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_control_register, &testing.ide_driver_mock,
		IDE_DRIVER_GET_CONTROL_REGISTER_FAILED, MOCK_ARG (1), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, IDE_DRIVER_GET_CONTROL_REGISTER_FAILED, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_insufficient_output_buffer (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = sizeof (struct ide_km_query_resp) - 1;
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock,
		0, MOCK_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_capability_register, &testing.ide_driver_mock,
		0, MOCK_ARG (1), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_control_register, &testing.ide_driver_mock,0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_OUT_OF_BUFFER_SPACE, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_link_ide_register_block_insufficient_output_buffer (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;
	struct ide_capability_register capability_register = {0};
	struct ide_control_register control_register = {0};

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response =
		sizeof (struct ide_km_query_resp) + sizeof (struct ide_link_ide_stream_register_block) - 1;
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	capability_register.link_ide_stream_supported = 1;
	capability_register.number_of_tcs_supported_for_link_ide = 0;
	capability_register.selective_ide_streams_supported = 1;
	capability_register.number_of_selective_ide_streams_supported = 100;

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

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_OUT_OF_BUFFER_SPACE, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_link_ide_register_block_fail (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;
	struct ide_capability_register capability_register = {0};
	struct ide_control_register control_register = {0};

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	capability_register.link_ide_stream_supported = 1;
	capability_register.number_of_tcs_supported_for_link_ide = 0;
	capability_register.selective_ide_streams_supported = 1;
	capability_register.number_of_selective_ide_streams_supported = 100;

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

	status |= mock_expect (&testing.ide_driver_mock.mock,
			testing.ide_driver_mock.base.get_link_ide_register_block, &testing.ide_driver_mock,
			IDE_DRIVER_GET_LINK_IDE_REGISTER_BLOCK_FAILED, MOCK_ARG (1), MOCK_ARG (0),
			MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, IDE_DRIVER_GET_LINK_IDE_REGISTER_BLOCK_FAILED, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_selective_ide_stream_register_insufficient_output_buffer (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;
	struct ide_capability_register capability_register = {0};

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response =
		sizeof (struct ide_km_query_resp) + sizeof (struct ide_link_ide_stream_register_block) +
		sizeof (struct ide_selective_ide_stream_register_block) - 1;
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	capability_register.link_ide_stream_supported = 1;
	capability_register.number_of_tcs_supported_for_link_ide = 0;
	capability_register.selective_ide_streams_supported = 1;
	capability_register.number_of_selective_ide_streams_supported = 0;

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_capability_register, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &capability_register,
		sizeof (capability_register), -1);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_control_register, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &capability_register,
		sizeof (capability_register), -1);

	status |= mock_expect (&testing.ide_driver_mock.mock,
			testing.ide_driver_mock.base.get_link_ide_register_block, &testing.ide_driver_mock,
			0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_OUT_OF_BUFFER_SPACE, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_query_get_selective_ide_stream_register_block_fail (
	CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_query *rq = (struct ide_km_query*) buf;
	int status;
	struct ide_capability_register capability_register = {0};

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_query);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_QUERY;
	rq->port_index = 1;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_bus_device_segment_info, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	capability_register.link_ide_stream_supported = 1;
	capability_register.number_of_tcs_supported_for_link_ide = 0;
	capability_register.selective_ide_streams_supported = 1;
	capability_register.number_of_selective_ide_streams_supported = 0;

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_capability_register, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &capability_register,
		sizeof (capability_register), -1);

	status |= mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.get_control_register, &testing.ide_driver_mock, 0,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.ide_driver_mock.mock, 1, &capability_register,
		sizeof (capability_register), -1);

	status |= mock_expect (&testing.ide_driver_mock.mock,
			testing.ide_driver_mock.base.get_link_ide_register_block, &testing.ide_driver_mock,
			0, MOCK_ARG (1), MOCK_ARG (0), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ide_driver_mock.mock,
			testing.ide_driver_mock.base.get_selective_ide_stream_register_block,
			&testing.ide_driver_mock,
			IDE_DRIVER_GET_SELECTIVE_IDE_STREAM_REGISTER_BLOCK_FAILED, MOCK_ARG (1),
			MOCK_ARG (0), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ide_km_query (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, IDE_DRIVER_GET_SELECTIVE_IDE_STREAM_REGISTER_BLOCK_FAILED,
		status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_prog (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_key_prog *rq = (struct ide_km_key_prog*) buf;
	struct ide_km_kp_ack *rsp = (struct ide_km_kp_ack*) buf;
	int status;
	struct ide_km_aes_256_gcm_key_buffer *key_buffer;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_key_prog) +
		sizeof (struct ide_km_aes_256_gcm_key_buffer);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_KEY_PROG;
	rq->port_index = 1;
	rq->stream_id = 2;
	rq->sub_stream_info.key_set = 1;
	rq->sub_stream_info.rx_tx = 1;
	rq->sub_stream_info.key_sub_stream = 3;

	key_buffer = (struct ide_km_aes_256_gcm_key_buffer*) (rq + 1);

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.key_prog, &testing.ide_driver_mock, 0,
		MOCK_ARG (rq->port_index), MOCK_ARG (rq->stream_id), MOCK_ARG (rq->sub_stream_info.key_set),
		MOCK_ARG (rq->sub_stream_info.rx_tx), MOCK_ARG (rq->sub_stream_info.key_sub_stream),
		MOCK_ARG_PTR (&key_buffer->key), MOCK_ARG (sizeof (key_buffer->key)),
		MOCK_ARG_PTR (&key_buffer->iv), MOCK_ARG (sizeof (key_buffer->iv)));

	CuAssertIntEquals (test, 0, status);

	status = ide_km_key_prog (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct ide_km_kp_ack), msg.payload_length);
	CuAssertIntEquals (test, IDE_KM_OBJECT_ID_KP_ACK, rsp->header.object_id);
	CuAssertIntEquals (test, rq->stream_id, rsp->stream_id);
	CuAssertIntEquals (test, rq->sub_stream_info.key_set, rsp->sub_stream_info.key_set);
	CuAssertIntEquals (test, rq->sub_stream_info.rx_tx, rsp->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, rq->sub_stream_info.key_sub_stream,
		rsp->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, rq->port_index, rsp->port_index);
	CuAssertIntEquals (test, 0, rsp->status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_prog_invalid_params (CuTest *test)
{
	int status;

	TEST_START;

	status = ide_km_key_prog ((struct ide_driver*) NULL, (struct cmd_interface_msg *) 0xDEADBEEF);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);

	status = ide_km_key_prog ((struct ide_driver*) 0xDEADBEEF, (struct cmd_interface_msg *) NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);
}

static void ide_commands_test_ide_km_key_prog_invalid_msg_size (CuTest *test)
{
	int status;
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_key_prog *rq = (struct ide_km_key_prog*) buf;
	struct ide_km_kp_ack *rsp = (struct ide_km_kp_ack*) buf;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_key_prog) +
		sizeof (struct ide_km_aes_256_gcm_key_buffer) - 1;
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_KEY_PROG;
	rq->port_index = 1;
	rq->stream_id = 2;
	rq->sub_stream_info.key_set = 1;
	rq->sub_stream_info.rx_tx = 1;
	rq->sub_stream_info.key_sub_stream = 3;

	ide_commands_testing_init_dependencies (test, &testing);

	status = ide_km_key_prog (&testing.ide_driver_mock.base, &msg);
	
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct ide_km_kp_ack), msg.payload_length);
	CuAssertIntEquals (test, IDE_KM_OBJECT_ID_KP_ACK, rsp->header.object_id);
	CuAssertIntEquals (test, rq->stream_id, rsp->stream_id);
	CuAssertIntEquals (test, rq->sub_stream_info.key_set, rsp->sub_stream_info.key_set);
	CuAssertIntEquals (test, rq->sub_stream_info.rx_tx, rsp->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, rq->sub_stream_info.key_sub_stream,
		rsp->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, rq->port_index, rsp->port_index);
	CuAssertIntEquals (test, IDE_KM_KP_ACK_STATUS_INCORRECT_LENGTH, rsp->status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_prog_key_prog_fail (CuTest *test)
{
	int status;
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_key_prog *rq = (struct ide_km_key_prog*) buf;
	struct ide_km_kp_ack *rsp = (struct ide_km_kp_ack*) buf;
	struct ide_km_aes_256_gcm_key_buffer *key_buffer;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_key_prog) +
		sizeof (struct ide_km_aes_256_gcm_key_buffer);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_KEY_PROG;
	rq->port_index = 1;
	rq->stream_id = 2;
	rq->sub_stream_info.key_set = 1;
	rq->sub_stream_info.rx_tx = 1;
	rq->sub_stream_info.key_sub_stream = 3;

	key_buffer = (struct ide_km_aes_256_gcm_key_buffer*) (rq + 1);

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.key_prog, &testing.ide_driver_mock, IDE_DRIVER_KEY_PROG_FAILED,
		MOCK_ARG (rq->port_index), MOCK_ARG (rq->stream_id), MOCK_ARG (rq->sub_stream_info.key_set),
		MOCK_ARG (rq->sub_stream_info.rx_tx), MOCK_ARG (rq->sub_stream_info.key_sub_stream),
		MOCK_ARG_PTR (&key_buffer->key), MOCK_ARG (sizeof (key_buffer->key)),
		MOCK_ARG_PTR (&key_buffer->iv), MOCK_ARG (sizeof (key_buffer->iv)));

	CuAssertIntEquals (test, 0, status);

	status = ide_km_key_prog (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct ide_km_kp_ack), msg.payload_length);
	CuAssertIntEquals (test, IDE_KM_OBJECT_ID_KP_ACK, rsp->header.object_id);
	CuAssertIntEquals (test, rq->stream_id, rsp->stream_id);
	CuAssertIntEquals (test, rq->sub_stream_info.key_set, rsp->sub_stream_info.key_set);
	CuAssertIntEquals (test, rq->sub_stream_info.rx_tx, rsp->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, rq->sub_stream_info.key_sub_stream,
		rsp->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, rq->port_index, rsp->port_index);
	CuAssertIntEquals (test, IDE_KM_KP_ACK_STATUS_UNSPECIFIED_FAILURE, rsp->status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_set_go (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_k_set_go *rq = (struct ide_km_k_set_go*) buf;
	struct ide_km_k_gostop_ack *rsp = (struct ide_km_k_gostop_ack*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_k_set_go);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_K_SET_GO;
	rq->port_index = 1;
	rq->stream_id = 2;
	rq->sub_stream_info.key_set = 0;
	rq->sub_stream_info.rx_tx = 1;
	rq->sub_stream_info.key_sub_stream = 3;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.key_set_go, &testing.ide_driver_mock, 0,
		MOCK_ARG (rq->port_index), MOCK_ARG (rq->stream_id), MOCK_ARG (rq->sub_stream_info.key_set),
		MOCK_ARG (rq->sub_stream_info.rx_tx), MOCK_ARG (rq->sub_stream_info.key_sub_stream));

	CuAssertIntEquals (test, 0, status);

	status = ide_km_key_set_go (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct ide_km_k_gostop_ack), msg.payload_length);
	CuAssertIntEquals (test, IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK, rsp->header.object_id);
	CuAssertIntEquals (test, rq->stream_id, rsp->stream_id);
	CuAssertIntEquals (test, rq->sub_stream_info.key_set, rsp->sub_stream_info.key_set);
	CuAssertIntEquals (test, rq->sub_stream_info.rx_tx, rsp->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, rq->sub_stream_info.key_sub_stream,
		rsp->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, rq->port_index, rsp->port_index);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_set_go_invalid_params (CuTest *test)
{
	int status;

	TEST_START;

	status = ide_km_key_set_go ((struct ide_driver*) NULL, (struct cmd_interface_msg *) 0xDEADBEEF);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);

	status = ide_km_key_set_go ((struct ide_driver*) 0xDEADBEEF, (struct cmd_interface_msg *) NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);
}

static void ide_commands_test_ide_km_key_set_go_invalid_msg_size (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_k_set_go *rq = (struct ide_km_k_set_go*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_k_set_go) - 1;
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_K_SET_GO;

	ide_commands_testing_init_dependencies (test, &testing);

	status = ide_km_key_set_go (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_set_go_fail (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_k_set_go *rq = (struct ide_km_k_set_go*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_k_set_go);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_K_SET_GO;
	rq->port_index = 1;
	rq->stream_id = 2;
	rq->sub_stream_info.key_set = 0;
	rq->sub_stream_info.rx_tx = 1;
	rq->sub_stream_info.key_sub_stream = 3;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.key_set_go, &testing.ide_driver_mock,
		IDE_DRIVER_KEY_SET_GO_FAILED, MOCK_ARG (rq->port_index), MOCK_ARG (rq->stream_id),
		MOCK_ARG (rq->sub_stream_info.key_set), MOCK_ARG (rq->sub_stream_info.rx_tx),
		MOCK_ARG (rq->sub_stream_info.key_sub_stream));

	CuAssertIntEquals (test, 0, status);

	status = ide_km_key_set_go (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, IDE_DRIVER_KEY_SET_GO_FAILED, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_set_stop (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_k_set_stop *rq = (struct ide_km_k_set_stop*) buf;
	struct ide_km_k_gostop_ack *rsp = (struct ide_km_k_gostop_ack*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_k_set_stop);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_K_SET_STOP;
	rq->port_index = 3;
	rq->stream_id = 1;
	rq->sub_stream_info.key_set = 1;
	rq->sub_stream_info.rx_tx = 0;
	rq->sub_stream_info.key_sub_stream = 4;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.key_set_stop, &testing.ide_driver_mock, 0,
		MOCK_ARG (rq->port_index), MOCK_ARG (rq->stream_id), MOCK_ARG (rq->sub_stream_info.key_set),
		MOCK_ARG (rq->sub_stream_info.rx_tx), MOCK_ARG (rq->sub_stream_info.key_sub_stream));

	CuAssertIntEquals (test, 0, status);

	status = ide_km_key_set_stop (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct ide_km_k_gostop_ack), msg.payload_length);
	CuAssertIntEquals (test, IDE_KM_OBJECT_ID_K_SET_GOSTOP_ACK, rsp->header.object_id);
	CuAssertIntEquals (test, rq->stream_id, rsp->stream_id);
	CuAssertIntEquals (test, rq->sub_stream_info.key_set, rsp->sub_stream_info.key_set);
	CuAssertIntEquals (test, rq->sub_stream_info.rx_tx, rsp->sub_stream_info.rx_tx);
	CuAssertIntEquals (test, rq->sub_stream_info.key_sub_stream,
		rsp->sub_stream_info.key_sub_stream);
	CuAssertIntEquals (test, rq->port_index, rsp->port_index);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_set_stop_invalid_params (CuTest *test)
{
	int status;

	TEST_START;

	status = ide_km_key_set_stop ((struct ide_driver*) NULL,
		(struct cmd_interface_msg *) 0xDEADBEEF);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);

	status = ide_km_key_set_stop ((struct ide_driver*) 0xDEADBEEF,
		(struct cmd_interface_msg *) NULL);
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_ARGUMENT, status);
}

static void ide_commands_test_ide_km_key_set_stop_invalid_msg_size (CuTest *test)
{
	int status;
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_k_set_stop *rq = (struct ide_km_k_set_stop*) buf;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_k_set_stop) - 1;
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_K_SET_STOP;

	ide_commands_testing_init_dependencies (test, &testing);

	status = ide_km_key_set_stop (&testing.ide_driver_mock.base, &msg);
	
	CuAssertIntEquals (test, CMD_INTERFACE_IDE_RESPONDER_INVALID_MSG_SIZE, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

static void ide_commands_test_ide_km_key_set_stop_fail (CuTest *test)
{
	struct ide_commands_testing testing;
	struct cmd_interface_msg msg;
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct ide_km_k_set_stop *rq = (struct ide_km_k_set_stop*) buf;
	int status;

	TEST_START;

	memset (&msg, 0, sizeof (msg));
	msg.data = buf;
	msg.payload = (uint8_t*) rq;
	msg.payload_length = sizeof (struct ide_km_k_set_stop);
	msg.max_response = ARRAY_SIZE (buf);
	rq->header.object_id = IDE_KM_OBJECT_ID_K_SET_STOP;
	rq->port_index = 2;
	rq->stream_id = 1;
	rq->sub_stream_info.key_set = 1;
	rq->sub_stream_info.rx_tx = 0;
	rq->sub_stream_info.key_sub_stream = 2;

	ide_commands_testing_init_dependencies (test, &testing);

	status = mock_expect (&testing.ide_driver_mock.mock,
		testing.ide_driver_mock.base.key_set_stop, &testing.ide_driver_mock,
		IDE_DRIVER_KEY_SET_STOP_FAILED, MOCK_ARG (rq->port_index), MOCK_ARG (rq->stream_id),
		MOCK_ARG (rq->sub_stream_info.key_set), MOCK_ARG (rq->sub_stream_info.rx_tx),
		MOCK_ARG (rq->sub_stream_info.key_sub_stream));

	CuAssertIntEquals (test, 0, status);

	status = ide_km_key_set_stop (&testing.ide_driver_mock.base, &msg);

	CuAssertIntEquals (test, IDE_DRIVER_KEY_SET_STOP_FAILED, status);

	ide_commands_testing_release_dependencies (test, &testing);
}

TEST_SUITE_START (ide_commands);

TEST (ide_commands_test_ide_km_header_format);
TEST (ide_commands_test_ide_km_query_format);
TEST (ide_commands_test_ide_km_query_resp_format);
TEST (ide_commands_test_ide_km_key_prog_format);
TEST (ide_commands_test_ide_km_aes_256_gcm_key_buffer_format);
TEST (ide_commands_test_ide_km_kp_ack_format);
TEST (ide_commands_test_ide_km_k_set_go_format);
TEST (ide_commands_test_ide_km_k_set_stop_format);
TEST (ide_commands_test_ide_km_k_gostop_ack_format);
TEST (ide_commands_test_ide_capability_register_format);
TEST (ide_commands_test_ide_control_register_format);
TEST (ide_commands_test_ide_link_ide_stream_control_register_format);
TEST (ide_commands_test_ide_link_ide_stream_status_register_format);
TEST (ide_commands_test_ide_selective_ide_stream_capability_register_format);
TEST (ide_commands_test_ide_selective_ide_stream_control_register_format);
TEST (ide_commands_test_ide_selective_ide_stream_status_register_format);
TEST (ide_commands_test_ide_selective_ide_rid_association_register_1_format);
TEST (ide_commands_test_ide_selective_ide_rid_association_register_2_format);
TEST (ide_commands_test_ide_selective_ide_address_association_register_block_format);
TEST (ide_commands_test_ide_km_query);
TEST (ide_commands_test_ide_km_query_invalid_params);
TEST (ide_commands_test_ide_km_query_invalid_msg_size);
TEST (ide_commands_test_ide_km_query_get_bus_device_segment_info_fail);
TEST (ide_commands_test_ide_km_query_get_capability_register_fail);
TEST (ide_commands_test_ide_km_query_get_control_register_fail);
TEST (ide_commands_test_ide_km_query_insufficient_output_buffer);
TEST (ide_commands_test_ide_km_query_get_link_ide_register_block_insufficient_output_buffer);
TEST (ide_commands_test_ide_km_query_get_link_ide_register_block_fail);
TEST (ide_commands_test_ide_km_query_get_selective_ide_stream_register_insufficient_output_buffer);
TEST (ide_commands_test_ide_km_query_get_selective_ide_stream_register_block_fail);
TEST (ide_commands_test_ide_km_key_prog);
TEST (ide_commands_test_ide_km_key_prog_invalid_params);
TEST (ide_commands_test_ide_km_key_prog_invalid_msg_size);
TEST (ide_commands_test_ide_km_key_prog_key_prog_fail);
TEST (ide_commands_test_ide_km_key_set_go);
TEST (ide_commands_test_ide_km_key_set_go_invalid_params);
TEST (ide_commands_test_ide_km_key_set_go_invalid_msg_size);
TEST (ide_commands_test_ide_km_key_set_go_fail);
TEST (ide_commands_test_ide_km_key_set_stop);
TEST (ide_commands_test_ide_km_key_set_stop_invalid_params);
TEST (ide_commands_test_ide_km_key_set_stop_invalid_msg_size);
TEST (ide_commands_test_ide_km_key_set_stop_fail);

TEST_SUITE_END;
