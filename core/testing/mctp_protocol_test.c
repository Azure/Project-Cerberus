// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "crypto/checksum.h"
#include "mctp/mctp_protocol.h"


static const char *SUITE = "mctp_protocol";


/*******************
 * Test cases
 *******************/

static void mctp_protocol_test_interpret_control_message (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG, payload[0]);
	CuAssertIntEquals (test, 0xAA, payload[1]);
	CuAssertIntEquals (test, 0xBB, payload[2]);
	CuAssertIntEquals (test, 0xCC, payload[3]);
	CuAssertIntEquals (test, 0xDD, payload[4]);
	CuAssertIntEquals (test, 0xEE, payload[5]);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_protocol_test_interpret_control_message_not_som (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 0;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertIntEquals (test, 0x01, payload[0]);
	CuAssertIntEquals (test, 0xAA, payload[1]);
	CuAssertIntEquals (test, 0xBB, payload[2]);
	CuAssertIntEquals (test, 0xCC, payload[3]);
	CuAssertIntEquals (test, 0xDD, payload[4]);
	CuAssertIntEquals (test, 0xEE, payload[5]);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_protocol_test_interpret_vendor_defined_message (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, payload[0]);
	CuAssertIntEquals (test, 0xAA, payload[1]);
	CuAssertIntEquals (test, 0xBB, payload[2]);
	CuAssertIntEquals (test, 0xCC, payload[3]);
	CuAssertIntEquals (test, 0xDD, payload[4]);
	CuAssertIntEquals (test, 0xEE, payload[5]);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_protocol_test_interpret_vendor_defined_message_not_som (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 0;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertIntEquals (test, 0x01, payload[0]);
	CuAssertIntEquals (test, 0xAA, payload[1]);
	CuAssertIntEquals (test, 0xBB, payload[2]);
	CuAssertIntEquals (test, 0xCC, payload[3]);
	CuAssertIntEquals (test, 0xDD, payload[4]);
	CuAssertIntEquals (test, 0xEE, payload[5]);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_protocol_test_interpret_not_som_unsupported_message_type (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0xAA;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 0;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_UNSUPPORTED_MSG, status);
}

static void mctp_protocol_test_interpret_null (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t crc;
	uint8_t msg_type = 0;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	status = mctp_protocol_interpret (NULL, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, NULL, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, NULL, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, NULL, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, NULL, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, NULL,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		NULL, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, NULL, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, NULL, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, NULL, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, NULL, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, NULL);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);
}

static void mctp_protocol_test_interpret_invalid_message (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t crc = 0;
	uint8_t msg_type;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = 0;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_MSG, status);

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_MSG, status);

	header->rsvd = 1;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_MSG, status);
}

static void mctp_protocol_test_interpret_invalid_message_type (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0xAA;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_UNSUPPORTED_MSG, status);
}

static void mctp_protocol_test_interpret_invalid_header_version (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 2;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_protocol_interpret (buf, sizeof (buf), 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_UNSUPPORTED_MSG, status);
}

static void mctp_protocol_test_interpret_invalid_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t *payload;
	size_t payload_len;

	TEST_START;


	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x0B;
	header->source_eid = 0x0A;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0x55, buf, 13);

	status = mctp_protocol_interpret (buf, sizeof (buf), 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_BAD_CHECKSUM, status);
}

static void mctp_protocol_test_construct_control_message (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_protocol_test_construct_control_message_not_som (CuTest *test)
{
	int status;
	uint8_t msg_type = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = 0x01;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, false, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x12, out_buf[6]);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_protocol_test_construct_vendor_defined_message (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_protocol_test_construct_vendor_defined_message_not_som (CuTest *test)
{
	int status;
	uint8_t msg_type = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = 0x01;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, false, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x12, out_buf[6]);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_protocol_test_construct_control_request (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_REQUEST, 0x5D, &msg_type);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x9A, out_buf[6]);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_protocol_test_construct_vendor_defined_request (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_REQUEST, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x9A, out_buf[6]);
	CuAssertIntEquals (test, MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_protocol_test_construct_unsupported_message (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = 0x01;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_REQUEST, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_UNSUPPORTED_MSG, status);
}

static void mctp_protocol_test_construct_control_message_buf_too_small (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[sizeof (struct mctp_protocol_transport_header) + sizeof (buf) - 1];

	TEST_START;

	buf[0] = MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_BUF_TOO_SMALL, status);
}

static void mctp_protocol_test_construct_vendor_defined_message_buf_too_small (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_PACKET_OVERHEAD + sizeof (buf) - 1];

	TEST_START;

	buf[0] = MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_BUF_TOO_SMALL, status);
}

static void mctp_protocol_test_construct_null (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

 	TEST_START;

	status = mctp_protocol_construct (NULL, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_protocol_construct (buf, sizeof (buf), NULL, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_INVALID_ARGUMENT, status);
}

static void mctp_protocol_test_construct_invalid_buf_len (CuTest *test)
{
	int status;
	uint8_t msg_type;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_PROTOCOL_MAX_PACKET_LEN];

 	TEST_START;

	status = mctp_protocol_construct (buf, 0, out_buf, sizeof (out_buf), 0xAA, 0x0A, 0x0B, true,
		false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D, &msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_BAD_BUFFER_LENGTH, status);

	status = mctp_protocol_construct (buf, MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT + 1, out_buf,
		sizeof (out_buf), 0xAA, 0x0A, 0x0B, true, false, 1, 2, MCTP_PROTOCOL_TO_RESPONSE, 0x5D,
		&msg_type);
	CuAssertIntEquals (test, MCTP_PROTOCOL_BAD_BUFFER_LENGTH, status);
}


CuSuite* get_mctp_protocol_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_control_message);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_control_message_not_som);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_vendor_defined_message);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_vendor_defined_message_not_som);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_not_som_unsupported_message_type);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_null);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_invalid_message);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_invalid_message_type);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_invalid_header_version);
	SUITE_ADD_TEST (suite, mctp_protocol_test_interpret_invalid_crc);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_control_message);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_control_message_not_som);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_vendor_defined_message);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_vendor_defined_message_not_som);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_control_request);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_vendor_defined_request);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_unsupported_message);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_control_message_buf_too_small);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_vendor_defined_message_buf_too_small);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_null);
	SUITE_ADD_TEST (suite, mctp_protocol_test_construct_invalid_buf_len);

	return suite;
}
