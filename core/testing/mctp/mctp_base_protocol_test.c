// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "crypto/checksum.h"
#include "mctp/mctp_base_protocol.h"


TEST_SUITE_LABEL ("mctp_base_protocol");


/*******************
 * Test cases
 *******************/

static void mctp_base_protocol_test_smbus_transport_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x0f,0x11,0x22,
		0x34,0x56,0x78,0x9a,
	};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct mctp_base_protocol_transport_header));

	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, header->cmd_code);
	CuAssertIntEquals (test, 0x11, header->byte_count);
	CuAssertIntEquals (test, 0x22, header->source_addr);
	CuAssertIntEquals (test, 0x3, header->rsvd);
	CuAssertIntEquals (test, 0x4, header->header_version);
	CuAssertIntEquals (test, 0x56, header->destination_eid);
	CuAssertIntEquals (test, 0x78, header->source_eid);
	CuAssertIntEquals (test, 1, header->som);
	CuAssertIntEquals (test, 0, header->eom);
	CuAssertIntEquals (test, 0x1, header->packet_seq);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, 0x2, header->msg_tag);

	raw_buffer[3] = 0xb4;
	CuAssertIntEquals (test, 0xb, header->rsvd);
	CuAssertIntEquals (test, 0x4, header->header_version);

	raw_buffer[3] = 0xbc;
	CuAssertIntEquals (test, 0xb, header->rsvd);
	CuAssertIntEquals (test, 0xc, header->header_version);

	raw_buffer[6] = 0x1a;
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 0, header->eom);
	CuAssertIntEquals (test, 0x1, header->packet_seq);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, 0x2, header->msg_tag);

	raw_buffer[6] = 0x5a;
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0x1, header->packet_seq);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, 0x2, header->msg_tag);

	raw_buffer[6] = 0x7a;
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0x3, header->packet_seq);
	CuAssertIntEquals (test, 1, header->tag_owner);
	CuAssertIntEquals (test, 0x2, header->msg_tag);

	raw_buffer[6] = 0x72;
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0x3, header->packet_seq);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0x2, header->msg_tag);

	raw_buffer[6] = 0x74;
	CuAssertIntEquals (test, 0, header->som);
	CuAssertIntEquals (test, 1, header->eom);
	CuAssertIntEquals (test, 0x3, header->packet_seq);
	CuAssertIntEquals (test, 0, header->tag_owner);
	CuAssertIntEquals (test, 0x4, header->msg_tag);
}

static void mctp_base_protocol_test_message_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e
	};
	struct mctp_base_protocol_message_header *header =
		(struct mctp_base_protocol_message_header*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct mctp_base_protocol_message_header));

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, 0, header->integrity_check);

	raw_buffer[0] = 0xfe;
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);

	raw_buffer[0] = 0x85;
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, header->msg_type);
	CuAssertIntEquals (test, 1, header->integrity_check);
}

static void mctp_base_protocol_test_vdm_pci_header_format (CuTest *test)
{
	uint8_t raw_buffer[] = {
		0x7e,
		0x11,0x22
	};
	struct mctp_base_protocol_vdm_pci_header *header =
		(struct mctp_base_protocol_vdm_pci_header*) raw_buffer;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer),
		sizeof (struct mctp_base_protocol_vdm_pci_header));

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_header.msg_type);
	CuAssertIntEquals (test, 0, header->msg_header.integrity_check);
	CuAssertIntEquals (test, 0x2211, header->pci_vendor_id);

	raw_buffer[0] = 0xfe;
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, header->msg_header.msg_type);
	CuAssertIntEquals (test, 1, header->msg_header.integrity_check);

	raw_buffer[0] = 0x85;
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, header->msg_header.msg_type);
	CuAssertIntEquals (test, 1, header->msg_header.integrity_check);
}

static void mctp_base_protocol_test_interpret_start_request_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 14;
	header->source_addr = 0x57;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x01;
	header->packet_seq = 2;

	buf[7] = 0x23;
	buf[8] = 0x12;
	buf[9] = 0x34;
	buf[10] = 0x56;
	buf[11] = 0x78;
	buf[12] = 0x9a;
	buf[13] = 0xbc;
	buf[14] = 0xde;
	buf[15] = 0xf0;
	buf[16] = checksum_crc8 (0xBA, buf, 16);

	status = mctp_base_protocol_interpret (buf, 17, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x2b, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x01, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[16], crc);
	CuAssertIntEquals (test, 0x23, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 9, payload_len);
}

static void mctp_base_protocol_test_interpret_start_request_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x03;
	header->packet_seq = 1;

	buf[7] = 0x48;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x22;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x03, msg_tag);
	CuAssertIntEquals (test, 1, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, 0x48, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_start_response_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x19;
	header->source_eid = 0xb4;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x28;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xEA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x75, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0xb4, src_eid);
	CuAssertIntEquals (test, 0x19, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, 0x28, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_start_response_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x07;
	header->packet_seq = 3;

	buf[7] = 0x53;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x45;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x07, msg_tag);
	CuAssertIntEquals (test, 3, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, 0x53, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_middle_packet_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0x10;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0x02;
	buf[9] = 0x03;
	buf[10] = 0x04;
	buf[11] = 0x05;
	buf[12] = 0x06;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, 0x10, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_middle_packet_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0x95;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x11;
	buf[8] = 0x12;
	buf[9] = 0x13;
	buf[10] = 0x24;
	buf[11] = 0x25;
	buf[12] = 0x26;
	buf[13] = 0x89;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, 0x95, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_end_packet_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0x93;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 13;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x04;
	header->packet_seq = 2;

	buf[7] = 0x11;
	buf[8] = 0x22;
	buf[9] = 0x33;
	buf[10] = 0x44;
	buf[11] = 0x55;
	buf[12] = 0x66;
	buf[13] = 0x77;
	buf[14] = 0x88;
	buf[15] = checksum_crc8 (0xBA, buf, 15);

	status = mctp_base_protocol_interpret (buf, 16, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, true, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x04, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[15], crc);
	CuAssertIntEquals (test, 0x93, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 8, payload_len);
}

static void mctp_base_protocol_test_interpret_end_packet_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0x67;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x99;
	buf[8] = 0x88;
	buf[9] = 0x77;
	buf[10] = 0x65;
	buf[11] = 0x43;
	buf[12] = 0x21;
	buf[13] = 0x83;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, true, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, 0x67, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_max_byte_count_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[253 + MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD] = {0};
	const size_t length = sizeof (buf);
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 253;
	header->source_addr = 0x57;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x01;
	header->packet_seq = 2;

	buf[7] = 0x23;
	buf[8] = 0x12;
	buf[9] = 0x34;
	buf[10] = 0x56;
	buf[11] = 0x78;
	buf[12] = 0x9a;
	buf[13] = 0xbc;
	buf[14] = 0xde;
	buf[15] = 0xf0;
	buf[length - 1] = checksum_crc8 (0xBA, buf, length - 1);

	status = mctp_base_protocol_interpret (buf, length, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x2b, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x01, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[length - 1], crc);
	CuAssertIntEquals (test, 0x23, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, length - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD, payload_len);
}

static void mctp_base_protocol_test_interpret_max_byte_count_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[255 + MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD_NO_PEC] = {0};
	const size_t length = sizeof (buf);
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 255;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x03;
	header->packet_seq = 1;

	buf[7] = 0x48;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;

	status = mctp_base_protocol_interpret (buf, length, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x03, msg_tag);
	CuAssertIntEquals (test, 1, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, 0x48, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test,
		length - (MCTP_BASE_PROTOCOL_PACKET_OVERHEAD - MCTP_BASE_PROTOCOL_PEC_SIZE), payload_len);
}

static void mctp_base_protocol_test_interpret_message_integrity_check (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 14;
	header->source_addr = 0x57;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x01;
	header->packet_seq = 2;

	buf[7] = 0x94;
	buf[8] = 0x12;
	buf[9] = 0x34;
	buf[10] = 0x56;
	buf[11] = 0x78;
	buf[12] = 0x9a;
	buf[13] = 0xbc;
	buf[14] = 0xde;
	buf[15] = 0xf0;
	buf[16] = checksum_crc8 (0xBA, buf, 16);

	status = mctp_base_protocol_interpret (buf, 17, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x2b, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x01, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[16], crc);
	CuAssertIntEquals (test, 0x14, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 9, payload_len);
}

static void mctp_base_protocol_test_interpret_control_request_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x24;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_control_request_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0x6D;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = 0x34;
	header->source_eid = 0x45;
	header->som = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->eom = 0;
	header->msg_tag = 0x04;
	header->packet_seq = 1;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[8] = 0x11;
	buf[9] = 0x22;
	buf[10] = 0x33;
	buf[11] = 0x44;
	buf[12] = 0x55;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x36, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x45, src_eid);
	CuAssertIntEquals (test, 0x34, dest_eid);
	CuAssertIntEquals (test, 0x04, msg_tag);
	CuAssertIntEquals (test, 1, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_control_response_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x12;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_control_response_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xD2, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x69, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_control_not_som (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_request_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_request_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x23;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_request_multi_packets (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	memset (&buf[8], 0xAA, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] =
		checksum_crc8 (0xBA, buf, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);

	status = mctp_base_protocol_interpret (buf, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN, 0x5D,
		&source_addr, &som, &eom, &src_eid, &dest_eid, &payload, &payload_len, &msg_tag,
		&packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&buf[8], &payload[1],
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, payload_len);

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 3;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, true, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 3, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_request_multi_packets_last_packet_with_1byte_payload (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 1;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	memset (&buf[8], 0xAA, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] =
		checksum_crc8 (0xBA, buf, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);

	status = mctp_base_protocol_interpret (buf, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN, 0x5D,
		&source_addr, &som, &eom, &src_eid, &dest_eid, &payload, &payload_len, &msg_tag,
		&packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&buf[8], &payload[1],
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 1, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, payload_len);

	memset (buf, 0, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN);
	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);

	memset (buf, 0, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN);
	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_PACKET_OVERHEAD - MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD + 2;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 3;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = checksum_crc8 (0xBA, buf, 9);

	status = mctp_base_protocol_interpret (buf, 10, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, true, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 3, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[9], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 0xAA, payload[1]);
	CuAssertIntEquals (test, 2, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_request_multi_packets_last_packet_with_2bytes_payload (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	memset (&buf[8], 0xAA, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1] =
		checksum_crc8 (0xBA, buf, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1);

	status = mctp_base_protocol_interpret (buf, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN, 0x5D,
		&source_addr, &som, &eom, &src_eid, &dest_eid, &payload, &payload_len, &msg_tag,
		&packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (&buf[8], &payload[1],
		MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT, payload_len);

	memset (buf, 0, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN);
	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 3;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 3, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);

	memset (buf, 0, MCTP_BASE_PROTOCOL_MAX_PACKET_LEN);
	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_PACKET_OVERHEAD - MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD + 3;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 0;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = checksum_crc8 (0xBA, buf, 10);

	status = mctp_base_protocol_interpret (buf, 11, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, true, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 0, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[10], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 3, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_response_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_response_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x43;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_vendor_defined_not_som (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_spdm_request_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_spdm_request_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x22;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_spdm_response_with_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_spdm_response_no_crc (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_RESPONSE;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = 0x45;

	status = mctp_base_protocol_interpret (buf, 13, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_RESPONSE, tag_owner);
	CuAssertIntEquals (test, 0, crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_spdm_not_som (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = 0x01;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
	CuAssertIntEquals (test, buf[13], crc);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, msg_type);
	CuAssertPtrEquals (test, &buf[7], (void*) payload);
	CuAssertIntEquals (test, 6, payload_len);
}

static void mctp_base_protocol_test_interpret_null (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t crc;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	status = mctp_base_protocol_interpret (NULL, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, NULL, &som, &eom, &src_eid, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, NULL, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, NULL, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, NULL, &dest_eid,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid, NULL,
		&payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, NULL, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, NULL, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, NULL, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, NULL, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, NULL, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, NULL, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, NULL);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);
}

static void mctp_base_protocol_test_interpret_buffer_length_less_than_header (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf,
		sizeof (struct mctp_base_protocol_transport_header) - 1, 0x5D, &source_addr, &som, &eom,
		&src_eid, &dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type,
		&tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PKT_TOO_SHORT, status);
}

static void mctp_base_protocol_test_interpret_wrong_smbus_command_code (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t crc = 0;
	uint8_t msg_type;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = 0x94;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 1;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_PKT, status);

	/* Assert that the MCTP header was parsed. */
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, true, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
}

static void mctp_base_protocol_test_interpret_non_zero_reserved_field (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t crc = 0;
	uint8_t msg_type;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0x57;
	header->rsvd = 3;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_PKT, status);

	/* Assert that the MCTP header was parsed. */
	CuAssertIntEquals (test, 0x2b, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
}

static void mctp_base_protocol_test_interpret_dest_eid_matches_src_eid (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr = 0;
	bool som = false;
	bool eom = false;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq = 0;
	uint8_t crc = 0;
	uint8_t msg_type = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->som = 0;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, 14, 0x5D, &source_addr, &som, &eom, &src_eid,
		&dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_PKT, status);

	/* Assert that the MCTP header was parsed. */
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, false, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0B, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
}

static void mctp_base_protocol_test_interpret_invalid_header_version (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 2;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x03;
	header->packet_seq = 1;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, sizeof (buf), 0x5D, &source_addr, &som, &eom,
		&src_eid, &dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type,
		&tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_PKT, status);

	/* Assert that the MCTP header was parsed. */
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x03, msg_tag);
	CuAssertIntEquals (test, 1, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
}

static void mctp_base_protocol_test_interpret_byte_count_only_header (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = sizeof (struct mctp_base_protocol_transport_header) -
		MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD_NO_PEC;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->tag_owner = MCTP_BASE_PROTOCOL_TO_REQUEST;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, sizeof (buf), 0x5D, &source_addr, &som, &eom,
		&src_eid, &dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type,
		&tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PKT_TOO_SHORT, status);

	/* Assert that the MCTP header was parsed. */
	CuAssertIntEquals (test, 0x55, source_addr);
	CuAssertIntEquals (test, true, som);
	CuAssertIntEquals (test, false, eom);
	CuAssertIntEquals (test, 0x0A, src_eid);
	CuAssertIntEquals (test, 0x0B, dest_eid);
	CuAssertIntEquals (test, 0x05, msg_tag);
	CuAssertIntEquals (test, 2, packet_seq);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_TO_REQUEST, tag_owner);
}

static void mctp_base_protocol_test_interpret_header_byte_count_more_than_buffer_length (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = MCTP_BASE_PROTOCOL_MAX_PACKET_LEN - 1;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[13] = checksum_crc8 (0xBA, buf, 13);

	status = mctp_base_protocol_interpret (buf, sizeof (buf), 0x5D, &source_addr, &som, &eom,
		&src_eid, &dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type,
		&tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PKT_LENGTH_MISMATCH, status);
}

static void mctp_base_protocol_test_interpret_failed_crc_check (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN] = {0};
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) buf;
	uint8_t source_addr;
	bool som;
	bool eom;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t msg_type;
	uint8_t crc = 0;
	uint8_t tag_owner;
	const uint8_t *payload;
	size_t payload_len;

	TEST_START;


	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = 11;
	header->source_addr = 0xAA;
	header->rsvd = 0;
	header->header_version = 1;
	header->destination_eid = MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID;
	header->source_eid = MCTP_BASE_PROTOCOL_BMC_EID;
	header->som = 1;
	header->eom = 0;
	header->msg_tag = 0x05;
	header->packet_seq = 2;

	buf[7] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[8] = 0xAA;
	buf[9] = 0xBB;
	buf[10] = 0xCC;
	buf[11] = 0xDD;
	buf[12] = 0xEE;
	buf[13] = checksum_crc8 (0x55, buf, 13);

	status = mctp_base_protocol_interpret (buf, sizeof (buf), 0x5D, &source_addr, &som, &eom,
		&src_eid, &dest_eid, &payload, &payload_len, &msg_tag, &packet_seq, &crc, &msg_type,
		&tag_owner);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BAD_CHECKSUM, status);
}

static void mctp_base_protocol_test_construct_control_message (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_control_message_overlapping_buffer (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	memcpy (&out_buf[8], buf, sizeof (buf));

	status = mctp_base_protocol_construct (&out_buf[8], sizeof (buf), out_buf, sizeof (out_buf),
		0x55, 0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_control_message_overlapping_buffer_at_beginning (
	CuTest *test)
{
	int status;
	uint8_t buf[8];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;
	buf[6] = 0xFF;
	buf[7] = 0x11;

	memcpy (out_buf, buf, sizeof (buf));

	status = mctp_base_protocol_construct (out_buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55,
		0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_control_message_not_som (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = 0x01;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, false, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x12, out_buf[6]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_vendor_defined_message (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_vendor_defined_message_overlapping_buffer (
	CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	memcpy (&out_buf[8], buf, sizeof (buf));

	status = mctp_base_protocol_construct (&out_buf[8], sizeof (buf), out_buf, sizeof (out_buf),
		0x55, 0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_vendor_defined_message_overlapping_buffer_at_beginning (
	CuTest *test)
{
	int status;
	uint8_t buf[8];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;
	buf[6] = 0xFF;
	buf[7] = 0x11;

	memcpy (out_buf, buf, sizeof (buf));

	status = mctp_base_protocol_construct (out_buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55,
		0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_vendor_defined_message_not_som (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = 0x01;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, false, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x12, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_spdm_response (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_spdm_response_overlapping_buffer (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	memcpy (&out_buf[8], buf, sizeof (buf));

	status = mctp_base_protocol_construct (&out_buf[8], sizeof (buf), out_buf, sizeof (out_buf), 0x55,
		0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_spdm_response_overlapping_buffer_at_beginning (
	CuTest *test)
{
	int status;
	uint8_t buf[8];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;
	buf[6] = 0xFF;
	buf[7] = 0x11;

	memcpy (out_buf, buf, sizeof (buf));

	status = mctp_base_protocol_construct (out_buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x92, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_control_request (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_REQUEST, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x9A, out_buf[6]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_vendor_defined_request (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_REQUEST, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x9A, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_spdm_request (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_REQUEST, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf), status);
	CuAssertIntEquals (test, SMBUS_CMD_CODE_MCTP, out_buf[0]);
	CuAssertIntEquals (test, sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 2,
		out_buf[1]);
	CuAssertIntEquals (test, 0xAB, out_buf[2]);
	CuAssertIntEquals (test, 0x01, out_buf[3]);
	CuAssertIntEquals (test, 0x0A, out_buf[4]);
	CuAssertIntEquals (test, 0x0B, out_buf[5]);
	CuAssertIntEquals (test, 0x9A, out_buf[6]);
	CuAssertIntEquals (test, checksum_crc8 (0xBA, out_buf, status - 1), out_buf[status - 1]);

	status = testing_validate_array (buf, &out_buf[7], sizeof (buf));
	CuAssertIntEquals (test, 0, status);
}

static void mctp_base_protocol_test_construct_control_message_buf_too_small (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[sizeof (struct mctp_base_protocol_transport_header) + sizeof (buf) - 1];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);
}

static void mctp_base_protocol_test_construct_vendor_defined_message_buf_too_small (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf) - 1];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);
}

static void mctp_base_protocol_test_construct_spdm_response_buf_too_small (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + sizeof (buf) - 1];

	TEST_START;

	buf[0] = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	buf[1] = 0xAA;
	buf[2] = 0xBB;
	buf[3] = 0xCC;
	buf[4] = 0xDD;
	buf[5] = 0xEE;

	status = mctp_base_protocol_construct (buf, sizeof (buf), out_buf, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BUF_TOO_SMALL, status);
}

static void mctp_base_protocol_test_construct_null (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

 	TEST_START;

	status = mctp_base_protocol_construct (NULL, sizeof (buf), out_buf, sizeof (out_buf), 0x55,
		0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);

	status = mctp_base_protocol_construct (buf, sizeof (buf), NULL, sizeof (out_buf), 0x55, 0x0A,
		0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_INVALID_ARGUMENT, status);
}

static void mctp_base_protocol_test_construct_invalid_buf_len (CuTest *test)
{
	int status;
	uint8_t buf[6];
	uint8_t out_buf[MCTP_BASE_PROTOCOL_MAX_PACKET_LEN];

 	TEST_START;

	status = mctp_base_protocol_construct (buf, 0, out_buf, sizeof (out_buf), 0xAA, 0x0A, 0x0B,
		true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BAD_BUFFER_LENGTH, status);

	status = mctp_base_protocol_construct (buf, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT + 1, out_buf,
		sizeof (out_buf), 0xAA, 0x0A, 0x0B, true, false, 1, 2, MCTP_BASE_PROTOCOL_TO_RESPONSE, 0x5D);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_BAD_BUFFER_LENGTH, status);
}


TEST_SUITE_START (mctp_base_protocol);

TEST (mctp_base_protocol_test_smbus_transport_header_format);
TEST (mctp_base_protocol_test_message_header_format);
TEST (mctp_base_protocol_test_vdm_pci_header_format);
TEST (mctp_base_protocol_test_interpret_start_request_with_crc);
TEST (mctp_base_protocol_test_interpret_start_request_no_crc);
TEST (mctp_base_protocol_test_interpret_start_response_with_crc);
TEST (mctp_base_protocol_test_interpret_start_response_no_crc);
TEST (mctp_base_protocol_test_interpret_middle_packet_with_crc);
TEST (mctp_base_protocol_test_interpret_middle_packet_no_crc);
TEST (mctp_base_protocol_test_interpret_end_packet_with_crc);
TEST (mctp_base_protocol_test_interpret_end_packet_no_crc);
TEST (mctp_base_protocol_test_interpret_max_byte_count_with_crc);
TEST (mctp_base_protocol_test_interpret_max_byte_count_no_crc);
TEST (mctp_base_protocol_test_interpret_message_integrity_check);
TEST (mctp_base_protocol_test_interpret_control_request_no_crc);
TEST (mctp_base_protocol_test_interpret_control_request_with_crc);
TEST (mctp_base_protocol_test_interpret_control_response_no_crc);
TEST (mctp_base_protocol_test_interpret_control_response_with_crc);
TEST (mctp_base_protocol_test_interpret_control_not_som);
TEST (mctp_base_protocol_test_interpret_vendor_defined_request_with_crc);
TEST (mctp_base_protocol_test_interpret_vendor_defined_request_no_crc);
TEST (mctp_base_protocol_test_interpret_vendor_defined_request_multi_packets);
TEST (mctp_base_protocol_test_interpret_vendor_defined_request_multi_packets_last_packet_with_1byte_payload);
TEST (mctp_base_protocol_test_interpret_vendor_defined_request_multi_packets_last_packet_with_2bytes_payload);
TEST (mctp_base_protocol_test_interpret_vendor_defined_response_with_crc);
TEST (mctp_base_protocol_test_interpret_vendor_defined_response_no_crc);
TEST (mctp_base_protocol_test_interpret_vendor_defined_not_som);
TEST (mctp_base_protocol_test_interpret_spdm_request_with_crc);
TEST (mctp_base_protocol_test_interpret_spdm_request_no_crc);
TEST (mctp_base_protocol_test_interpret_spdm_response_with_crc);
TEST (mctp_base_protocol_test_interpret_spdm_response_no_crc);
TEST (mctp_base_protocol_test_interpret_spdm_not_som);
TEST (mctp_base_protocol_test_interpret_null);
TEST (mctp_base_protocol_test_interpret_wrong_smbus_command_code);
TEST (mctp_base_protocol_test_interpret_non_zero_reserved_field);
TEST (mctp_base_protocol_test_interpret_invalid_header_version);
TEST (mctp_base_protocol_test_interpret_dest_eid_matches_src_eid);
TEST (mctp_base_protocol_test_interpret_buffer_length_less_than_header);
TEST (mctp_base_protocol_test_interpret_byte_count_only_header);
TEST (mctp_base_protocol_test_interpret_header_byte_count_more_than_buffer_length);
TEST (mctp_base_protocol_test_interpret_failed_crc_check);
TEST (mctp_base_protocol_test_construct_control_message);
TEST (mctp_base_protocol_test_construct_control_message_overlapping_buffer);
TEST (mctp_base_protocol_test_construct_control_message_overlapping_buffer_at_beginning);
TEST (mctp_base_protocol_test_construct_control_message_not_som);
TEST (mctp_base_protocol_test_construct_vendor_defined_message);
TEST (mctp_base_protocol_test_construct_vendor_defined_message_overlapping_buffer);
TEST (mctp_base_protocol_test_construct_vendor_defined_message_overlapping_buffer_at_beginning);
TEST (mctp_base_protocol_test_construct_vendor_defined_message_not_som);
TEST (mctp_base_protocol_test_construct_spdm_response);
TEST (mctp_base_protocol_test_construct_spdm_response_overlapping_buffer);
TEST (mctp_base_protocol_test_construct_spdm_response_overlapping_buffer_at_beginning);
TEST (mctp_base_protocol_test_construct_control_request);
TEST (mctp_base_protocol_test_construct_vendor_defined_request);
TEST (mctp_base_protocol_test_construct_spdm_request);
TEST (mctp_base_protocol_test_construct_control_message_buf_too_small);
TEST (mctp_base_protocol_test_construct_vendor_defined_message_buf_too_small);
TEST (mctp_base_protocol_test_construct_spdm_response_buf_too_small);
TEST (mctp_base_protocol_test_construct_null);
TEST (mctp_base_protocol_test_construct_invalid_buf_len);

TEST_SUITE_END;
