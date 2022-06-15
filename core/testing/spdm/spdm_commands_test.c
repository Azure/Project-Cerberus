// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "cmd_interface/device_manager.h"
#include "logging/debug_log.h"
#include "riot/riot_key_manager.h"
#include "spdm/cmd_interface_spdm.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_logging.h"
#include "spdm/spdm_protocol.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/mock/attestation/attestation_responder_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/logging/debug_log_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("spdm_commands");


/*******************
 * Test cases
 *******************/

static void spdm_test_error_response_format (CuTest *test)
{
	uint8_t raw_buffer_rsp[] = {
		0x05,0x12,0x7F,
		0xAA,0xBB,
		0x11,0x22
	};
	struct spdm_error_response *rsp = (struct spdm_error_response*) raw_buffer_rsp;
	uint16_t *optional_data = (uint16_t*) spdm_get_spdm_error_rsp_optional_data (rsp);

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_rsp), sizeof (struct spdm_error_response) + 2);

	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, rsp->header.msg_type);
	CuAssertIntEquals (test, 0x02, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);

	CuAssertIntEquals (test, 0xAA, rsp->error_code);
	CuAssertIntEquals (test, 0xBB, rsp->error_data);

	CuAssertIntEquals (test, 0x2211, *optional_data);
}

static void spdm_test_get_version_request_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x05,0x11,0x84,
		0x00,0x00
	};
	struct spdm_get_version_request *req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct spdm_get_version_request));

	req = (struct spdm_get_version_request*) raw_buffer_req;
	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x05, req->header.msg_type);
	CuAssertIntEquals (test, 0x01, req->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, req->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_VERSION, req->header.req_rsp_code);

	CuAssertIntEquals (test, 0, req->reserved);
	CuAssertIntEquals (test, 0, req->reserved2);
}

static void spdm_test_get_version_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x04,
		0x00,0x00,0x00,0x01,0x12,0x34
	};
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) raw_buffer_resp;
	struct spdm_version_num_entry *version_num = spdm_get_version_resp_version_table(resp);

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct spdm_get_version_response) + sizeof (struct spdm_version_num_entry));

	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, resp->header.msg_type);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_VERSION, resp->header.req_rsp_code);

	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 0, resp->reserved2);
	CuAssertIntEquals (test, 0, resp->reserved3);
	CuAssertIntEquals (test, 1, resp->version_num_entry_count);

	CuAssertIntEquals (test, 1, version_num->update_version);
	CuAssertIntEquals (test, 2, version_num->alpha);
	CuAssertIntEquals (test, 3, version_num->major_version);
	CuAssertIntEquals (test, 4, version_num->minor_version);
}

static void spdm_test_get_capabilities_format (CuTest *test)
{
	uint8_t raw_buffer_msg[] = {
		0x05,0x11,0xe1,
		0x00,0x00,0x00,0x01,0x00,0x00,
		0xa5,0x55,0x01,0x00,
		0x11,0x22,0x33,0x44,
		0xaa,0xbb,0xcc,0xdd
	};
	struct spdm_get_capabilities *msg = (struct spdm_get_capabilities*) raw_buffer_msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_msg), sizeof (struct spdm_get_capabilities));

	CuAssertIntEquals (test, 0, msg->base_capabilities.header.integrity_check);
	CuAssertIntEquals (test, 0x05, msg->base_capabilities.header.msg_type);
	CuAssertIntEquals (test, 0x01, msg->base_capabilities.header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, msg->base_capabilities.header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_CAPABILITIES,
		msg->base_capabilities.header.req_rsp_code);

	CuAssertIntEquals (test, 0, msg->base_capabilities.reserved);
	CuAssertIntEquals (test, 0, msg->base_capabilities.reserved2);
	CuAssertIntEquals (test, 0, msg->base_capabilities.reserved3);
	CuAssertIntEquals (test, 1, msg->base_capabilities.ct_exponent);
	CuAssertIntEquals (test, 0, msg->base_capabilities.reserved4);

	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.cache_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.cert_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.chal_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.meas_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.encrypt_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.mac_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.key_ex_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.psk_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.encap_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.hbeat_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.key_upd_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 1, msg->base_capabilities.flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.reserved);
	CuAssertIntEquals (test, 0, msg->base_capabilities.flags.reserved2);
	CuAssertIntEquals (test, 0x44332211, msg->data_transfer_size);
	CuAssertIntEquals (test, 0xddccbbaa, msg->max_spdm_msg_size);
}

static void spdm_test_get_capabilities_1_1_format (CuTest *test)
{
	uint8_t raw_buffer_msg[] = {
		0x05,0x11,0xe1,
		0x00,0x00,0x00,0x01,0x00,0x00,
		0xa5,0x55,0x01,0x00
	};
	struct spdm_get_capabilities_1_1 *msg = (struct spdm_get_capabilities_1_1*) raw_buffer_msg;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_msg), sizeof (struct spdm_get_capabilities_1_1));

	CuAssertIntEquals (test, 0, msg->header.integrity_check);
	CuAssertIntEquals (test, 0x05, msg->header.msg_type);
	CuAssertIntEquals (test, 0x01, msg->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, msg->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_CAPABILITIES,	msg->header.req_rsp_code);

	CuAssertIntEquals (test, 0, msg->reserved);
	CuAssertIntEquals (test, 0, msg->reserved2);
	CuAssertIntEquals (test, 0, msg->reserved3);
	CuAssertIntEquals (test, 1, msg->ct_exponent);
	CuAssertIntEquals (test, 0, msg->reserved4);

	CuAssertIntEquals (test, 1, msg->flags.cache_cap);
	CuAssertIntEquals (test, 0, msg->flags.cert_cap);
	CuAssertIntEquals (test, 1, msg->flags.chal_cap);
	CuAssertIntEquals (test, 0, msg->flags.meas_cap);
	CuAssertIntEquals (test, 1, msg->flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, msg->flags.encrypt_cap);
	CuAssertIntEquals (test, 1, msg->flags.mac_cap);
	CuAssertIntEquals (test, 1, msg->flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, msg->flags.key_ex_cap);
	CuAssertIntEquals (test, 1, msg->flags.psk_cap);
	CuAssertIntEquals (test, 1, msg->flags.encap_cap);
	CuAssertIntEquals (test, 0, msg->flags.hbeat_cap);
	CuAssertIntEquals (test, 1, msg->flags.key_upd_cap);
	CuAssertIntEquals (test, 0, msg->flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 1, msg->flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, msg->flags.reserved);
	CuAssertIntEquals (test, 0, msg->flags.reserved2);
}

static void spdm_test_negotiate_algorithms_request_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x05,0x11,0xe3,
		0x01,0x00,0xaa,0x00,0x03,0x00,0xaa,0xbb,0xcc,0xdd,0xa1,0xb2,0xc3,0xd4,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x00,0x00,
		0xab,0x00,0xcd,0xef,
		0x11,0x00,0x33,0xdd,
		0xb5,0x11,0x12,0x34,
		0x22,0x00,0x44,0xee,
	};

	struct spdm_negotiate_algorithms_request *req =
		(struct spdm_negotiate_algorithms_request*) raw_buffer_req;
	struct spdm_extended_algorithm *asym_alg = spdm_negotiate_algorithms_req_ext_asym_table(req);
	struct spdm_extended_algorithm *hash_alg = spdm_negotiate_algorithms_req_ext_hash_table(req);
	struct spdm_algorithm_request *algstruct_table =
		spdm_negotiate_algorithms_req_algstruct_table(req);
	struct spdm_extended_algorithm *ext_alg =
		(struct spdm_extended_algorithm*) (algstruct_table + 1);
	uint8_t reserved_buf[12] = {0};
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req),
		sizeof (struct spdm_negotiate_algorithms_request) +
		sizeof (struct spdm_extended_algorithm) * 3 + sizeof (struct spdm_algorithm_request));

	CuAssertIntEquals (test, 0, req->header.integrity_check);
	CuAssertIntEquals (test, 0x05, req->header.msg_type);
	CuAssertIntEquals (test, 0x01, req->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, req->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, req->header.req_rsp_code);

	CuAssertIntEquals (test, 1, req->num_alg_structure_tables);
	CuAssertIntEquals (test, 0, req->reserved);
	CuAssertIntEquals (test, 0xaa, req->length);
	CuAssertIntEquals (test, 0x03, req->measurement_specification);
	CuAssertIntEquals (test, 0, req->reserved2);
	CuAssertIntEquals (test, 0xddccbbaa, req->base_asym_algo);
	CuAssertIntEquals (test, 0xd4c3b2a1, req->base_hash_algo);
	CuAssertIntEquals (test, 1, req->ext_asym_count);
	CuAssertIntEquals (test, 1, req->ext_hash_count);
	CuAssertIntEquals (test, 0, req->reserved4);

	status = testing_validate_array (reserved_buf, req->reserved3, sizeof (reserved_buf));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0xab, asym_alg->registry_id);
	CuAssertIntEquals (test, 0, asym_alg->reserved);
	CuAssertIntEquals (test, 0xefcd, asym_alg->algorithm_id);

	CuAssertIntEquals (test, 0x11, hash_alg->registry_id);
	CuAssertIntEquals (test, 0, hash_alg->reserved);
	CuAssertIntEquals (test, 0xdd33, hash_alg->algorithm_id);

	CuAssertIntEquals (test, 0xb5, algstruct_table->alg_type);
	CuAssertIntEquals (test, 1, algstruct_table->fixed_alg_count);
	CuAssertIntEquals (test, 1, algstruct_table->ext_alg_count);
	CuAssertIntEquals (test, 0x3412, algstruct_table->alg_supported);

	CuAssertIntEquals (test, 0x22, ext_alg->registry_id);
	CuAssertIntEquals (test, 0, ext_alg->reserved);
	CuAssertIntEquals (test, 0xee44, ext_alg->algorithm_id);
}

static void spdm_test_negotiate_algorithms_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x63,
		0x01,0x00,0xaa,0x00,0x03,0x00,0x11,0x22,0x33,0x44,0xaa,0xbb,0xcc,0xdd,0xa1,0xb2,0xc3,0xd4,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x01,0x00,0x00,
		0xab,0x00,0xcd,0xef,
		0x11,0x00,0x33,0xdd,
		0xb5,0x11,0x12,0x34,
		0x22,0x00,0x44,0xee,
	};

	struct spdm_negotiate_algorithms_response *resp =
		(struct spdm_negotiate_algorithms_response*) raw_buffer_resp;
	struct spdm_extended_algorithm *asym_alg = spdm_negotiate_algorithms_rsp_ext_asym_table(resp);
	struct spdm_extended_algorithm *hash_alg = spdm_negotiate_algorithms_rsp_ext_hash_table(resp);
	struct spdm_algorithm_request *algstruct_table =
		spdm_negotiate_algorithms_rsp_algstruct_table(resp);
	struct spdm_extended_algorithm *ext_alg =
		(struct spdm_extended_algorithm*) (algstruct_table + 1);
	uint8_t reserved_buf[12] = {0};
	int status;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		sizeof (struct spdm_negotiate_algorithms_response) +
		sizeof (struct spdm_extended_algorithm) * 3 + sizeof (struct spdm_algorithm_request));

	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, resp->header.msg_type);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_NEGOTIATE_ALGORITHMS, resp->header.req_rsp_code);

	CuAssertIntEquals (test, 1, resp->num_alg_structure_tables);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 0xaa, resp->length);
	CuAssertIntEquals (test, 0x03, resp->measurement_specification);
	CuAssertIntEquals (test, 0, resp->reserved2);
	CuAssertIntEquals (test, 0x44332211, resp->measurement_hash_algo);
	CuAssertIntEquals (test, 0xddccbbaa, resp->base_asym_sel);
	CuAssertIntEquals (test, 0xd4c3b2a1, resp->base_hash_sel);
	CuAssertIntEquals (test, 1, resp->ext_asym_sel_count);
	CuAssertIntEquals (test, 1, resp->ext_hash_sel_count);
	CuAssertIntEquals (test, 0, resp->reserved4);

	status = testing_validate_array (reserved_buf, resp->reserved3, sizeof (reserved_buf));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0xab, asym_alg->registry_id);
	CuAssertIntEquals (test, 0, asym_alg->reserved);
	CuAssertIntEquals (test, 0xefcd, asym_alg->algorithm_id);

	CuAssertIntEquals (test, 0x11, hash_alg->registry_id);
	CuAssertIntEquals (test, 0, hash_alg->reserved);
	CuAssertIntEquals (test, 0xdd33, hash_alg->algorithm_id);

	CuAssertIntEquals (test, 0xb5, algstruct_table->alg_type);
	CuAssertIntEquals (test, 1, algstruct_table->fixed_alg_count);
	CuAssertIntEquals (test, 1, algstruct_table->ext_alg_count);
	CuAssertIntEquals (test, 0x3412, algstruct_table->alg_supported);

	CuAssertIntEquals (test, 0x22, ext_alg->registry_id);
	CuAssertIntEquals (test, 0, ext_alg->reserved);
	CuAssertIntEquals (test, 0xee44, ext_alg->algorithm_id);
}

static void spdm_test_get_digests_request_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x05,0x11,0x81,
		0x00,0x00
	};
	struct spdm_get_digests_request *msg = (struct spdm_get_digests_request*) raw_buffer_req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct spdm_get_digests_request));

	CuAssertIntEquals (test, 0, msg->header.integrity_check);
	CuAssertIntEquals (test, 0x05, msg->header.msg_type);
	CuAssertIntEquals (test, 0x01, msg->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, msg->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_DIGESTS, msg->header.req_rsp_code);

	CuAssertIntEquals (test, 0, msg->reserved);
	CuAssertIntEquals (test, 0, msg->reserved2);
}

static void spdm_test_get_digests_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x01,
		0x00,0x01,0xaa,0xbb
	};
	struct spdm_get_digests_response *resp = (struct spdm_get_digests_response*) raw_buffer_resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_resp), spdm_get_digests_resp_length (resp, 2));

	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, resp->header.msg_type);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_DIGESTS, resp->header.req_rsp_code);

	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 1, resp->slot_mask);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], spdm_get_digests_resp_digests(resp));
}

static void spdm_test_get_certificate_request_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x05,0x11,0x82,
		0x01,0x00,0xaa,0x00,0xbb,0x00
	};
	struct spdm_get_certificate_request *msg =
		(struct spdm_get_certificate_request*) raw_buffer_req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct spdm_get_certificate_request));

	CuAssertIntEquals (test, 0, msg->header.integrity_check);
	CuAssertIntEquals (test, 0x05, msg->header.msg_type);
	CuAssertIntEquals (test, 0x01, msg->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, msg->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_CERTIFICATE, msg->header.req_rsp_code);

	CuAssertIntEquals (test, 1, msg->slot_num);
	CuAssertIntEquals (test, 0, msg->reserved);
	CuAssertIntEquals (test, 0xaa, msg->offset);
	CuAssertIntEquals (test, 0xbb, msg->length);
}

static void spdm_test_get_certificate_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x02,
		0x01,0x00,0x03,0x00,0x10,0x00,0xaa,0xbb,0xcc
	};
	struct spdm_get_certificate_response *resp =
		(struct spdm_get_certificate_response*) raw_buffer_resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_resp), spdm_get_certificate_resp_length (resp));

	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, resp->header.msg_type);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_CERTIFICATE, resp->header.req_rsp_code);

	CuAssertIntEquals (test, 1, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 3, resp->portion_len);
	CuAssertIntEquals (test, 16, resp->remainder_len);

	CuAssertPtrEquals (test, &raw_buffer_resp[9], spdm_get_certificate_resp_cert_chain (resp));
}

static void spdm_test_challenge_request_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x05,0x11,0x83,
		0x01,0x02,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04

	};
	struct spdm_challenge_request *rq = (struct spdm_challenge_request*) raw_buffer_req;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), sizeof (struct spdm_challenge_request));

	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0x05, rq->header.msg_type);
	CuAssertIntEquals (test, 0x01, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_CHALLENGE, rq->header.req_rsp_code);

	CuAssertIntEquals (test, 1, rq->slot_num);
	CuAssertIntEquals (test, 2, rq->req_measurement_summary_hash_type);

	CuAssertPtrEquals (test, &raw_buffer_req[5], rq->nonce);
}

static void spdm_test_challenge_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x03,
		0x81,0x02,
		0xaa,0xbb,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0xcc,0xdd,
		0x03,0x00,
		0xab,0xcd,0xef,
		0x11,0x22,0x33,0x44,0x55

	};
	struct spdm_challenge_response *resp = (struct spdm_challenge_response*) raw_buffer_resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_resp),
		spdm_get_challenge_resp_length (resp, 2, 2) + 5);

	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, resp->header.msg_type);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_CHALLENGE, resp->header.req_rsp_code);

	CuAssertIntEquals (test, 1, resp->slot_num);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 1, resp->basic_mutual_auth_req);
	CuAssertIntEquals (test, 2, resp->slot_mask);

	CuAssertPtrEquals (test, &raw_buffer_resp[5], spdm_get_challenge_resp_cert_chain_hash (resp));
	CuAssertPtrEquals (test, &raw_buffer_resp[7], spdm_get_challenge_resp_nonce(resp, 2));
	CuAssertPtrEquals (test, &raw_buffer_resp[39],
		spdm_get_challenge_resp_measurement_summary_hash (resp, 2));
	CuAssertIntEquals (test, 0x03, spdm_get_challenge_resp_opaque_len(resp, 2, 2));
	CuAssertPtrEquals (test, &raw_buffer_resp[43], spdm_get_challenge_resp_opaque_data(resp, 2, 2));
	CuAssertPtrEquals (test, &raw_buffer_resp[46], spdm_get_challenge_resp_signature(resp, 2, 2));
	CuAssertIntEquals (test, 5, spdm_get_challenge_resp_signature_length (resp, 2,
		sizeof (raw_buffer_resp), 2));
}

static void spdm_test_get_measurements_request_format (CuTest *test)
{
	uint8_t raw_buffer_req[] = {
		0x05,0x11,0xe0,
		0x01,0x04,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x03

	};
	struct spdm_get_measurements_request *rq =
		(struct spdm_get_measurements_request*) raw_buffer_req;
	uint8_t *slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_req), spdm_get_measurements_rq_length (rq));

	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0x05, rq->header.msg_type);
	CuAssertIntEquals (test, 0x01, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_MEASUREMENTS, rq->header.req_rsp_code);

	CuAssertIntEquals (test, 1, rq->sig_required);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 4, rq->measurement_operation);
	CuAssertIntEquals (test, 3, *slot_id);

	CuAssertPtrEquals (test, &raw_buffer_req[5], spdm_get_measurements_rq_nonce (rq));
}

static void spdm_test_get_measurements_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x60,
		0x01,0x02,0x03,0x02,0x00,0x00,
		0xaa,0xbb,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x03,0x00,
		0xcc,0xdd,0xee,
		0x11,0x22,0x33,0x44,0x55

	};
	struct spdm_get_measurements_response *resp =
		(struct spdm_get_measurements_response*) raw_buffer_resp;

	TEST_START;

	CuAssertIntEquals (test, sizeof (raw_buffer_resp), spdm_get_measurements_resp_length (resp) + 5);

	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0x05, resp->header.msg_type);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, 0x01, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_MEASUREMENTS, resp->header.req_rsp_code);

	CuAssertIntEquals (test, 1, resp->num_measurement_indices);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 2, resp->slot_id);
	CuAssertIntEquals (test, 3, resp->number_of_blocks);
	CuAssertIntEquals (test, 2, spdm_get_measurements_resp_measurement_record_len(resp));

	CuAssertPtrEquals (test, &raw_buffer_resp[9],
		spdm_get_measurements_resp_measurement_record(resp));
	CuAssertPtrEquals (test, &raw_buffer_resp[11], spdm_get_measurements_resp_nonce(resp));
	CuAssertIntEquals (test, 0x03, spdm_get_measurements_resp_opaque_len(resp));
	CuAssertPtrEquals (test, &raw_buffer_resp[45], spdm_get_measurements_resp_opaque_data(resp));
	CuAssertPtrEquals (test, &raw_buffer_resp[48], spdm_get_measurements_resp_signature(resp));
}

static void spdm_test_get_spdm_response_format (CuTest *test)
{
	uint8_t raw_buffer_resp[] = {
		0x05,0x11,0x60,
		0x01,0x02,0x03,0x02,0x00,0x00,
		0xaa,0xbb,
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04,
		0x03,0x00,
		0xcc,0xdd,0xee,
		0x11,0x22,0x33,0x44,0x55

	};
	struct spdm_get_measurements_response *resp =
		(struct spdm_get_measurements_response*) raw_buffer_resp;

	TEST_START;

	CuAssertPtrEquals (test, &raw_buffer_resp[1], spdm_get_spdm_rsp_payload(resp));
}

static void spdm_test_generate_error_response (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg msg;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) 0xcc) << 24 | 0xcd << 16 | 0xaa << 8 | 0xbb),
		.arg2 = 0xab
	};
	int status;

	msg.data = buf;
	msg.source_eid = 0xcd;

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	spdm_generate_error_response (&msg, 2, 0xaa, 0xbb, NULL, 0, 0xcc, 0xab);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 0xaa, rsp->error_code);
	CuAssertIntEquals (test, 0xbb, rsp->error_data);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_error_response_with_optional_data (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg msg;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	uint32_t optional_data = 0xCCDDEEFF;
	uint32_t *optional_data_ptr = (uint32_t*) spdm_get_spdm_error_rsp_optional_data (rsp);
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) 0xcc) << 24 | 0xcd << 16 | 0xaa << 8 | 0xbb),
		.arg2 = 0xab
	};
	int status;

	msg.data = buf;
	msg.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	msg.source_eid = 0xcd;

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	spdm_generate_error_response (&msg, 2, 0xaa, 0xbb, (uint8_t*) &optional_data,
		sizeof (optional_data), 0xcc, 0xab);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response) + sizeof (optional_data),
		msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 0xaa, rsp->error_code);
	CuAssertIntEquals (test, 0xbb, rsp->error_data);
	CuAssertIntEquals (test, 0xCCDDEEFF, *optional_data_ptr);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_error_response_with_optional_data_too_large (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg msg;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	uint32_t optional_data = 0xCCDDEEFF;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) 0xcc) << 24 | 0xcd << 16 | 0xaa << 8 | 0xbb),
		.arg2 = 0xab
	};
	int status;

	msg.data = buf;
	msg.max_response = sizeof (struct spdm_error_response) + sizeof (optional_data) - 1;
	msg.source_eid = 0xcd;

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	spdm_generate_error_response (&msg, 2, 0xaa, 0xbb, (uint8_t*) &optional_data,
		sizeof (optional_data), 0xcc, 0xab);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 0xaa, rsp->error_code);
	CuAssertIntEquals (test, 0xbb, rsp->error_data);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_version (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	uint8_t expected_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) buf;
	struct spdm_get_version_response *expected_rsp =
		(struct spdm_get_version_response*) expected_buf;
	struct spdm_version_num_entry *version_num =
		spdm_get_version_resp_version_table (expected_rsp);
	int minor_version;
	int i_version;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_version_request);

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;

	expected_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp->header.integrity_check = 0;
	expected_rsp->header.spdm_minor_version = 0;
	expected_rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	expected_rsp->reserved = 0;
	expected_rsp->reserved2 = 0;
	expected_rsp->reserved3 = 0;
	expected_rsp->version_num_entry_count = SPDM_MAX_MINOR_VERSION - SPDM_MIN_MINOR_VERSION + 1;

	for (i_version = 0, minor_version = SPDM_MIN_MINOR_VERSION;
		i_version < expected_rsp->version_num_entry_count; ++i_version, ++minor_version) {
		version_num[i_version].major_version = SPDM_MAJOR_VERSION;
		version_num[i_version].minor_version = minor_version;
		version_num[i_version].update_version = 0;
		version_num[i_version].alpha = 0;
	}

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_version_request)),
		MOCK_ARG (sizeof (struct spdm_get_version_request)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (expected_rsp, spdm_get_version_resp_length (expected_rsp)),
		MOCK_ARG (spdm_get_version_resp_length (expected_rsp)));
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_version (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, spdm_get_version_resp_length (resp), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, resp->header.msg_type);
	CuAssertIntEquals (test, 0, resp->header.integrity_check);
	CuAssertIntEquals (test, 0, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_VERSION, resp->header.req_rsp_code);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 0, resp->reserved2);
	CuAssertIntEquals (test, 0, resp->reserved3);
	CuAssertIntEquals (test, 2, resp->version_num_entry_count);

	version_num = spdm_get_version_resp_version_table (resp);

	for (i_version = 0, minor_version = SPDM_MIN_MINOR_VERSION;
		i_version < resp->version_num_entry_count; ++i_version, ++minor_version) {
		CuAssertIntEquals (test, SPDM_MAJOR_VERSION, version_num[i_version].major_version);
		CuAssertIntEquals (test, minor_version, version_num[i_version].minor_version);
		CuAssertIntEquals (test, 0, version_num[i_version].update_version);
		CuAssertIntEquals (test, 0, version_num[i_version].alpha);
	}

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_version_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_version (NULL, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = spdm_get_version (&msg, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_version_bad_length (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_version_request) - 1;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_version (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_version_request) + 1;

	status = spdm_get_version (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_version_start_hash_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) SPDM_REQUEST_GET_VERSION) << 24 | 0xcd << 16 |
			SPDM_ERROR_UNSPECIFIED << 8 | 0),
		.arg2 = HASH_ENGINE_NO_MEMORY
	};
	int status;

	msg.data = buf;
	msg.source_eid = 0xcd;
	msg.length = sizeof (struct spdm_get_version_request);

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_version (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_version_hash_update_rq_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_version_request);

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_version_request)),
		MOCK_ARG (sizeof (struct spdm_get_version_request)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_version (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_version_hash_update_rsp_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	uint8_t expected_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_get_version_response *expected_rsp =
		(struct spdm_get_version_response*) expected_buf;
	struct spdm_version_num_entry *version_num =
		spdm_get_version_resp_version_table (expected_rsp);
	int minor_version;
	int i_version;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_version_request);

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;

	expected_rsp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp->header.integrity_check = 0;
	expected_rsp->header.spdm_minor_version = 0;
	expected_rsp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	expected_rsp->reserved = 0;
	expected_rsp->reserved2 = 0;
	expected_rsp->reserved3 = 0;
	expected_rsp->version_num_entry_count = SPDM_MAX_MINOR_VERSION - SPDM_MIN_MINOR_VERSION + 1;

	for (i_version = 0, minor_version = SPDM_MIN_MINOR_VERSION;
		i_version < expected_rsp->version_num_entry_count; ++i_version, ++minor_version) {
		version_num[i_version].major_version = SPDM_MAJOR_VERSION;
		version_num[i_version].minor_version = minor_version;
		version_num[i_version].update_version = 0;
		version_num[i_version].alpha = 0;
	}

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_version_request)),
		MOCK_ARG (sizeof (struct spdm_get_version_request)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (expected_rsp, spdm_get_version_resp_length (expected_rsp)),
		MOCK_ARG (spdm_get_version_resp_length (expected_rsp)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_version (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 0, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_get_version_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_get_version_request (buf, sizeof (buf));
	CuAssertIntEquals (test, sizeof (struct spdm_get_version_request), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 0, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_VERSION, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 0, rq->reserved2);
}

static void spdm_test_generate_get_version_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_version_request) - 1];
	int status;

	TEST_START;

	status = spdm_generate_get_version_request (buf, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_get_version_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_version_request)];
	int status;

	TEST_START;

	status = spdm_generate_get_version_request (NULL, sizeof (buf));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_get_version_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_version_response) +
		sizeof (struct spdm_version_num_entry)] = {0};
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) buf;
	struct spdm_version_num_entry *version_num;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 0;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	resp->version_num_entry_count = 1;

	version_num = spdm_get_version_resp_version_table(resp);

	version_num->alpha = 1;
	version_num->update_version = 2;
	version_num->minor_version = 3;
	version_num->major_version = 4;

	TEST_START;

	status = spdm_process_get_version_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_get_version_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_version_response) - 1;

	TEST_START;

	status = spdm_process_get_version_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_version_response) +
		sizeof (struct spdm_version_num_entry) - 1;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 0;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;

	resp->version_num_entry_count = 1;

	status = spdm_process_get_version_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_version_response) +
		sizeof (struct spdm_version_num_entry) + 1;

	status = spdm_process_get_version_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_get_version_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_get_version_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_get_capabilities (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;
	struct spdm_get_capabilities expected_rsp;
	struct device_manager manager;
	struct device_manager_full_capabilities capabilities;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities);
	msg.source_eid = 0xCC;

	rq->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->base_capabilities.header.integrity_check = 0;
	rq->base_capabilities.header.spdm_minor_version = 2;
	rq->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;

	rq->base_capabilities.ct_exponent = 21;
	rq->data_transfer_size = 1000;

	expected_rsp.base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp.base_capabilities.header.integrity_check = 0;
	expected_rsp.base_capabilities.header.spdm_minor_version = 2;
	expected_rsp.base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp.base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;
	expected_rsp.base_capabilities.reserved = 0;
	expected_rsp.base_capabilities.reserved2 = 0;
	expected_rsp.base_capabilities.reserved3 = 0;
	expected_rsp.base_capabilities.ct_exponent = 20;
	expected_rsp.base_capabilities.reserved4 = 0;

	expected_rsp.base_capabilities.flags.cache_cap = 0;
	expected_rsp.base_capabilities.flags.cert_cap = 1;
	expected_rsp.base_capabilities.flags.chal_cap = 1;
	expected_rsp.base_capabilities.flags.meas_cap = 2;
	expected_rsp.base_capabilities.flags.meas_fresh_cap = 0;
	expected_rsp.base_capabilities.flags.encrypt_cap = 0;
	expected_rsp.base_capabilities.flags.mac_cap = 0;
	expected_rsp.base_capabilities.flags.mut_auth_cap = 0;
	expected_rsp.base_capabilities.flags.key_ex_cap = 0;
	expected_rsp.base_capabilities.flags.psk_cap = 0;
	expected_rsp.base_capabilities.flags.encap_cap = 0;
	expected_rsp.base_capabilities.flags.hbeat_cap = 0;
	expected_rsp.base_capabilities.flags.key_upd_cap = 0;
	expected_rsp.base_capabilities.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.base_capabilities.flags.pub_key_id_cap = 0;
	expected_rsp.base_capabilities.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.base_capabilities.flags.chunk_cap = 0;
	expected_rsp.base_capabilities.flags.alias_cert_cap = 0;
	expected_rsp.base_capabilities.flags.reserved = 0;
	expected_rsp.base_capabilities.flags.reserved2 = 0;
	expected_rsp.data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected_rsp.max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&expected_rsp, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (&msg, &manager, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->base_capabilities.header.msg_type);
	CuAssertIntEquals (test, 0, rq->base_capabilities.header.integrity_check);
	CuAssertIntEquals (test, 2, rq->base_capabilities.header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->base_capabilities.header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_CAPABILITIES,
		rq->base_capabilities.header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved2);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved3);
	CuAssertIntEquals (test, 20, rq->base_capabilities.ct_exponent);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved4);

	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.cache_cap);
	CuAssertIntEquals (test, 1, rq->base_capabilities.flags.cert_cap);
	CuAssertIntEquals (test, 1, rq->base_capabilities.flags.chal_cap);
	CuAssertIntEquals (test, 2, rq->base_capabilities.flags.meas_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.encrypt_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.mac_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.key_ex_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.psk_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.encap_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.hbeat_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.key_upd_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.chunk_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.alias_cert_cap);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq->data_transfer_size);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq->max_spdm_msg_size);

	status = device_manager_get_device_capabilities (&manager, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, capabilities.max_timeout);
	CuAssertIntEquals (test, 20, capabilities.max_sig);
	CuAssertIntEquals (test, 1000, capabilities.request.max_message_size);
	CuAssertIntEquals (test, 0, capabilities.request.max_packet_size);
	CuAssertIntEquals (test, 0, capabilities.request.security_mode);
	CuAssertIntEquals (test, 0, capabilities.request.reserved1);
	CuAssertIntEquals (test, 0, capabilities.request.bus_role);
	CuAssertIntEquals (test, 0, capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, 0, capabilities.request.reserved2);
	CuAssertIntEquals (test, 0, capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0, capabilities.request.policy_support);
	CuAssertIntEquals (test, 0, capabilities.request.pfm_support);
	CuAssertIntEquals (test, 0, capabilities.request.rsa_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.ecdsa);
	CuAssertIntEquals (test, 0, capabilities.request.rsa);
	CuAssertIntEquals (test, 0, capabilities.request.aes_enc_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.reserved3);
	CuAssertIntEquals (test, 0, capabilities.request.ecc);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void spdm_test_get_capabilities_null (CuTest *test)
{
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct device_manager manager;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (NULL, &manager, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = spdm_get_capabilities (&msg, NULL, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = spdm_get_capabilities (&msg, &manager, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void spdm_test_get_capabilities_ct_too_large (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;
	struct spdm_get_capabilities expected_rsp;
	struct device_manager manager;
	struct device_manager_full_capabilities capabilities;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities);
	msg.source_eid = 0xCC;

	rq->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->base_capabilities.header.integrity_check = 0;
	rq->base_capabilities.header.spdm_minor_version = 2;
	rq->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;

	rq->base_capabilities.ct_exponent = 24;
	rq->data_transfer_size = 1000;

	expected_rsp.base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp.base_capabilities.header.integrity_check = 0;
	expected_rsp.base_capabilities.header.spdm_minor_version = 2;
	expected_rsp.base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp.base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;
	expected_rsp.base_capabilities.reserved = 0;
	expected_rsp.base_capabilities.reserved2 = 0;
	expected_rsp.base_capabilities.reserved3 = 0;
	expected_rsp.base_capabilities.ct_exponent = 20;
	expected_rsp.base_capabilities.reserved4 = 0;

	expected_rsp.base_capabilities.flags.cache_cap = 0;
	expected_rsp.base_capabilities.flags.cert_cap = 1;
	expected_rsp.base_capabilities.flags.chal_cap = 1;
	expected_rsp.base_capabilities.flags.meas_cap = 2;
	expected_rsp.base_capabilities.flags.meas_fresh_cap = 0;
	expected_rsp.base_capabilities.flags.encrypt_cap = 0;
	expected_rsp.base_capabilities.flags.mac_cap = 0;
	expected_rsp.base_capabilities.flags.mut_auth_cap = 0;
	expected_rsp.base_capabilities.flags.key_ex_cap = 0;
	expected_rsp.base_capabilities.flags.psk_cap = 0;
	expected_rsp.base_capabilities.flags.encap_cap = 0;
	expected_rsp.base_capabilities.flags.hbeat_cap = 0;
	expected_rsp.base_capabilities.flags.key_upd_cap = 0;
	expected_rsp.base_capabilities.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.base_capabilities.flags.pub_key_id_cap = 0;
	expected_rsp.base_capabilities.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.base_capabilities.flags.chunk_cap = 0;
	expected_rsp.base_capabilities.flags.alias_cert_cap = 0;
	expected_rsp.base_capabilities.flags.reserved = 0;
	expected_rsp.base_capabilities.flags.reserved2 = 0;
	expected_rsp.data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected_rsp.max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&expected_rsp, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (&msg, &manager, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->base_capabilities.header.msg_type);
	CuAssertIntEquals (test, 0, rq->base_capabilities.header.integrity_check);
	CuAssertIntEquals (test, 2, rq->base_capabilities.header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->base_capabilities.header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_CAPABILITIES,
		rq->base_capabilities.header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved2);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved3);
	CuAssertIntEquals (test, 20, rq->base_capabilities.ct_exponent);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved4);

	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.cache_cap);
	CuAssertIntEquals (test, 1, rq->base_capabilities.flags.cert_cap);
	CuAssertIntEquals (test, 1, rq->base_capabilities.flags.chal_cap);
	CuAssertIntEquals (test, 2, rq->base_capabilities.flags.meas_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.encrypt_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.mac_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.key_ex_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.psk_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.encap_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.hbeat_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.key_upd_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.chunk_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.alias_cert_cap);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq->data_transfer_size);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq->max_spdm_msg_size);

	status = device_manager_get_device_capabilities (&manager, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, capabilities.max_timeout);
	CuAssertIntEquals (test, 167, capabilities.max_sig);
	CuAssertIntEquals (test, 1000, capabilities.request.max_message_size);
	CuAssertIntEquals (test, 0, capabilities.request.max_packet_size);
	CuAssertIntEquals (test, 0, capabilities.request.security_mode);
	CuAssertIntEquals (test, 0, capabilities.request.reserved1);
	CuAssertIntEquals (test, 0, capabilities.request.bus_role);
	CuAssertIntEquals (test, 0, capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, 0, capabilities.request.reserved2);
	CuAssertIntEquals (test, 0, capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0, capabilities.request.policy_support);
	CuAssertIntEquals (test, 0, capabilities.request.pfm_support);
	CuAssertIntEquals (test, 0, capabilities.request.rsa_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.ecdsa);
	CuAssertIntEquals (test, 0, capabilities.request.rsa);
	CuAssertIntEquals (test, 0, capabilities.request.aes_enc_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.reserved3);
	CuAssertIntEquals (test, 0, capabilities.request.ecc);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void spdm_test_get_capabilities_1_1 (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_capabilities_1_1 *rq = (struct spdm_get_capabilities_1_1*) buf;
	struct spdm_get_capabilities_1_1 expected_rsp;
	struct device_manager manager;
	struct device_manager_full_capabilities capabilities;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities_1_1);
	msg.source_eid = 0xCC;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 1;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;

	rq->ct_exponent = 21;

	expected_rsp.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp.header.integrity_check = 0;
	expected_rsp.header.spdm_minor_version = 1;
	expected_rsp.header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;
	expected_rsp.reserved = 0;
	expected_rsp.reserved2 = 0;
	expected_rsp.reserved3 = 0;
	expected_rsp.ct_exponent = 20;
	expected_rsp.reserved4 = 0;

	expected_rsp.flags.cache_cap = 0;
	expected_rsp.flags.cert_cap = 1;
	expected_rsp.flags.chal_cap = 1;
	expected_rsp.flags.meas_cap = 2;
	expected_rsp.flags.meas_fresh_cap = 0;
	expected_rsp.flags.encrypt_cap = 0;
	expected_rsp.flags.mac_cap = 0;
	expected_rsp.flags.mut_auth_cap = 0;
	expected_rsp.flags.key_ex_cap = 0;
	expected_rsp.flags.psk_cap = 0;
	expected_rsp.flags.encap_cap = 0;
	expected_rsp.flags.hbeat_cap = 0;
	expected_rsp.flags.key_upd_cap = 0;
	expected_rsp.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.flags.pub_key_id_cap = 0;
	expected_rsp.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.flags.chunk_cap = 0;
	expected_rsp.flags.alias_cert_cap = 0;
	expected_rsp.flags.reserved = 0;
	expected_rsp.flags.reserved2 = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_capabilities_1_1)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities_1_1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&expected_rsp, sizeof (struct spdm_get_capabilities_1_1)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities_1_1)));
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (&msg, &manager, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities_1_1), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 1, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_CAPABILITIES, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 0, rq->reserved2);
	CuAssertIntEquals (test, 0, rq->reserved3);
	CuAssertIntEquals (test, 20, rq->ct_exponent);
	CuAssertIntEquals (test, 0, rq->reserved4);

	CuAssertIntEquals (test, 0, rq->flags.cache_cap);
	CuAssertIntEquals (test, 1, rq->flags.cert_cap);
	CuAssertIntEquals (test, 1, rq->flags.chal_cap);
	CuAssertIntEquals (test, 2, rq->flags.meas_cap);
	CuAssertIntEquals (test, 0, rq->flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, rq->flags.encrypt_cap);
	CuAssertIntEquals (test, 0, rq->flags.mac_cap);
	CuAssertIntEquals (test, 0, rq->flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, rq->flags.key_ex_cap);
	CuAssertIntEquals (test, 0, rq->flags.psk_cap);
	CuAssertIntEquals (test, 0, rq->flags.encap_cap);
	CuAssertIntEquals (test, 0, rq->flags.hbeat_cap);
	CuAssertIntEquals (test, 0, rq->flags.key_upd_cap);
	CuAssertIntEquals (test, 0, rq->flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, rq->flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->flags.chunk_cap);
	CuAssertIntEquals (test, 0, rq->flags.alias_cert_cap);

	status = device_manager_get_device_capabilities (&manager, 1, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 10, capabilities.max_timeout);
	CuAssertIntEquals (test, 20, capabilities.max_sig);
	CuAssertIntEquals (test, 0, capabilities.request.max_message_size);
	CuAssertIntEquals (test, 0, capabilities.request.max_packet_size);
	CuAssertIntEquals (test, 0, capabilities.request.security_mode);
	CuAssertIntEquals (test, 0, capabilities.request.reserved1);
	CuAssertIntEquals (test, 0, capabilities.request.bus_role);
	CuAssertIntEquals (test, 0, capabilities.request.hierarchy_role);
	CuAssertIntEquals (test, 0, capabilities.request.reserved2);
	CuAssertIntEquals (test, 0, capabilities.request.fw_protection);
	CuAssertIntEquals (test, 0, capabilities.request.policy_support);
	CuAssertIntEquals (test, 0, capabilities.request.pfm_support);
	CuAssertIntEquals (test, 0, capabilities.request.rsa_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.ecc_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.ecdsa);
	CuAssertIntEquals (test, 0, capabilities.request.rsa);
	CuAssertIntEquals (test, 0, capabilities.request.aes_enc_key_strength);
	CuAssertIntEquals (test, 0, capabilities.request.reserved3);
	CuAssertIntEquals (test, 0, capabilities.request.ecc);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);
}

static void spdm_test_get_capabilities_unknown_device (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct device_manager manager;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 =
			(((uint32_t) SPDM_REQUEST_GET_CAPABILITIES) << 24 | 0xdd << 16 |
				SPDM_ERROR_UNSPECIFIED << 8 | 0),
		.arg2 = DEVICE_MGR_UNKNOWN_DEVICE
	};
	int status;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities);
	msg.source_eid = 0xDD;

	rq->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->base_capabilities.header.integrity_check = 0;
	rq->base_capabilities.header.spdm_minor_version = 2;
	rq->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;

	rq->base_capabilities.ct_exponent = 21;
	rq->data_transfer_size = 1000;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC, 0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (&msg, &manager, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_capabilities_hash_update_rq_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct device_manager manager;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 =
			(((uint32_t) SPDM_REQUEST_GET_CAPABILITIES) << 24 | 0xcc << 16 |
				SPDM_ERROR_UNSPECIFIED << 8 | 0),
		.arg2 = HASH_ENGINE_NO_MEMORY
	};
	int status;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities);
	msg.source_eid = 0xCC;

	rq->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->base_capabilities.header.integrity_check = 0;
	rq->base_capabilities.header.spdm_minor_version = 2;
	rq->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;

	rq->base_capabilities.ct_exponent = 21;
	rq->data_transfer_size = 1000;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (&msg, &manager, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_get_capabilities_hash_update_rsp_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct hash_engine_mock hash;
	struct cmd_interface_msg msg;
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_get_capabilities expected_rsp;
	struct device_manager manager;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 =
			(((uint32_t) SPDM_REQUEST_GET_CAPABILITIES) << 24 | 0xcc << 16 |
				SPDM_ERROR_UNSPECIFIED << 8 | 0),
		.arg2 = HASH_ENGINE_NO_MEMORY
	};
	int status;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities);
	msg.source_eid = 0xCC;

	rq->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->base_capabilities.header.integrity_check = 0;
	rq->base_capabilities.header.spdm_minor_version = 2;
	rq->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;

	rq->base_capabilities.ct_exponent = 21;
	rq->data_transfer_size = 1000;

	expected_rsp.base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp.base_capabilities.header.integrity_check = 0;
	expected_rsp.base_capabilities.header.spdm_minor_version = 2;
	expected_rsp.base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp.base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;
	expected_rsp.base_capabilities.reserved = 0;
	expected_rsp.base_capabilities.reserved2 = 0;
	expected_rsp.base_capabilities.reserved3 = 0;
	expected_rsp.base_capabilities.ct_exponent = 20;
	expected_rsp.base_capabilities.reserved4 = 0;

	expected_rsp.base_capabilities.flags.cache_cap = 0;
	expected_rsp.base_capabilities.flags.cert_cap = 1;
	expected_rsp.base_capabilities.flags.chal_cap = 1;
	expected_rsp.base_capabilities.flags.meas_cap = 2;
	expected_rsp.base_capabilities.flags.meas_fresh_cap = 0;
	expected_rsp.base_capabilities.flags.encrypt_cap = 0;
	expected_rsp.base_capabilities.flags.mac_cap = 0;
	expected_rsp.base_capabilities.flags.mut_auth_cap = 0;
	expected_rsp.base_capabilities.flags.key_ex_cap = 0;
	expected_rsp.base_capabilities.flags.psk_cap = 0;
	expected_rsp.base_capabilities.flags.encap_cap = 0;
	expected_rsp.base_capabilities.flags.hbeat_cap = 0;
	expected_rsp.base_capabilities.flags.key_upd_cap = 0;
	expected_rsp.base_capabilities.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.base_capabilities.flags.pub_key_id_cap = 0;
	expected_rsp.base_capabilities.flags.handshake_in_the_clear_cap = 0;
	expected_rsp.base_capabilities.flags.chunk_cap = 0;
	expected_rsp.base_capabilities.flags.alias_cert_cap = 0;
	expected_rsp.base_capabilities.flags.reserved = 0;
	expected_rsp.base_capabilities.flags.reserved2 = 0;
	expected_rsp.data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	expected_rsp.max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&expected_rsp, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_init (&manager, 2, 0, DEVICE_MANAGER_AC_ROT_MODE,
		DEVICE_MANAGER_SLAVE_BUS_ROLE, 1000, 0, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB, 0);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 1, 0xCC,	0xDD, 1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_get_capabilities (&msg, &manager, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	device_manager_release (&manager);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_get_capabilities_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_capabilities *rq = (struct spdm_get_capabilities*) buf;
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_get_capabilities_request (buf, sizeof (buf), 2);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->base_capabilities.header.msg_type);
	CuAssertIntEquals (test, 0, rq->base_capabilities.header.integrity_check);
	CuAssertIntEquals (test, 2, rq->base_capabilities.header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->base_capabilities.header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_CAPABILITIES,
		rq->base_capabilities.header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved2);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved3);
	CuAssertIntEquals (test, 20, rq->base_capabilities.ct_exponent);
	CuAssertIntEquals (test, 0, rq->base_capabilities.reserved4);

	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.cache_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.cert_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.chal_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.meas_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.encrypt_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.mac_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.key_ex_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.psk_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.encap_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.hbeat_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.key_upd_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.chunk_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.alias_cert_cap);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.reserved);
	CuAssertIntEquals (test, 0, rq->base_capabilities.flags.reserved2);

	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq->data_transfer_size);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, rq->max_spdm_msg_size);
}

static void spdm_test_generate_get_capabilities_request_1_1 (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_capabilities_1_1 *rq = (struct spdm_get_capabilities_1_1*) buf;
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_get_capabilities_request (buf, sizeof (buf), 1);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities_1_1), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 1, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_CAPABILITIES,	rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 0, rq->reserved2);
	CuAssertIntEquals (test, 0, rq->reserved3);
	CuAssertIntEquals (test, 20, rq->ct_exponent);
	CuAssertIntEquals (test, 0, rq->reserved4);

	CuAssertIntEquals (test, 0, rq->flags.cache_cap);
	CuAssertIntEquals (test, 0, rq->flags.cert_cap);
	CuAssertIntEquals (test, 0, rq->flags.chal_cap);
	CuAssertIntEquals (test, 0, rq->flags.meas_cap);
	CuAssertIntEquals (test, 0, rq->flags.meas_fresh_cap);
	CuAssertIntEquals (test, 0, rq->flags.encrypt_cap);
	CuAssertIntEquals (test, 0, rq->flags.mac_cap);
	CuAssertIntEquals (test, 0, rq->flags.mut_auth_cap);
	CuAssertIntEquals (test, 0, rq->flags.key_ex_cap);
	CuAssertIntEquals (test, 0, rq->flags.psk_cap);
	CuAssertIntEquals (test, 0, rq->flags.encap_cap);
	CuAssertIntEquals (test, 0, rq->flags.hbeat_cap);
	CuAssertIntEquals (test, 0, rq->flags.key_upd_cap);
	CuAssertIntEquals (test, 0, rq->flags.handshake_in_the_clear_cap);
	CuAssertIntEquals (test, 0, rq->flags.pub_key_id_cap);
	CuAssertIntEquals (test, 0, rq->flags.chunk_cap);
	CuAssertIntEquals (test, 0, rq->flags.alias_cert_cap);
	CuAssertIntEquals (test, 0, rq->flags.reserved);
	CuAssertIntEquals (test, 0, rq->flags.reserved2);
}

static void spdm_test_generate_get_capabilities_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_capabilities) - 1];
	int status;

	TEST_START;

	status = spdm_generate_get_capabilities_request (buf, sizeof (buf), 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_get_capabilities_request_1_1_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_capabilities_1_1) - 1];
	int status;

	TEST_START;

	status = spdm_generate_get_capabilities_request (buf, sizeof (buf), 1);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_get_capabilities_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_capabilities)];
	int status;

	TEST_START;

	status = spdm_generate_get_capabilities_request (NULL, sizeof (buf), 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_get_capabilities_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_capabilities)] = {0};
	struct spdm_get_capabilities *resp = (struct spdm_get_capabilities*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->base_capabilities.header.integrity_check = 0;
	resp->base_capabilities.header.spdm_minor_version = 2;
	resp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	resp->base_capabilities.reserved = 0;
	resp->base_capabilities.reserved2 = 0;
	resp->base_capabilities.reserved3 = 0;
	resp->base_capabilities.ct_exponent = 1;
	resp->base_capabilities.reserved4 = 0;

	resp->base_capabilities.flags.cache_cap = 1;
	resp->base_capabilities.flags.cert_cap = 1;
	resp->base_capabilities.flags.chal_cap = 1;
	resp->base_capabilities.flags.meas_cap = 1;
	resp->base_capabilities.flags.meas_fresh_cap = 1;
	resp->base_capabilities.flags.encrypt_cap = 1;
	resp->base_capabilities.flags.mac_cap = 1;
	resp->base_capabilities.flags.mut_auth_cap = 1;
	resp->base_capabilities.flags.key_ex_cap = 1;
	resp->base_capabilities.flags.psk_cap = 1;
	resp->base_capabilities.flags.encap_cap = 1;
	resp->base_capabilities.flags.hbeat_cap = 1;
	resp->base_capabilities.flags.key_upd_cap = 1;
	resp->base_capabilities.flags.handshake_in_the_clear_cap = 1;
	resp->base_capabilities.flags.pub_key_id_cap = 1;
	resp->base_capabilities.flags.chunk_cap = 1;
	resp->base_capabilities.flags.alias_cert_cap = 1;
	resp->base_capabilities.flags.reserved = 0;
	resp->base_capabilities.flags.reserved2 = 0;

	resp->data_transfer_size = 4096;
	resp->max_spdm_msg_size = 4096;

	TEST_START;

	status = spdm_process_get_capabilities_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_get_capabilities_1_1_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_capabilities_1_1)] = {0};
	struct spdm_get_capabilities_1_1 *resp = (struct spdm_get_capabilities_1_1*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 1;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	resp->reserved = 0;
	resp->reserved2 = 0;
	resp->reserved3 = 0;
	resp->ct_exponent = 1;
	resp->reserved4 = 0;

	resp->flags.cache_cap = 1;
	resp->flags.cert_cap = 1;
	resp->flags.chal_cap = 1;
	resp->flags.meas_cap = 1;
	resp->flags.meas_fresh_cap = 1;
	resp->flags.encrypt_cap = 1;
	resp->flags.mac_cap = 1;
	resp->flags.mut_auth_cap = 1;
	resp->flags.key_ex_cap = 1;
	resp->flags.psk_cap = 1;
	resp->flags.encap_cap = 1;
	resp->flags.hbeat_cap = 1;
	resp->flags.key_upd_cap = 1;
	resp->flags.handshake_in_the_clear_cap = 1;
	resp->flags.pub_key_id_cap = 1;
	resp->flags.chunk_cap = 0;
	resp->flags.alias_cert_cap = 0;
	resp->flags.reserved = 0;
	resp->flags.reserved2 = 0;

	TEST_START;

	status = spdm_process_get_capabilities_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_get_capabilities_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_capabilities *resp = (struct spdm_get_capabilities*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities) - 1;

	resp->base_capabilities.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->base_capabilities.header.integrity_check = 0;
	resp->base_capabilities.header.spdm_minor_version = 2;
	resp->base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->base_capabilities.header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	TEST_START;

	status = spdm_process_get_capabilities_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_capabilities) + 1;

	status = spdm_process_get_capabilities_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_get_capabilities_response_1_1_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_capabilities_1_1 *resp = (struct spdm_get_capabilities_1_1*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_capabilities_1_1) - 1;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 1;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_CAPABILITIES;

	TEST_START;

	status = spdm_process_get_capabilities_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_capabilities_1_1) + 1;

	status = spdm_process_get_capabilities_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_get_capabilities_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_get_capabilities_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_negotiate_algorithms (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) buf;
	struct spdm_negotiate_algorithms_response expected_rsp = {0};
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	uint8_t zeroes[12] = {0};
	int status;

	msg.data = buf;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->reserved2 = 0;
	rq->base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P521 | SPDM_TPM_ALG_ECDSA_ECC_NIST_P384 |
		SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	rq->base_hash_algo = SPDM_TPM_ALG_SHA_512 | SPDM_TPM_ALG_SHA_384 | SPDM_TPM_ALG_SHA_256;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	expected_rsp.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp.header.integrity_check = 0;
	expected_rsp.header.spdm_minor_version = 2;
	expected_rsp.header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp.header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;
	expected_rsp.num_alg_structure_tables = 0;
	expected_rsp.reserved = 0;
	expected_rsp.length = sizeof (struct spdm_negotiate_algorithms_response) - 1;
	expected_rsp.measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	expected_rsp.reserved2 = 0;
	expected_rsp.measurement_hash_algo = SPDM_TPM_ALG_SHA_256;
	expected_rsp.base_asym_sel = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	expected_rsp.base_hash_sel = SPDM_TPM_ALG_SHA_256;

	memset (expected_rsp.reserved3, 0, sizeof (expected_rsp.reserved3));

	expected_rsp.ext_asym_sel_count = 0;
	expected_rsp.ext_hash_sel_count = 0;
	expected_rsp.reserved4 = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	msg.length = rq->length + 1;

	status = mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, msg.length), MOCK_ARG (msg.length));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&expected_rsp, sizeof (expected_rsp)),
		MOCK_ARG (sizeof (expected_rsp)));
	CuAssertIntEquals (test, 0, status);

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_NEGOTIATE_ALGORITHMS, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rsp->num_alg_structure_tables);
	CuAssertIntEquals (test, 0, rsp->reserved);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response) - 1, rsp->length);
	CuAssertIntEquals (test, SPDM_MEASUREMENT_SPEC_DMTF, rsp->measurement_specification);
	CuAssertIntEquals (test, 0, rsp->reserved2);
	CuAssertIntEquals (test, SPDM_TPM_ALG_SHA_256, rsp->measurement_hash_algo);
	CuAssertIntEquals (test, SPDM_TPM_ALG_ECDSA_ECC_NIST_P256, rsp->base_asym_sel);
	CuAssertIntEquals (test, SPDM_TPM_ALG_SHA_256, rsp->base_hash_sel);

	status = testing_validate_array (zeroes, rsp->reserved3, sizeof (zeroes));
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, rsp->ext_asym_sel_count);
	CuAssertIntEquals (test, 0, rsp->ext_hash_sel_count);
	CuAssertIntEquals (test, 0, rsp->reserved4);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_null (CuTest *test)
{
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = spdm_negotiate_algorithms (NULL, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = spdm_negotiate_algorithms (&msg, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_dmtf_measurement_specification_not_supported (
	CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) SPDM_REQUEST_NEGOTIATE_ALGORITHMS) << 24 | 0xab << 16 |
			SPDM_ERROR_INVALID_REQUEST << 8 | 0),
		.arg2 = CMD_HANDLER_SPDM_UNSUPPORTED_MEAS_SPEC
	};
	int status;

	msg.data = buf;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = 0;
	rq->reserved2 = 0;
	rq->base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	rq->base_hash_algo = SPDM_TPM_ALG_SHA_256;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	msg.length = rq->length + 1;
	msg.source_eid = 0xab;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_no_common_asym_algo (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) SPDM_REQUEST_NEGOTIATE_ALGORITHMS) << 24 | 0xab << 16 |
			SPDM_ERROR_INVALID_REQUEST << 8 | 0),
		.arg2 = CMD_HANDLER_SPDM_UNSUPPORTED_ASYM_ALGO
	};
	int status;

	msg.data = buf;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->reserved2 = 0;
	rq->base_asym_algo = 0;
	rq->base_hash_algo = SPDM_TPM_ALG_SHA_256;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	msg.length = rq->length + 1;
	msg.source_eid = 0xab;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_no_common_hash_algo (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) SPDM_REQUEST_NEGOTIATE_ALGORITHMS) << 24 | 0xab << 16 |
			SPDM_ERROR_INVALID_REQUEST << 8 | 0),
		.arg2 = CMD_HANDLER_SPDM_UNSUPPORTED_HASH_ALGO
	};
	int status;

	msg.data = buf;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->reserved2 = 0;
	rq->base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	rq->base_hash_algo = 0;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	msg.length = rq->length + 1;
	msg.source_eid = 0xab;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	int status;

	msg.data = buf;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->reserved2 = 0;
	rq->base_asym_algo = 0xabcdef;
	rq->base_hash_algo = 0xfedcba;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_request) - 1;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 2;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = rq->length;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = rq->length + 2;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_request) +
		sizeof (struct spdm_extended_algorithm) *
		(rq->ext_asym_count + rq->ext_hash_count) +
		sizeof (struct spdm_algorithm_request) * rq->num_alg_structure_tables - 1;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) +
		sizeof (struct spdm_extended_algorithm) *
		(rq->ext_asym_count + rq->ext_hash_count) +
		sizeof (struct spdm_algorithm_request) * rq->num_alg_structure_tables - 2;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 3 + sizeof (struct spdm_algorithm_request) * 2;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 2 +
		sizeof (struct spdm_extended_algorithm) * 3 + sizeof (struct spdm_algorithm_request) * 2;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 2 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_hash_update_rq_fail (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) SPDM_REQUEST_NEGOTIATE_ALGORITHMS) << 24 | 0xab << 16 |
			SPDM_ERROR_UNSPECIFIED << 8 | 0),
		.arg2 = HASH_ENGINE_NO_MEMORY
	};
	int status;

	msg.data = buf;
	msg.source_eid = 0xab;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->reserved2 = 0;
	rq->base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P521 | SPDM_TPM_ALG_ECDSA_ECC_NIST_P384 |
		SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	rq->base_hash_algo = SPDM_TPM_ALG_SHA_512 | SPDM_TPM_ALG_SHA_384 | SPDM_TPM_ALG_SHA_256;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);
	msg.length = rq->length + 1;

	status = mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, msg.length), MOCK_ARG (msg.length));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_negotiate_algorithms_hash_update_rsp_fail (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_error_response *rsp = (struct spdm_error_response*) buf;
	struct spdm_negotiate_algorithms_response expected_rsp;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	struct hash_engine_mock hash;
	struct logging_mock log;
	struct debug_log_entry_info entry = {
		.format = DEBUG_LOG_ENTRY_FORMAT,
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_SPDM,
		.msg_index = SPDM_LOGGING_ERR_MSG,
		.arg1 = (((uint32_t) SPDM_REQUEST_NEGOTIATE_ALGORITHMS) << 24 | 0xab << 16 |
			SPDM_ERROR_UNSPECIFIED << 8 | 0),
		.arg2 = HASH_ENGINE_NO_MEMORY
	};
	int status;

	msg.data = buf;

	rq->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	rq->header.integrity_check = 0;
	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	rq->num_alg_structure_tables = 2;
	rq->reserved = 0;
	rq->length = sizeof (struct spdm_negotiate_algorithms_request) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	rq->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	rq->reserved2 = 0;
	rq->base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P521 | SPDM_TPM_ALG_ECDSA_ECC_NIST_P384 |
		SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	rq->base_hash_algo = SPDM_TPM_ALG_SHA_512 | SPDM_TPM_ALG_SHA_384 | SPDM_TPM_ALG_SHA_256;
	rq->ext_asym_count = 1;
	rq->ext_hash_count = 1;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table(rq);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));

	expected_rsp.header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	expected_rsp.header.integrity_check = 0;
	expected_rsp.header.spdm_minor_version = 2;
	expected_rsp.header.spdm_major_version = SPDM_MAJOR_VERSION;
	expected_rsp.header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;
	expected_rsp.num_alg_structure_tables = 0;
	expected_rsp.reserved = 0;
	expected_rsp.length = sizeof (struct spdm_negotiate_algorithms_response) - 1;
	expected_rsp.measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	expected_rsp.reserved2 = 0;
	expected_rsp.measurement_hash_algo = SPDM_TPM_ALG_SHA_256;
	expected_rsp.base_asym_sel = SPDM_TPM_ALG_ECDSA_ECC_NIST_P256;
	expected_rsp.base_hash_sel = SPDM_TPM_ALG_SHA_256;

	memset (expected_rsp.reserved3, 0, sizeof (expected_rsp.reserved3));

	expected_rsp.ext_asym_sel_count = 0;
	expected_rsp.ext_hash_sel_count = 0;
	expected_rsp.reserved4 = 0;

	TEST_START;

	status = logging_mock_init (&log);
	CuAssertIntEquals (test, 0, status);

	debug_log = &log.base;

	status = mock_expect (&log.mock, log.base.create_entry, &log, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) &entry, LOG_ENTRY_SIZE_TIME_FIELD_NOT_INCLUDED),
		MOCK_ARG (sizeof (entry)));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	msg.length = rq->length + 1;
	msg.source_eid = 0xab;

	status = mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (rq, msg.length), MOCK_ARG (msg.length));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (&expected_rsp, sizeof (expected_rsp)),
		MOCK_ARG (sizeof (expected_rsp)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_negotiate_algorithms (&msg, &hash.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), msg.length);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rsp->header.msg_type);
	CuAssertIntEquals (test, 0, rsp->header.integrity_check);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, SPDM_ERROR_UNSPECIFIED, rsp->error_code);
	CuAssertIntEquals (test, 0, rsp->error_data);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	debug_log = NULL;

	status = logging_mock_validate_and_release (&log);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_negotiate_algorithms_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_request *rq = (struct spdm_negotiate_algorithms_request*) buf;
	uint8_t reserved_buf[12] = {0};
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_negotiate_algorithms_request (buf, sizeof (buf), 0xa0b0c0d0, 0x10203040,
		2);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_request), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_NEGOTIATE_ALGORITHMS, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->num_alg_structure_tables);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_request) - 1, rq->length);
	CuAssertIntEquals (test, SPDM_MEASUREMENT_SPEC_DMTF, rq->measurement_specification);
	CuAssertIntEquals (test, 0, rq->reserved2);
	CuAssertIntEquals (test, 0xa0b0c0d0, rq->base_asym_algo);
	CuAssertIntEquals (test, 0x10203040, rq->base_hash_algo);
	CuAssertIntEquals (test, 0, rq->ext_asym_count);
	CuAssertIntEquals (test, 0, rq->ext_hash_count);
	CuAssertIntEquals (test, 0, rq->reserved4);

	status = testing_validate_array (reserved_buf, rq->reserved3, sizeof (reserved_buf));
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_negotiate_algorithms_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_negotiate_algorithms_request) - 1];
	int status;

	TEST_START;

	status = spdm_generate_negotiate_algorithms_request (buf, sizeof (buf), 0, 0, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_negotiate_algorithms_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_negotiate_algorithms_request)];
	int status;

	TEST_START;

	status = spdm_generate_negotiate_algorithms_request (NULL, sizeof (buf), 0, 0, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_negotiate_algorithms_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_negotiate_algorithms_response)] = {0};
	struct spdm_negotiate_algorithms_response *resp =
		(struct spdm_negotiate_algorithms_response*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	resp->num_alg_structure_tables = 0;
	resp->reserved = 0;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1;
	resp->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	resp->reserved2 = 0;
	resp->measurement_hash_algo = 0xaabbccdd;
	resp->base_asym_sel = 0xabcdef;
	resp->base_hash_sel = 0xfedcba;
	resp->ext_asym_sel_count = 0;
	resp->ext_hash_sel_count = 0;
	resp->reserved4 = 0;

	memset (resp->reserved3, 0, sizeof (resp->reserved3));

	TEST_START;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_negotiate_algorithms_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_negotiate_algorithms_response *resp =
		(struct spdm_negotiate_algorithms_response*) buf;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_NEGOTIATE_ALGORITHMS;

	resp->num_alg_structure_tables = 2;
	resp->reserved = 0;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	resp->measurement_specification = SPDM_MEASUREMENT_SPEC_DMTF;
	resp->reserved2 = 0;
	resp->measurement_hash_algo = 0xaabbccdd;
	resp->base_asym_sel = 0xabcdef;
	resp->base_hash_sel = 0xfedcba;
	resp->ext_asym_sel_count = 1;
	resp->ext_hash_sel_count = 1;
	resp->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_rsp_algstruct_table(resp);
	algstruct_table->ext_alg_count = 1;

	algstruct_table = (struct spdm_algorithm_request*) (((uint8_t*) (algstruct_table + 1)) +
		sizeof (struct spdm_extended_algorithm));
	algstruct_table->ext_alg_count = 1;

	memset (resp->reserved3, 0, sizeof (resp->reserved3));

	TEST_START;

	msg.length = sizeof (struct spdm_negotiate_algorithms_response) - 1;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 2;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = resp->length;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = resp->length + 2;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_response) +
		sizeof (struct spdm_extended_algorithm) *
		(resp->ext_asym_sel_count + resp->ext_hash_sel_count) +
		sizeof (struct spdm_algorithm_request) * resp->num_alg_structure_tables - 1;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) +
		sizeof (struct spdm_extended_algorithm) *
		(resp->ext_asym_sel_count + resp->ext_hash_sel_count) +
		sizeof (struct spdm_algorithm_request) * resp->num_alg_structure_tables - 2;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_response) - 1 +
		sizeof (struct spdm_extended_algorithm) * 3 + sizeof (struct spdm_algorithm_request) * 2;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 2 +
		sizeof (struct spdm_extended_algorithm) * 3 + sizeof (struct spdm_algorithm_request) * 2;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_negotiate_algorithms_response) - 1 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;
	resp->length = sizeof (struct spdm_negotiate_algorithms_response) - 2 +
		sizeof (struct spdm_extended_algorithm) * 4 + sizeof (struct spdm_algorithm_request) * 2;

	status = spdm_process_negotiate_algorithms_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_negotiate_algorithms_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_negotiate_algorithms_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_generate_get_digests_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_digests_request *rq = (struct spdm_get_digests_request*) buf;
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_get_digests_request (buf, sizeof (buf), 2);
	CuAssertIntEquals (test, sizeof (struct spdm_get_digests_request), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_DIGESTS, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 0, rq->reserved2);
}

static void spdm_test_generate_get_digests_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_digests_request) - 1];
	int status;

	TEST_START;

	status = spdm_generate_get_digests_request (buf, sizeof (buf), 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_get_digests_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_digests_request)];
	int status;

	TEST_START;

	status = spdm_generate_get_digests_request (NULL, sizeof (buf), 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_get_digests_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_digests_response) + 32] = {0};
	struct spdm_get_digests_response *resp = (struct spdm_get_digests_response*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	resp->slot_mask = 1;
	resp->reserved = 0;

	TEST_START;

	status = spdm_process_get_digests_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_get_digests_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_digests_response) - 1;

	TEST_START;

	status = spdm_process_get_digests_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_get_digests_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_get_digests_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_generate_get_certificate_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_certificate_request *rq = (struct spdm_get_certificate_request*) buf;
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_get_certificate_request (buf, sizeof (buf), 1, 2, 3, 2);
	CuAssertIntEquals (test, sizeof (struct spdm_get_certificate_request), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_CERTIFICATE, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 1, rq->slot_num);
	CuAssertIntEquals (test, 2, rq->offset);
	CuAssertIntEquals (test, 3, rq->length);
}

static void spdm_test_generate_get_certificate_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_certificate_request) - 1];
	int status;

	TEST_START;

	status = spdm_generate_get_certificate_request (buf, sizeof (buf), 1, 2, 3, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_get_certificate_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_certificate_request)];
	int status;

	TEST_START;

	status = spdm_generate_get_certificate_request (NULL, sizeof (buf), 0, 0, 0, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_get_certificate_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_certificate_response) + 32] = {0};
	struct spdm_get_certificate_response *resp = (struct spdm_get_certificate_response*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	resp->slot_num = 1;
	resp->portion_len = 32;
	resp->remainder_len = 0xcc;
	resp->reserved = 0;

	TEST_START;

	status = spdm_process_get_certificate_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_get_certificate_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_certificate_response *resp = (struct spdm_get_certificate_response*) buf;
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_certificate_response) - 1;

	TEST_START;

	status = spdm_process_get_certificate_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_certificate_response) + 31;

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_DIGESTS;

	resp->slot_num = 1;
	resp->portion_len = 32;
	resp->remainder_len = 0xaa;
	resp->reserved = 0;

	status = spdm_process_get_certificate_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = sizeof (struct spdm_get_certificate_response) + 33;

	status = spdm_process_get_certificate_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_get_certificate_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_get_certificate_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_format_signature_digest (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	uint8_t formatted_digest[SHA256_HASH_LENGTH] = {0};
	uint8_t digest[SHA256_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	int status;

	digest[0] = 0x19;
	digest[31] = 0x92;

	formatted_digest[0] = 0x10;
	formatted_digest[31] = 0x08;

	spdm_prefix[13] = '2';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (combined_spdm_prefix, sizeof (combined_spdm_prefix)),
		MOCK_ARG (sizeof (combined_spdm_prefix)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digest, sizeof (digest)), MOCK_ARG (sizeof (digest)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (HASH_MAX_HASH_LEN));
	status |= mock_expect_output (&hash.mock, 0, formatted_digest, sizeof (formatted_digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA256, 2, spdm_context, digest);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (formatted_digest, digest, sizeof (formatted_digest));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_sha384 (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	uint8_t formatted_digest[SHA384_HASH_LENGTH] = {0};
	uint8_t digest[SHA384_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	formatted_digest[0] = 0x10;
	formatted_digest[47] = 0x08;

	spdm_prefix[13] = '2';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (combined_spdm_prefix, sizeof (combined_spdm_prefix)),
		MOCK_ARG (sizeof (combined_spdm_prefix)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digest, sizeof (digest)), MOCK_ARG (sizeof (digest)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (HASH_MAX_HASH_LEN));
	status |= mock_expect_output (&hash.mock, 0, formatted_digest, sizeof (formatted_digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA384, 2, spdm_context, digest);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (formatted_digest, digest, sizeof (formatted_digest));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_sha512 (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	uint8_t formatted_digest[SHA512_HASH_LENGTH] = {0};
	uint8_t digest[SHA512_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	formatted_digest[0] = 0x10;
	formatted_digest[47] = 0x08;

	spdm_prefix[13] = '2';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (combined_spdm_prefix, sizeof (combined_spdm_prefix)),
		MOCK_ARG (sizeof (combined_spdm_prefix)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digest, sizeof (digest)), MOCK_ARG (sizeof (digest)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (HASH_MAX_HASH_LEN));
	status |= mock_expect_output (&hash.mock, 0, formatted_digest, sizeof (formatted_digest), -1);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA512, 2, spdm_context, digest);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (formatted_digest, digest, sizeof (formatted_digest));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_start_hash_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t digest[SHA256_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	int status;

	digest[0] = 0x19;
	digest[31] = 0x92;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA256, 2, spdm_context, digest);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_start_hash_sha384_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t digest[SHA384_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA384, 2, spdm_context, digest);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_start_hash_sha512_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t digest[SHA512_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash, HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA512, 2, spdm_context, digest);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_update_hash_prefix_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	uint8_t digest[SHA384_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	spdm_prefix[13] = '2';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS (combined_spdm_prefix, sizeof (combined_spdm_prefix)),
		MOCK_ARG (sizeof (combined_spdm_prefix)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA384, 2, spdm_context, digest);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_update_hash_context_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	uint8_t digest[SHA384_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	spdm_prefix[13] = '2';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (combined_spdm_prefix, sizeof (combined_spdm_prefix)),
		MOCK_ARG (sizeof (combined_spdm_prefix)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_PTR_CONTAINS_TMP (digest, sizeof (digest)), MOCK_ARG (sizeof (digest)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA384, 2, spdm_context, digest);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_format_signature_digest_finish_hash_fail (CuTest *test)
{
	struct hash_engine_mock hash;
	uint8_t combined_spdm_prefix[SPDM_COMBINED_PREFIX_LEN] = {0};
	uint8_t digest[SHA384_HASH_LENGTH] = {0};
	char spdm_context[] = "responder-challenge_auth signing";
	char spdm_prefix[] = "dmtf-spdm-v1.x.*";
	size_t spdm_prefix_len = strlen (spdm_prefix);
	int status;

	digest[0] = 0x19;
	digest[47] = 0x92;

	spdm_prefix[13] = '2';

	strcpy ((char*) combined_spdm_prefix, spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 2], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[spdm_prefix_len * 3], spdm_prefix);
	strcpy ((char*) &combined_spdm_prefix[100 - strlen (spdm_context)], spdm_context);

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (combined_spdm_prefix, sizeof (combined_spdm_prefix)),
		MOCK_ARG (sizeof (combined_spdm_prefix)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (digest, sizeof (digest)), MOCK_ARG (sizeof (digest)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_NO_MEMORY,
		MOCK_ARG_NOT_NULL, MOCK_ARG (HASH_MAX_HASH_LEN));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_format_signature_digest (&hash.base, HASH_TYPE_SHA384, 2, spdm_context, digest);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_challenge_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_challenge_request *rq = (struct spdm_challenge_request*) buf;
	uint8_t nonce[SPDM_NONCE_LEN] = {0};
	int status;

	memset (buf, 0x55, sizeof (buf));

	nonce[0] = 0xaa;
	nonce[10] = 0xbb;
	nonce[20] = 0xcc;
	nonce[30] = 0xdd;
	nonce[31] = 0xee;

	TEST_START;

	status = spdm_generate_challenge_request (buf, sizeof (buf), 1, 2, nonce, 2);
	CuAssertIntEquals (test, sizeof (struct spdm_challenge_request), status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_CHALLENGE, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 1, rq->slot_num);
	CuAssertIntEquals (test, 2, rq->req_measurement_summary_hash_type);

	status = testing_validate_array (nonce, rq->nonce, sizeof (nonce));
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_challenge_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_challenge_request) - 1];
	uint8_t nonce[SPDM_NONCE_LEN];
	int status;

	TEST_START;

	status = spdm_generate_challenge_request (buf, sizeof (buf), 1, 2, nonce, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_challenge_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_challenge_request)];
	uint8_t nonce[SPDM_NONCE_LEN];
	int status;

	TEST_START;

	status = spdm_generate_challenge_request (NULL, sizeof (buf), 0, 0, nonce, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = spdm_generate_challenge_request (buf, sizeof (buf), 0, 0, NULL, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_challenge_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_challenge_response) + 45] = {0};
	struct spdm_challenge_response *resp = (struct spdm_challenge_response*) buf;
	uint16_t *opaque_len = spdm_get_challenge_resp_opaque_len_ptr (resp, SHA256_HASH_LENGTH,
		SHA256_HASH_LENGTH);
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_CHALLENGE;

	resp->slot_num = 1;
	resp->reserved = 0;
	resp->basic_mutual_auth_req = 1;
	resp->slot_mask = 2;

	*opaque_len = 2;

	TEST_START;

	status = spdm_process_challenge_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_challenge_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct cmd_interface_msg msg;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_challenge_response);

	TEST_START;

	status = spdm_process_challenge_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_challenge_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_challenge_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_generate_get_measurements_request (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_measurements_request *rq = (struct spdm_get_measurements_request*) buf;
	uint8_t nonce[SPDM_NONCE_LEN] = {0};
	uint8_t *slot_id;
	int status;

	memset (buf, 0x55, sizeof (buf));

	nonce[0] = 0xaa;
	nonce[10] = 0xbb;
	nonce[20] = 0xcc;
	nonce[30] = 0xdd;
	nonce[31] = 0xee;

	TEST_START;

	status = spdm_generate_get_measurements_request (buf, sizeof (buf), 2, 4, 1, 0, nonce, 2);

	slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);

	CuAssertIntEquals (test, sizeof (struct spdm_get_measurements_request) + 1 + SPDM_NONCE_LEN,
		status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_MEASUREMENTS, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 1, rq->sig_required);
	CuAssertIntEquals (test, 0, rq->raw_bit_stream_requested);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 4, rq->measurement_operation);
	CuAssertIntEquals (test, 2, *slot_id);

	status = testing_validate_array (nonce, spdm_get_measurements_rq_nonce (rq), sizeof (nonce));
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_get_measurements_request_no_sig_required (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_measurements_request *rq = (struct spdm_get_measurements_request*) buf;
	uint8_t *slot_id;
	int status;

	memset (buf, 0x55, sizeof (buf));

	TEST_START;

	status = spdm_generate_get_measurements_request (buf, sizeof (buf), 2, 4, 0, 0, NULL, 2);

	slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);

	CuAssertIntEquals (test, sizeof (struct spdm_get_measurements_request) + 1, status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_MEASUREMENTS, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rq->sig_required);
	CuAssertIntEquals (test, 0, rq->raw_bit_stream_requested);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 4, rq->measurement_operation);
	CuAssertIntEquals (test, 2, *slot_id);
}

static void spdm_test_generate_get_measurements_request_raw_bitstream_requested (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_measurements_request *rq = (struct spdm_get_measurements_request*) buf;
	uint8_t nonce[SPDM_NONCE_LEN] = {0};
	uint8_t *slot_id;
	int status;

	memset (buf, 0x55, sizeof (buf));

	nonce[0] = 0xaa;
	nonce[10] = 0xbb;
	nonce[20] = 0xcc;
	nonce[30] = 0xdd;
	nonce[31] = 0xee;

	TEST_START;

	status = spdm_generate_get_measurements_request (buf, sizeof (buf), 2, 4, 1, 1, nonce, 2);

	slot_id = spdm_get_measurements_rq_slot_id_ptr (rq);

	CuAssertIntEquals (test, sizeof (struct spdm_get_measurements_request) + 1 + SPDM_NONCE_LEN,
		status);
	CuAssertIntEquals (test, MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM, rq->header.msg_type);
	CuAssertIntEquals (test, 0, rq->header.integrity_check);
	CuAssertIntEquals (test, 2, rq->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rq->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_REQUEST_GET_MEASUREMENTS, rq->header.req_rsp_code);
	CuAssertIntEquals (test, 1, rq->sig_required);
	CuAssertIntEquals (test, 1, rq->raw_bit_stream_requested);
	CuAssertIntEquals (test, 0, rq->reserved);
	CuAssertIntEquals (test, 4, rq->measurement_operation);
	CuAssertIntEquals (test, 2, *slot_id);

	status = testing_validate_array (nonce, spdm_get_measurements_rq_nonce (rq), sizeof (nonce));
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_generate_get_measurements_request_buf_too_small (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_measurements_request) - 1];
	uint8_t nonce[SPDM_NONCE_LEN];
	int status;

	TEST_START;

	status = spdm_generate_get_measurements_request (buf, sizeof (buf), 2, 4, 1, 0, nonce, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BUF_TOO_SMALL, status);
}

static void spdm_test_generate_get_measurements_request_null (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_measurements_request)];
	uint8_t nonce[SPDM_NONCE_LEN];
	int status;

	TEST_START;

	status = spdm_generate_get_measurements_request (NULL, sizeof (buf), 2, 4, 1, 0, nonce, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	status = spdm_generate_get_measurements_request (buf, sizeof (buf), 2, 4, 1, 0, NULL, 2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}

static void spdm_test_process_get_measurements_response (CuTest *test)
{
	uint8_t buf[sizeof (struct spdm_get_measurements_response) + 44] = {0};
	struct spdm_get_measurements_response *resp = (struct spdm_get_measurements_response*) buf;
	struct cmd_interface_msg msg;
	uint16_t *opaque_len;
	int status;

	msg.data = buf;
	msg.length = sizeof (buf);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	resp->num_measurement_indices = 2;
	resp->slot_id = 3;
	resp->reserved = 0;
	resp->number_of_blocks = 3;
	resp->measurement_record_len[0] = 3;

	opaque_len = (uint16_t*)(spdm_get_measurements_resp_nonce(resp) + SPDM_NONCE_LEN);

	*opaque_len = 2;

	TEST_START;

	status = spdm_process_get_measurements_response (&msg);
	CuAssertIntEquals (test, 0, status);
}

static void spdm_test_process_get_measurements_response_bad_length (CuTest *test)
{
	uint8_t buf[CERBERUS_PROTOCOL_MAX_PAYLOAD_PER_MSG] = {0};
	struct spdm_get_measurements_response *resp = (struct spdm_get_measurements_response*) buf;
	struct cmd_interface_msg msg;
	size_t opaque_len_offset;
	uint16_t *opaque_len;
	int status;

	msg.data = buf;
	msg.length = sizeof (struct spdm_get_measurements_response) - 1;

	TEST_START;

	status = spdm_process_get_measurements_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	resp->header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_SPDM;
	resp->header.integrity_check = 0;
	resp->header.spdm_minor_version = 2;
	resp->header.spdm_major_version = SPDM_MAJOR_VERSION;
	resp->header.req_rsp_code = SPDM_RESPONSE_GET_MEASUREMENTS;

	resp->num_measurement_indices = 2;
	resp->slot_id = 3;
	resp->reserved = 0;
	resp->number_of_blocks = 3;
	resp->measurement_record_len[0] = 3;

	opaque_len_offset = sizeof (struct spdm_get_measurements_response) +
		spdm_get_measurements_resp_measurement_record_len(resp) + SPDM_NONCE_LEN;

	opaque_len = (uint16_t*)(spdm_get_measurements_resp_nonce(resp) + SPDM_NONCE_LEN);
	*opaque_len = 2;

	msg.length = opaque_len_offset - 1;

	status = spdm_process_get_measurements_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);

	msg.length = spdm_get_measurements_resp_length (resp) - 1;

	status = spdm_process_get_measurements_response (&msg);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_BAD_LENGTH, status);
}

static void spdm_test_process_get_measurements_response_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spdm_process_get_measurements_response (NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);
}


TEST_SUITE_START (spdm_commands);

TEST (spdm_test_error_response_format);
TEST (spdm_test_get_version_request_format);
TEST (spdm_test_get_version_response_format);
TEST (spdm_test_get_capabilities_format);
TEST (spdm_test_get_capabilities_1_1_format);
TEST (spdm_test_negotiate_algorithms_request_format);
TEST (spdm_test_negotiate_algorithms_response_format);
TEST (spdm_test_get_digests_request_format);
TEST (spdm_test_get_digests_response_format);
TEST (spdm_test_get_certificate_request_format);
TEST (spdm_test_get_certificate_response_format);
TEST (spdm_test_challenge_request_format);
TEST (spdm_test_challenge_response_format);
TEST (spdm_test_get_measurements_request_format);
TEST (spdm_test_get_measurements_response_format);
TEST (spdm_test_get_spdm_response_format);
TEST (spdm_test_generate_error_response);
TEST (spdm_test_generate_error_response_with_optional_data);
TEST (spdm_test_generate_error_response_with_optional_data_too_large);
TEST (spdm_test_get_version);
TEST (spdm_test_get_version_null);
TEST (spdm_test_get_version_bad_length);
TEST (spdm_test_get_version_start_hash_fail);
TEST (spdm_test_get_version_hash_update_rq_fail);
TEST (spdm_test_get_version_hash_update_rsp_fail);
TEST (spdm_test_generate_get_version_request);
TEST (spdm_test_generate_get_version_request_buf_too_small);
TEST (spdm_test_generate_get_version_request_null);
TEST (spdm_test_process_get_version_response);
TEST (spdm_test_process_get_version_response_bad_length);
TEST (spdm_test_process_get_version_response_null);
TEST (spdm_test_get_capabilities);
TEST (spdm_test_get_capabilities_null);
TEST (spdm_test_get_capabilities_ct_too_large);
TEST (spdm_test_get_capabilities_1_1);
TEST (spdm_test_get_capabilities_unknown_device);
TEST (spdm_test_get_capabilities_hash_update_rq_fail);
TEST (spdm_test_get_capabilities_hash_update_rsp_fail);
TEST (spdm_test_generate_get_capabilities_request);
TEST (spdm_test_generate_get_capabilities_request_1_1);
TEST (spdm_test_generate_get_capabilities_request_buf_too_small);
TEST (spdm_test_generate_get_capabilities_request_1_1_buf_too_small);
TEST (spdm_test_generate_get_capabilities_request_null);
TEST (spdm_test_process_get_capabilities_response);
TEST (spdm_test_process_get_capabilities_1_1_response);
TEST (spdm_test_process_get_capabilities_response_bad_length);
TEST (spdm_test_process_get_capabilities_response_1_1_bad_length);
TEST (spdm_test_process_get_capabilities_response_null);
TEST (spdm_test_negotiate_algorithms);
TEST (spdm_test_negotiate_algorithms_null);
TEST (spdm_test_negotiate_algorithms_dmtf_measurement_specification_not_supported);
TEST (spdm_test_negotiate_algorithms_no_common_asym_algo);
TEST (spdm_test_negotiate_algorithms_no_common_hash_algo);
TEST (spdm_test_negotiate_algorithms_bad_length);
TEST (spdm_test_negotiate_algorithms_hash_update_rq_fail);
TEST (spdm_test_negotiate_algorithms_hash_update_rsp_fail);
TEST (spdm_test_generate_negotiate_algorithms_request);
TEST (spdm_test_generate_negotiate_algorithms_request_buf_too_small);
TEST (spdm_test_generate_negotiate_algorithms_request_null);
TEST (spdm_test_process_negotiate_algorithms_response);
TEST (spdm_test_process_negotiate_algorithms_response_bad_length);
TEST (spdm_test_process_negotiate_algorithms_response_null);
TEST (spdm_test_generate_get_digests_request);
TEST (spdm_test_generate_get_digests_request_buf_too_small);
TEST (spdm_test_generate_get_digests_request_null);
TEST (spdm_test_process_get_digests_response);
TEST (spdm_test_process_get_digests_response_bad_length);
TEST (spdm_test_process_get_digests_response_null);
TEST (spdm_test_generate_get_certificate_request);
TEST (spdm_test_generate_get_certificate_request_buf_too_small);
TEST (spdm_test_generate_get_certificate_request_null);
TEST (spdm_test_process_get_certificate_response);
TEST (spdm_test_process_get_certificate_response_bad_length);
TEST (spdm_test_process_get_certificate_response_null);
TEST (spdm_test_format_signature_digest);
TEST (spdm_test_format_signature_digest_sha384);
TEST (spdm_test_format_signature_digest_sha512);
TEST (spdm_test_format_signature_digest_start_hash_fail);
TEST (spdm_test_format_signature_digest_start_hash_sha384_fail);
TEST (spdm_test_format_signature_digest_start_hash_sha512_fail);
TEST (spdm_test_format_signature_digest_update_hash_prefix_fail);
TEST (spdm_test_format_signature_digest_update_hash_context_fail);
TEST (spdm_test_format_signature_digest_finish_hash_fail);
TEST (spdm_test_generate_challenge_request);
TEST (spdm_test_generate_challenge_request_buf_too_small);
TEST (spdm_test_generate_challenge_request_null);
TEST (spdm_test_process_challenge_response);
TEST (spdm_test_process_challenge_response_bad_length);
TEST (spdm_test_process_challenge_response_null);
TEST (spdm_test_generate_get_measurements_request);
TEST (spdm_test_generate_get_measurements_request_no_sig_required);
TEST (spdm_test_generate_get_measurements_request_raw_bitstream_requested);
TEST (spdm_test_generate_get_measurements_request_buf_too_small);
TEST (spdm_test_generate_get_measurements_request_null);
TEST (spdm_test_process_get_measurements_response);
TEST (spdm_test_process_get_measurements_response_bad_length);
TEST (spdm_test_process_get_measurements_response_null);

TEST_SUITE_END;
