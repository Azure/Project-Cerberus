// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "spdm/cmd_interface_spdm_responder_static.h"
#include "spdm/spdm_commands.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/spdm/spdm_transcript_manager_mock.h"


TEST_SUITE_LABEL ("cmd_interface_spdm_responder");

uint32_t cmd_interface_spdm_responder_testing_hash_priority_table[] = {
	SPDM_TPM_ALG_SHA_384,
};

uint32_t cmd_interface_spdm_responder_testing_asym_priority_table[] = {
	SPDM_TPM_ALG_ECDSA_ECC_NIST_P384,
};

uint32_t cmd_interface_spdm_responder_testing_req_asym_priority_table[] = {
	SPDM_TPM_ALG_ECDSA_ECC_NIST_P384,
};

uint32_t cmd_interface_spdm_responder_testing_dhe_priority_table[] = {
	SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1,
};

uint32_t cmd_interface_spdm_responder_testing_aead_priority_table[] = {
	SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM,
};

uint32_t cmd_interface_spdm_responder_testing_key_schedule_priority_table[] = {
	SPDM_ALG_KEY_SCHEDULE_HMAC_HASH,
};

uint32_t cmd_interface_spdm_responder_testing_measurement_hash_priority_table[] = {
	SPDM_MEAS_RSP_TPM_ALG_SHA_384,
};

uint32_t cmd_interface_spdm_responder_testing_measurement_spec_priority_table[] = {
	SPDM_MEASUREMENT_SPEC_DMTF,
};

uint32_t cmd_interface_spdm_responder_testing_other_params_support_priority_table[] = {
	SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1,
	SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_0,
	SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_NONE
};


/**
 * Dependencies for testing.
 */
struct cmd_interface_spdm_responder_testing {
	struct cmd_interface_spdm_responder spdm_responder;				/**< The SPDM responder being tested. */
	struct spdm_state spdm_responder_state;							/**< The SPDM responder state. */
	struct spdm_transcript_manager_state state;						/**< The transcript manager state. */
	struct spdm_transcript_manager_mock transcript_manager_mock;	/**< The transcript manager. */
	struct spdm_transcript_manager_state transcript_manager_state; 	/**< The transcript manager state. */
	struct hash_engine_mock hash_engine_mock;						/**< Mock hash engine for the responder. */
	struct spdm_version_num_entry version_num[SPDM_MAX_MINOR_VERSION];	/**< Version number entries. */
	struct spdm_device_capability local_capabilities;				/**< Local capabilities. */
	struct spdm_local_device_algorithms local_algorithms;			/**< Local algorithms. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
void cmd_interface_spdm_responder_testing_init_dependencies (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	int status;
	struct spdm_version_num_entry version_num[SPDM_MAX_MINOR_VERSION] =
		{ {0, 0, 1, 1}, {0, 0, 2, 1} };

	memcpy (testing->version_num, version_num, sizeof (version_num));

	status = spdm_transcript_manager_mock_init (&testing->transcript_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&testing->hash_engine_mock);
	CuAssertIntEquals (test, 0, status);

	/* Set the default capabilities. */
	memset (&testing->local_capabilities, 0, sizeof (testing->local_capabilities));
	testing->local_capabilities.ct_exponent = SPDM_MAX_CT_EXPONENT;
	testing->local_capabilities.flags.cache_cap = 0;
	testing->local_capabilities.flags.cert_cap = 1;
	testing->local_capabilities.flags.chal_cap = 0;
	testing->local_capabilities.flags.meas_cap = 1;
	testing->local_capabilities.flags.meas_fresh_cap = 0;
	testing->local_capabilities.flags.encrypt_cap = 1;
	testing->local_capabilities.flags.mac_cap = 1;
	testing->local_capabilities.flags.mut_auth_cap = 0;
	testing->local_capabilities.flags.key_ex_cap = 1;
	testing->local_capabilities.flags.psk_cap = SPDM_PSK_NOT_SUPPORTED;
	testing->local_capabilities.flags.encap_cap = 0;
	testing->local_capabilities.flags.hbeat_cap = 0;
	testing->local_capabilities.flags.key_upd_cap = 0;
	testing->local_capabilities.flags.handshake_in_the_clear_cap = 0;
	testing->local_capabilities.flags.pub_key_id_cap = 0;
	testing->local_capabilities.flags.chunk_cap = 0;
	testing->local_capabilities.flags.alias_cert_cap = 0;
	testing->local_capabilities.data_transfer_size = DOE_MESSAGE_MAX_SIZE_IN_BYTES;
	testing->local_capabilities.max_spdm_msg_size = DOE_MESSAGE_MAX_SIZE_IN_BYTES;
	testing->local_capabilities.flags.reserved = 0;
	testing->local_capabilities.flags.reserved2 = 0;

	/* Set the default algorithms. */
	memset (&testing->local_algorithms, 0, sizeof (testing->local_algorithms));
	testing->local_algorithms.device_algorithms.base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
	testing->local_algorithms.device_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;
	testing->local_algorithms.device_algorithms.measurement_hash_algo = SPDM_MEAS_RSP_TPM_ALG_SHA_384;
	testing->local_algorithms.device_algorithms.measurement_spec = SPDM_MEASUREMENT_SPEC_DMTF;
	testing->local_algorithms.device_algorithms.aead_cipher_suite = SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM;
	testing->local_algorithms.device_algorithms.dhe_named_group = SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1;
	testing->local_algorithms.device_algorithms.req_base_asym_alg = SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
	testing->local_algorithms.device_algorithms.key_schedule = SPDM_ALG_KEY_SCHEDULE_HMAC_HASH;
	testing->local_algorithms.device_algorithms.other_params_support.opaque_data_format =
		SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

	/* Set the algorithm priorities. */
	testing->local_algorithms.algorithms_priority_table.aead_priority_table =
			cmd_interface_spdm_responder_testing_aead_priority_table;
	testing->local_algorithms.algorithms_priority_table.aead_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_aead_priority_table);

	testing->local_algorithms.algorithms_priority_table.asym_priority_table =
		cmd_interface_spdm_responder_testing_asym_priority_table;
	testing->local_algorithms.algorithms_priority_table.asym_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_asym_priority_table);

	testing->local_algorithms.algorithms_priority_table.dhe_priority_table =
			cmd_interface_spdm_responder_testing_dhe_priority_table;
	testing->local_algorithms.algorithms_priority_table.dhe_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_dhe_priority_table);

	testing->local_algorithms.algorithms_priority_table.hash_priority_table =
			cmd_interface_spdm_responder_testing_hash_priority_table;
	testing->local_algorithms.algorithms_priority_table.hash_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_hash_priority_table);

	testing->local_algorithms.algorithms_priority_table.key_schedule_priority_table =
			cmd_interface_spdm_responder_testing_key_schedule_priority_table;
	testing->local_algorithms.algorithms_priority_table.key_schedule_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_key_schedule_priority_table);

	testing->local_algorithms.algorithms_priority_table.measurement_spec_priority_table =
			cmd_interface_spdm_responder_testing_measurement_spec_priority_table;
	testing->local_algorithms.algorithms_priority_table.measurement_spec_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_measurement_spec_priority_table);

	testing->local_algorithms.algorithms_priority_table.other_params_support_priority_table =
			cmd_interface_spdm_responder_testing_other_params_support_priority_table;
	testing->local_algorithms.algorithms_priority_table.other_params_support_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_other_params_support_priority_table);

	testing->local_algorithms.algorithms_priority_table.req_asym_priority_table =
			cmd_interface_spdm_responder_testing_req_asym_priority_table;
	testing->local_algorithms.algorithms_priority_table.req_asym_priority_table_count =
		ARRAY_SIZE (cmd_interface_spdm_responder_testing_req_asym_priority_table);

}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
void cmd_interface_spdm_responder_testing_release_dependencies (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	int status;
	status = spdm_transcript_manager_mock_validate_and_release (
		&testing->transcript_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&testing->hash_engine_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the SPDM responder for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void cmd_interface_spdm_responder_testing_init (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	int status;

	cmd_interface_spdm_responder_testing_init_dependencies (test, testing);

	status = cmd_interface_spdm_responder_init (&testing->spdm_responder,
		&testing->spdm_responder_state, &testing->transcript_manager_mock.base,
		&testing->hash_engine_mock.base, testing->version_num, ARRAY_SIZE (testing->version_num),
		&testing->local_capabilities, &testing->local_algorithms);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release SPDM responder and validate all mocks.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void cmd_interface_spdm_responder_testing_release (CuTest *test,
	struct cmd_interface_spdm_responder_testing *testing)
{
	cmd_interface_spdm_responder_deinit (&testing->spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, testing);
}

/*******************
 * Test cases
 *******************/

static void cmd_interface_spdm_responder_test_static_init (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, spdm_responder.base.process_response);
	CuAssertPtrNotNull (test, spdm_responder.base.generate_error_packet);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			NULL, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	struct cmd_interface_spdm_responder spdm_responder2 =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, NULL,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	struct cmd_interface_spdm_responder spdm_responder3 =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			NULL, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	struct cmd_interface_spdm_responder spdm_responder4 =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, NULL, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	struct cmd_interface_spdm_responder spdm_responder5 =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, 0,
			&testing.local_capabilities, &testing.local_algorithms);

	struct cmd_interface_spdm_responder spdm_responder6 =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			NULL, &testing.local_algorithms);

	struct cmd_interface_spdm_responder spdm_responder7 =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, NULL);

	TEST_START;

	/* state = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder2);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder3);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder4);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num_count = 0 */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder5);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder6);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder7);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_incompatible_capabilities (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.flags.key_ex_cap = 1;
	testing.local_capabilities.flags.mac_cap = 0;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INCOMPATIBLE_CAPABILITIES, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_ct_exponent_gt_max (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.ct_exponent = SPDM_MAX_CT_EXPONENT + 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_data_transfer_size_lt_min_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size = SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2 - 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_data_transfer_size_gt_max_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size =
		testing.local_capabilities.max_spdm_msg_size + 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_data_transfer_size_ne_max_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.flags.chunk_cap = 0;
	testing.local_capabilities.max_spdm_msg_size =
		testing.local_capabilities.data_transfer_size + 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (
			&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
			&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
			&testing.local_capabilities, &testing.local_algorithms);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_init (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		&testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_response);
	CuAssertPtrNotNull (test, testing.spdm_responder.base.generate_error_packet);

	cmd_interface_spdm_responder_deinit (&testing.spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	/* spdm_responder = NULL */
	status = cmd_interface_spdm_responder_init (NULL, &testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, &testing.hash_engine_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num), &testing.local_capabilities,
		&testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* state = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder, NULL,
		&testing.transcript_manager_mock.base, &testing.hash_engine_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num), &testing.local_capabilities,
		&testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, NULL, &testing.hash_engine_mock.base,
		testing.version_num, ARRAY_SIZE (testing.version_num), &testing.local_capabilities,
		&testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, NULL,
		testing.version_num, ARRAY_SIZE (testing.version_num), &testing.local_capabilities,
		&testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, NULL, ARRAY_SIZE (testing.version_num),
		&testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num_count = 0 */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, 0, &testing.local_capabilities,
		&testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		NULL, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		&testing.local_capabilities, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init_incompatible_capabilities (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.flags.key_ex_cap = 1;
	testing.local_capabilities.flags.mac_cap = 0;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		 &testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INCOMPATIBLE_CAPABILITIES, status);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_init_ct_exponent_gt_max (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.ct_exponent = SPDM_MAX_CT_EXPONENT + 1;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		 &testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_init_data_transfer_size_lt_min_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size = SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2 - 1;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		 &testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_init_data_transfer_size_gt_max_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size =
		testing.local_capabilities.max_spdm_msg_size + 1;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		 &testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_init_data_transfer_size_ne_max_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.flags.chunk_cap = 0;
	testing.local_capabilities.max_spdm_msg_size =
		testing.local_capabilities.data_transfer_size + 1;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base,
		&testing.hash_engine_mock.base, testing.version_num, ARRAY_SIZE (testing.version_num),
		 &testing.local_capabilities, &testing.local_algorithms);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies(test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_version (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	uint8_t expected_buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct spdm_get_version_request rq = {0};
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) buf;
	struct spdm_get_version_response *expected_rsp =
		(struct spdm_get_version_response*) expected_buf;
	struct cmd_interface_msg request;
	size_t version_count = SPDM_MAX_MINOR_VERSION - SPDM_MIN_MINOR_VERSION + 1;
	size_t version_length = version_count * sizeof (struct spdm_version_num_entry);
	struct spdm_version_num_entry *version_num =
		spdm_get_version_resp_version_table (expected_rsp);
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	resp = (struct spdm_get_version_response*) buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request);
	request.length = request.payload_length;

	rq.header.spdm_minor_version = 0;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.req_rsp_code = SPDM_REQUEST_GET_VERSION;
	rq.reserved = 0;
	rq.reserved2 = 0;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_version_request));

	expected_rsp->header.spdm_minor_version = 0;
	expected_rsp->header.spdm_major_version = 1;
	expected_rsp->header.req_rsp_code = SPDM_RESPONSE_GET_VERSION;
	expected_rsp->reserved = 0;
	expected_rsp->reserved2 = 0;
	expected_rsp->reserved3 = 0;
	expected_rsp->version_num_entry_count = version_count;
	memcpy (version_num, testing.version_num,
		sizeof (struct spdm_version_num_entry) * ARRAY_SIZE (testing.version_num));

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset,
		&testing.transcript_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_version_request)),
		MOCK_ARG (sizeof (struct spdm_get_version_request)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (expected_rsp, sizeof (struct spdm_get_version_request) +
			version_length),
		MOCK_ARG (sizeof (struct spdm_get_version_response) + version_length),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (*resp) + version_length, request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, 0, resp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, resp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_VERSION, resp->header.req_rsp_code);
	CuAssertIntEquals (test, 0, resp->reserved);
	CuAssertIntEquals (test, 0, resp->reserved2);
	CuAssertIntEquals (test, 0, resp->reserved3);
	CuAssertIntEquals (test, 2, resp->version_num_entry_count);

	version_num = spdm_get_version_resp_version_table (resp);
	status = memcmp (version_num, testing.version_num,
		sizeof (struct spdm_version_num_entry) * ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_version_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request) - 1;
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;
	rq->reserved = 0;
	rq->reserved2 = 0;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, error_response->header.spdm_major_version);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_capabilities (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg request;
	struct spdm_get_capabilities rq = {0};
	struct spdm_get_capabilities *resp = (struct spdm_get_capabilities*) buf;
	int status;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_device_capability *local_capabilities;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;
	local_capabilities = &testing.local_capabilities;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_capabilities);
	request.length = request.payload_length;

	rq.base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.base_capabilities.header.spdm_minor_version = 2;
	rq.base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;
	rq.base_capabilities.ct_exponent = local_capabilities->ct_exponent;
	rq.base_capabilities.flags = local_capabilities->flags;
	rq.data_transfer_size = local_capabilities->data_transfer_size;
	rq.max_spdm_msg_size = local_capabilities->max_spdm_msg_size;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_capabilities));

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_VERSION;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_get_capabilities)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_get_capabilities), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, resp, request.payload);
	CuAssertIntEquals (test, 2, resp->base_capabilities.header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, resp->base_capabilities.header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_CAPABILITIES,
		resp->base_capabilities.header.req_rsp_code);
	CuAssertIntEquals (test, 0, resp->base_capabilities.reserved);
	CuAssertIntEquals (test, 0, resp->base_capabilities.reserved2);
	CuAssertIntEquals (test, 0, resp->base_capabilities.reserved3);
	CuAssertIntEquals (test, 0, resp->base_capabilities.reserved4);
	CuAssertIntEquals (test, local_capabilities->ct_exponent, resp->base_capabilities.ct_exponent);
	CuAssertIntEquals (test, local_capabilities->data_transfer_size, resp->data_transfer_size);
	CuAssertIntEquals (test, local_capabilities->max_spdm_msg_size, resp->max_spdm_msg_size);

	status = memcmp (&local_capabilities->flags, &resp->base_capabilities.flags,
		sizeof (struct spdm_get_capabilities_flags_format));
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_capabilities_fail (CuTest *test)
{
uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg request;
	struct spdm_get_capabilities rq = {0};
	int status;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_device_capability *local_capabilities;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;
	local_capabilities = &testing.local_capabilities;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_capabilities) - 1;
	request.length = request.payload_length;

	rq.base_capabilities.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.base_capabilities.header.spdm_minor_version = 2;
	rq.base_capabilities.header.req_rsp_code = SPDM_REQUEST_GET_CAPABILITIES;
	rq.base_capabilities.ct_exponent = local_capabilities->ct_exponent;
	rq.base_capabilities.flags = local_capabilities->flags;
	rq.data_transfer_size = local_capabilities->data_transfer_size;
	rq.max_spdm_msg_size = local_capabilities->max_spdm_msg_size;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_capabilities));

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_VERSION;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_negotiate_algorithms (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	uint8_t rq_copy[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_negotiate_algorithms_request *rq =
		(struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_negotiate_algorithms_response *rsp =
		(struct spdm_negotiate_algorithms_response*) buf;
	struct spdm_negotiate_algorithms_response_no_ext_alg *resp_no_ext_alg = 
		(struct spdm_negotiate_algorithms_response_no_ext_alg*) rsp;
	struct spdm_algorithm_request *algstruct_table;
	struct cmd_interface_msg request;
	int status;
	size_t req_length = sizeof (struct spdm_negotiate_algorithms_request) +
		(sizeof (struct spdm_algorithm_request) * 4);
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_local_device_algorithms *local_algorithms;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;
	local_algorithms = &testing.local_algorithms;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = req_length;
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 2;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;
	rq->num_alg_structure_tables = 4;
	rq->reserved = 0;
	rq->length = req_length;
	rq->measurement_specification = local_algorithms->device_algorithms.measurement_spec;
	rq->other_params_support.opaque_data_format = 
		local_algorithms->device_algorithms.other_params_support.opaque_data_format;
	rq->base_asym_algo = local_algorithms->device_algorithms.base_asym_algo;
	rq->base_hash_algo = local_algorithms->device_algorithms.base_hash_algo;
	rq->ext_asym_count = 0;
	rq->ext_hash_count = 0;
	rq->reserved4 = 0;

	algstruct_table = spdm_negotiate_algorithms_req_algstruct_table (rq);
	algstruct_table[0].fixed_alg_count = 2;
	algstruct_table[0].ext_alg_count = 0;
	algstruct_table[0].alg_type = SPDM_ALG_REQ_STRUCT_ALG_TYPE_DHE;
	algstruct_table[0].alg_supported = SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1;

	algstruct_table[1].fixed_alg_count = 2;
	algstruct_table[1].ext_alg_count = 0;
	algstruct_table[1].alg_type = SPDM_ALG_REQ_STRUCT_ALG_TYPE_AEAD;
	algstruct_table[1].alg_supported = local_algorithms->device_algorithms.aead_cipher_suite;

	algstruct_table[2].fixed_alg_count = 2;
	algstruct_table[2].ext_alg_count = 0;
	algstruct_table[2].alg_type = SPDM_ALG_REQ_STRUCT_ALG_TYPE_REQ_BASE_ASYM_ALG;
	algstruct_table[2].alg_supported = local_algorithms->device_algorithms.req_base_asym_alg;

	algstruct_table[3].fixed_alg_count = 2;
	algstruct_table[3].ext_alg_count = 0;
	algstruct_table[3].alg_type = SPDM_ALG_REQ_STRUCT_ALG_TYPE_KEY_SCHEDULE;
	algstruct_table[3].alg_supported = local_algorithms->device_algorithms.key_schedule;

	memset (rq->reserved3, 0, sizeof (rq->reserved3));
	memcpy (rq_copy, rq, rq->length);

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_AFTER_CAPABILITIES;
	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (&rq_copy, req_length),
		MOCK_ARG (req_length), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update,
		&testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA), MOCK_ARG_PTR_PTR_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_negotiate_algorithms_response_no_ext_alg)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.set_hash_algo,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response_no_ext_alg),
		request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_NEGOTIATE_ALGORITHMS, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 4, rsp->num_alg_structure_tables);
	CuAssertIntEquals (test, 0, rsp->reserved);
	CuAssertIntEquals (test, sizeof (struct spdm_negotiate_algorithms_response_no_ext_alg),
		rsp->length);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.measurement_spec, rsp->measurement_specification);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.other_params_support.opaque_data_format,
		rsp->other_params_selection.opaque_data_format);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.measurement_hash_algo, rsp->measurement_hash_algo);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.base_asym_algo, rsp->base_asym_sel);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.base_hash_algo, rsp->base_hash_sel);

	CuAssertIntEquals (test, 0, rsp->ext_asym_sel_count);
	CuAssertIntEquals (test, 0, rsp->ext_hash_sel_count);
	CuAssertIntEquals (test, 0, rsp->reserved4);

	CuAssertIntEquals (test, SPDM_ALG_REQ_STRUCT_ALG_TYPE_DHE, 
		resp_no_ext_alg->algstruct_table[0].alg_type);
	CuAssertIntEquals (test, 2, resp_no_ext_alg->algstruct_table[0].fixed_alg_count);
	CuAssertIntEquals (test, 0, resp_no_ext_alg->algstruct_table[0].ext_alg_count);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.dhe_named_group,
		resp_no_ext_alg->algstruct_table[0].alg_supported);

	CuAssertIntEquals (test, 2, resp_no_ext_alg->algstruct_table[1].fixed_alg_count);
	CuAssertIntEquals (test, 0, resp_no_ext_alg->algstruct_table[1].ext_alg_count);
	CuAssertIntEquals (test, SPDM_ALG_REQ_STRUCT_ALG_TYPE_AEAD,
		resp_no_ext_alg->algstruct_table[1].alg_type);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.aead_cipher_suite,
		resp_no_ext_alg->algstruct_table[1].alg_supported);

	CuAssertIntEquals (test, 2, resp_no_ext_alg->algstruct_table[2].fixed_alg_count);
	CuAssertIntEquals (test, 0, resp_no_ext_alg->algstruct_table[2].ext_alg_count);
	CuAssertIntEquals (test, SPDM_ALG_REQ_STRUCT_ALG_TYPE_REQ_BASE_ASYM_ALG,
		resp_no_ext_alg->algstruct_table[2].alg_type);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.req_base_asym_alg,
		resp_no_ext_alg->algstruct_table[2].alg_supported);

	CuAssertIntEquals (test, 2, resp_no_ext_alg->algstruct_table[3].fixed_alg_count);
	CuAssertIntEquals (test, 0, resp_no_ext_alg->algstruct_table[3].ext_alg_count);
	CuAssertIntEquals (test, SPDM_ALG_REQ_STRUCT_ALG_TYPE_KEY_SCHEDULE, 
		resp_no_ext_alg->algstruct_table[3].alg_type);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.key_schedule, 
		resp_no_ext_alg->algstruct_table[3].alg_supported) ;

	CuAssertIntEquals (test, local_algorithms->device_algorithms.aead_cipher_suite,
		spdm_state->connection_info.peer_algorithms.aead_cipher_suite);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.base_asym_algo,
		spdm_state->connection_info.peer_algorithms.base_asym_algo);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.base_hash_algo,
		spdm_state->connection_info.peer_algorithms.base_hash_algo);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.dhe_named_group,
		spdm_state->connection_info.peer_algorithms.dhe_named_group);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.key_schedule,
		spdm_state->connection_info.peer_algorithms.key_schedule);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.measurement_hash_algo,
		spdm_state->connection_info.peer_algorithms.measurement_hash_algo);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.measurement_spec,
		spdm_state->connection_info.peer_algorithms.measurement_spec);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.other_params_support.opaque_data_format,
		spdm_state->connection_info.peer_algorithms.other_params_support.opaque_data_format);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.req_base_asym_alg,
		spdm_state->connection_info.peer_algorithms.req_base_asym_alg);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_negotiate_algorithms_fail (CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_negotiate_algorithms_request *rq =
		(struct spdm_negotiate_algorithms_request*) buf;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_negotiate_algorithms_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;

	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;
	rq->header.req_rsp_code = SPDM_REQUEST_NEGOTIATE_ALGORITHMS;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNEXPECTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	/* intf = NULL */
	status = testing.spdm_responder.base.process_request (NULL,
		(struct cmd_interface_msg*) (0xDEADBEEF));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* request = NULL */
	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_short_payload (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_protocol_header) - 1;
	request.length = request.payload_length;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_unsupported_major_version (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request);
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION + 1;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_VERSION;
	rq->reserved = 0;
	rq->reserved2 = 0;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_NOT_INTEROPERABLE, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_unsupported_request_code (
	CuTest *test)
{
	uint8_t buf[DOE_MESSAGE_MAX_SIZE_IN_BYTES];
	struct spdm_get_version_request *rq = (struct spdm_get_version_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_version_request);
	request.length = request.payload_length;

	rq->header.spdm_minor_version = 0;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.req_rsp_code = -1;
	rq->reserved = 0;
	rq->reserved2 = 0;

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNSUPPORTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, error_response->header.spdm_major_version);
	CuAssertIntEquals (test, 0, error_response->header.spdm_minor_version);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_response (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	status = testing.spdm_responder.base.process_response (
		(const struct cmd_interface*)(0xDEADBEEF), (struct cmd_interface_msg*)(0xBAADF00D));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_generate_error_packet (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	status = testing.spdm_responder.base.generate_error_packet (
		(const struct cmd_interface*)(0xDEADBEEF), (struct cmd_interface_msg*)(0xBAADF00D),
		-1, -1, -1);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

TEST_SUITE_START (cmd_interface_spdm_responder);

TEST (cmd_interface_spdm_responder_test_static_init);
TEST (cmd_interface_spdm_responder_test_static_init_invalid_arg);
TEST (cmd_interface_spdm_responder_test_static_init_incompatible_capabilities);
TEST (cmd_interface_spdm_responder_test_static_init_ct_exponent_gt_max);
TEST (cmd_interface_spdm_responder_test_static_init_data_transfer_size_lt_min_size);
TEST (cmd_interface_spdm_responder_test_static_init_data_transfer_size_gt_max_size);
TEST (cmd_interface_spdm_responder_test_static_init_data_transfer_size_ne_max_size);
TEST (cmd_interface_spdm_responder_test_init);
TEST (cmd_interface_spdm_responder_test_init_invalid_arg);
TEST (cmd_interface_spdm_responder_test_init_incompatible_capabilities);
TEST (cmd_interface_spdm_responder_test_init_ct_exponent_gt_max);
TEST (cmd_interface_spdm_responder_test_init_data_transfer_size_lt_min_size);
TEST (cmd_interface_spdm_responder_test_init_data_transfer_size_gt_max_size);
TEST (cmd_interface_spdm_responder_test_init_data_transfer_size_ne_max_size);
TEST (cmd_interface_spdm_responder_test_process_request_get_version);
TEST (cmd_interface_spdm_responder_test_process_request_get_version_fail);
TEST (cmd_interface_spdm_responder_test_process_request_get_capabilities);
TEST (cmd_interface_spdm_responder_test_process_request_get_capabilities_fail);
TEST (cmd_interface_spdm_responder_test_process_request_negotiate_algorithms);
TEST (cmd_interface_spdm_responder_test_process_request_negotiate_algorithms_fail);
TEST (cmd_interface_spdm_responder_test_process_request_invalid_arg);
TEST (cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_short_payload);
TEST (cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_unsupported_major_version);
TEST (cmd_interface_spdm_responder_test_process_request_unsupported_request_code);
TEST (cmd_interface_spdm_responder_test_process_response);
TEST (cmd_interface_spdm_responder_test_generate_error_packet);

TEST_SUITE_END;



