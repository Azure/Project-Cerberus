// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "spdm/spdm_secure_session_manager_static.h"
#include "spdm/spdm_commands.h"
#include "testing/mock/spdm/spdm_transcript_manager_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/aes_mock.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/crypto/ecc_testing.h"


TEST_SUITE_LABEL ("spdm_secure_session_manager");

/**
 * Dependencies for testing.
 */
struct spdm_secure_session_manager_testing {
	struct spdm_secure_session_manager session_manager;				/**< The session manager being tested. */
	struct spdm_secure_session_manager_state state;					/**< The session manager state. */
	struct spdm_transcript_manager_mock transcript_manager_mock;	/**< The transcript manager. */
	struct spdm_secure_session_manager_state transcript_manager_state; 	/**< The transcript manager state. */
	struct hash_engine_mock hash_engine_mock;						/**< Mock hash engine for the responder. */
	struct spdm_device_capability local_capabilities;				/**< Local capabilities. */
	struct spdm_local_device_algorithms local_algorithms;			/**< Local algorithms. */
	struct ecc_engine_mock ecc_mock;								/**< Mock ECC engine. */
	struct rng_engine_mock rng_mock;								/**< Mock RNG engine. */
	struct aes_engine_mock aes_mock;								/**< Mock AES engine. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to initialize.
 */
static void spdm_secure_session_manager_testing_init_dependencies (CuTest *test,
	struct spdm_secure_session_manager_testing *testing)
{
	int status;

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
	testing->local_capabilities.flags.alias_cert_cap = 1;
	testing->local_capabilities.data_transfer_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	testing->local_capabilities.max_spdm_msg_size = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;
	testing->local_capabilities.flags.reserved = 0;
	testing->local_capabilities.flags.reserved2 = 0;

	/* Set the default algorithms. */
	memset (&testing->local_algorithms, 0, sizeof (testing->local_algorithms));
	testing->local_algorithms.device_algorithms.base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
	testing->local_algorithms.device_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;
	testing->local_algorithms.device_algorithms.measurement_hash_algo
		= SPDM_MEAS_RSP_TPM_ALG_SHA_384;
	testing->local_algorithms.device_algorithms.measurement_spec = SPDM_MEASUREMENT_SPEC_DMTF;
	testing->local_algorithms.device_algorithms.aead_cipher_suite =
		SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM;
	testing->local_algorithms.device_algorithms.dhe_named_group =
		SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1;
	testing->local_algorithms.device_algorithms.req_base_asym_alg =
		SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
	testing->local_algorithms.device_algorithms.key_schedule = SPDM_ALG_KEY_SCHEDULE_HMAC_HASH;
	testing->local_algorithms.device_algorithms.other_params_support.opaque_data_format =
			SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

	// /* Set the algorithm priorities. */
	// testing->local_algorithms.algorithms_priority_table.aead_priority_table =
	// 		spdm_command_testing_aead_priority_table;
	// testing->local_algorithms.algorithms_priority_table.aead_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_aead_priority_table);

	// testing->local_algorithms.algorithms_priority_table.asym_priority_table =
	// 	spdm_command_testing_asym_priority_table;
	// testing->local_algorithms.algorithms_priority_table.asym_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_asym_priority_table);

	// testing->local_algorithms.algorithms_priority_table.dhe_priority_table =
	// 		spdm_command_testing_dhe_priority_table;
	// testing->local_algorithms.algorithms_priority_table.dhe_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_dhe_priority_table);

	// testing->local_algorithms.algorithms_priority_table.hash_priority_table =
	// 		spdm_command_testing_hash_priority_table;
	// testing->local_algorithms.algorithms_priority_table.hash_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_hash_priority_table);

	// testing->local_algorithms.algorithms_priority_table.key_schedule_priority_table =
	// 		spdm_command_testing_key_schedule_priority_table;
	// testing->local_algorithms.algorithms_priority_table.key_schedule_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_key_schedule_priority_table);

	// testing->local_algorithms.algorithms_priority_table.measurement_spec_priority_table =
	// 		spdm_command_testing_measurement_spec_priority_table;
	// testing->local_algorithms.algorithms_priority_table.measurement_spec_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_measurement_spec_priority_table);

	// testing->local_algorithms.algorithms_priority_table.other_params_support_priority_table =
	// 		spdm_command_testing_other_params_support_priority_table;
	// testing->local_algorithms.algorithms_priority_table.other_params_support_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_other_params_support_priority_table);

	// testing->local_algorithms.algorithms_priority_table.req_asym_priority_table =
	// 		spdm_command_testing_req_asym_priority_table;
	// testing->local_algorithms.algorithms_priority_table.req_asym_priority_table_count =
	// 	ARRAY_SIZE (spdm_command_testing_req_asym_priority_table);
	
	status = ecc_mock_init (&testing->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_init (&testing->aes_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all dependencies for testing.
 *
 * @param test The test framework.
 * @param testing Testing dependencies to release.
 */
static void spdm_secure_session_manager_testing_release_dependencies (CuTest *test,
	struct spdm_secure_session_manager_testing *testing)
{
	int status;

	status = spdm_transcript_manager_mock_validate_and_release (&testing->transcript_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&testing->hash_engine_mock);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&testing->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_validate_and_release (&testing->aes_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the session manager for testing.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to initialize.
 */
static void spdm_secure_session_manager_testing_init (CuTest *test,
	struct spdm_secure_session_manager_testing *testing)
{
	int status;

	spdm_secure_session_manager_testing_init_dependencies (test, testing);

	status = spdm_secure_session_manager_init (&testing->session_manager, &testing->state,
		&testing->local_capabilities,
		(const struct spdm_device_algorithms*) &testing->local_algorithms,
		&testing->aes_mock.base, &testing->hash_engine_mock.base, &testing->rng_mock.base,
		&testing->ecc_mock.base, &testing->transcript_manager_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release session manager and validate all mocks.
 *
 * @param test		The test framework.
 * @param testing	Testing dependencies to release.
 */
static void spdm_secure_session_manager_testing_release (CuTest *test,
	struct spdm_secure_session_manager_testing *testing)
{
	spdm_secure_session_manager_release (&testing->session_manager);

	spdm_secure_session_manager_testing_release_dependencies (test, testing);
}

/*******************
 * Test cases
 *******************/

static void spdm_secure_session_manager_test_static_init (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;

	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	const struct spdm_secure_session_manager session_manager = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);

	status = spdm_secure_session_manager_init_state (&session_manager);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, session_manager.create_session);
	CuAssertPtrNotNull (test, session_manager.release_session);
	CuAssertPtrNotNull (test, session_manager.get_session);
	CuAssertPtrNotNull (test, session_manager.set_session_state);
	CuAssertPtrNotNull (test, session_manager.reset);
	CuAssertPtrNotNull (test, session_manager.generate_shared_secret);
	CuAssertPtrNotNull (test, session_manager.generate_session_handshake_keys);

	spdm_secure_session_manager_release (&session_manager);

	spdm_secure_session_manager_testing_release_dependencies (test, &testing);
}

static void spdm_secure_session_manager_test_static_init_invalid_params (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;

	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	/* session_manager = NULL */
	status = spdm_secure_session_manager_init_state (NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* state_ptr = NULL */
	const struct spdm_secure_session_manager session_manager = spdm_secure_session_manager_static_init (
		NULL, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	const struct spdm_secure_session_manager session_manager2 = spdm_secure_session_manager_static_init (
		&testing.state, NULL,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager2);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	const struct spdm_secure_session_manager session_manager3 = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		NULL, &testing.aes_mock.base, &testing.hash_engine_mock.base, &testing.rng_mock.base,
		&testing.ecc_mock.base, &testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager3);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* aes_engine = NULL */
	const struct spdm_secure_session_manager session_manager4 = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, NULL,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager4);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	const struct spdm_secure_session_manager session_manager5 = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms,  &testing.aes_mock.base,
		NULL, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager5);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* rng_engine = NULL */
	const struct spdm_secure_session_manager session_manager6 = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms,  &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager6);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* ecc_engine = NULL */
	const struct spdm_secure_session_manager session_manager7 = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms,  &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, NULL,
		&testing.transcript_manager_mock.base);
	status = spdm_secure_session_manager_init_state (&session_manager7);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	const struct spdm_secure_session_manager session_manager8 = spdm_secure_session_manager_static_init (
		&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms,  &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		NULL);
	status = spdm_secure_session_manager_init_state (&session_manager8);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release_dependencies (test, &testing);
}

static void spdm_secure_session_manager_test_init (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;

	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, testing.session_manager.create_session);
	CuAssertPtrNotNull (test, testing.session_manager.release_session);
	CuAssertPtrNotNull (test, testing.session_manager.get_session);
	CuAssertPtrNotNull (test, testing.session_manager.set_session_state);
	CuAssertPtrNotNull (test, testing.session_manager.reset);
	CuAssertPtrNotNull (test, testing.session_manager.generate_shared_secret);
	CuAssertPtrNotNull (test, testing.session_manager.generate_session_handshake_keys);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_init_invalid_params (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;

	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	/* session_manager = NULL */
	status = spdm_secure_session_manager_init (NULL, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* state = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, NULL,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		NULL, (const struct spdm_device_algorithms*) &testing.local_algorithms,
		&testing.aes_mock.base, &testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities, NULL, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* aes_engine = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, NULL,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		NULL, NULL, &testing.ecc_mock.base, &testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* ecc_engine = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, NULL, &testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base, NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release_dependencies (test, &testing);
}

static void spdm_secure_session_manager_test_release_null (CuTest *test)
{
	TEST_START;
	spdm_secure_session_manager_release (NULL);
}

static void spdm_secure_session_manager_test_create_session (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	struct spdm_secure_session *session = session_manager->create_session (session_manager,
		session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_invalid_params (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	/* session_manager = NULL */
	session = session_manager->create_session (NULL, session_id, false, &connection_info);
	CuAssertPtrEquals (test, NULL, session);

	/* session_id = SPDM_INVALID_SESSION_ID */
	session = session_manager->create_session (session_manager, 0, false, &connection_info);
	CuAssertPtrEquals (test, NULL, session);

	/* connection_info = NULL */
	session = session_manager->create_session (session_manager, session_id, false, NULL);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_count_gt_max (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	session_manager->state->current_session_count = SPDM_MAX_SESSION_COUNT;
	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_duplicate_session (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	session_manager->state->current_session_count = 0;
	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_release_session (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	
	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_release_session_invalid_params (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	/* session_manager = NULL */
	session_manager->release_session (NULL, session_id);

	/* session_id = SPDM_INVALID_SESSION_ID */
	session_manager->release_session (session_manager, SPDM_INVALID_SESSION_ID);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_get_session (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session, *session2;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	session2 = session_manager->get_session (session_manager, session_id);
	CuAssertPtrNotNull (test, session);

	CuAssertPtrEquals (test, session, session2);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_get_session_invalid_param (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	/* session_manager = NULL */
	session = session_manager->get_session (NULL, session_id);
	CuAssertPtrEquals (test, NULL, session);

	/* session_id = SPDM_INVALID_SESSION_ID */
	session = session_manager->get_session (session_manager, SPDM_INVALID_SESSION_ID);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_get_session_no_session (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	session = session_manager->get_session (session_manager, session_id);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_set_session_state (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_NOT_STARTED, session->session_state);

	session_manager->set_session_state (session_manager, session_id, SPDM_SESSION_STATE_HANDSHAKING);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_HANDSHAKING, session->session_state);

	session_manager->set_session_state (session_manager, session_id, SPDM_SESSION_STATE_ESTABLISHED);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_ESTABLISHED, session->session_state);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_set_session_state_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_NOT_STARTED, session->session_state);

	session_manager->set_session_state (NULL, session_id, SPDM_SESSION_STATE_HANDSHAKING);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_NOT_STARTED, session->session_state);

	session_manager->set_session_state (session_manager, SPDM_INVALID_SESSION_ID,
		SPDM_SESSION_STATE_ESTABLISHED);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_NOT_STARTED, session->session_state);

	session_manager->set_session_state (session_manager, session_id, SPDM_SESSION_STATE_MAX);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_NOT_STARTED, session->session_state);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_reset (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, 1, session_manager->state->current_session_count);

	session_manager->reset (session_manager);
	CuAssertIntEquals (test, 0, session_manager->state->current_session_count);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_reset_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, 1, session_manager->state->current_session_count);

	session_manager->reset (NULL);
	CuAssertIntEquals (test, 1, session_manager->state->current_session_count);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	struct spdm_connection_info connection_info;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	ECC_TESTING_ENGINE ecc_engine_real;
	AES_TESTING_ENGINE aes_engine_real;
	struct ecc_private_key req_priv_key;
	struct ecc_public_key req_pub_key;
	struct ecc_public_key resp_pub_key;
	uint8_t *req_pub_key_der = NULL;
	size_t req_pub_key_der_len;
	struct ecc_point_public_key req_pub_key_point = {0};
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];
	uint8_t resp_pub_key_der[ECC_DER_MAX_PUBLIC_LENGTH];
	uint8_t dhe_secret[SPDM_MAX_DHE_SHARED_SECRET_SIZE];

	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	session_manager = &testing.session_manager;

	status = ECC_TESTING_ENGINE_INIT (&ecc_engine_real);
	status |= AES_TESTING_ENGINE_INIT (&aes_engine_real);
	CuAssertIntEquals (test, 0, status);

	status = spdm_secure_session_manager_init (session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms,
		&aes_engine_real.base, &testing.hash_engine_mock.base, &testing.rng_mock.base,
		&ecc_engine_real.base, &testing.transcript_manager_mock.base);
	CuAssertIntEquals (test, 0, status);	

	/* Generate a random key pair. */
	status = ecc_engine_real.base.generate_key_pair (&ecc_engine_real.base, ECC_KEY_LENGTH_384,
		&req_priv_key, &req_pub_key);
	CuAssertIntEquals (test, 0, status);

	/* Convert the req public key in DER format. */
	status = ecc_engine_real.base.get_public_key_der (&ecc_engine_real.base, &req_pub_key,
		&req_pub_key_der, &req_pub_key_der_len);
	CuAssertTrue (test, ROT_IS_ERROR (status) == false);

	status = ecc_der_decode_public_key (req_pub_key_der, req_pub_key_der_len, req_pub_key_point.x,
		req_pub_key_point.y, ECC_KEY_LENGTH_384);
	CuAssertTrue (test, ROT_IS_ERROR (status) == false);
	req_pub_key_point.key_length = ECC_KEY_LENGTH_384;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	/* Generate the responder shared secret. */
	status = session_manager->generate_shared_secret (session_manager, session,
		&req_pub_key_point, resp_pub_key_point);
	CuAssertIntEquals (test, 0, status);

	/* Get the responder public key. */
	status = ecc_der_encode_public_key (resp_pub_key_point, resp_pub_key_point + ECC_KEY_LENGTH_384,
		ECC_KEY_LENGTH_384, resp_pub_key_der, sizeof (resp_pub_key_der));
	CuAssertTrue (test, ROT_IS_ERROR (status) == false);

	status = ecc_engine_real.base.init_public_key (&ecc_engine_real.base, resp_pub_key_der, status,
		&resp_pub_key);
	CuAssertIntEquals (test, 0, status);

	/* Compute the requester shared secret. */
	status = ecc_engine_real.base.compute_shared_secret (&ecc_engine_real.base,
		&req_priv_key, &resp_pub_key, dhe_secret, sizeof (dhe_secret));
	CuAssertTrue (test, ROT_IS_ERROR (status) == false);

	/* Compare the shared secrets. */
	CuAssertIntEquals (test, 0, memcmp (dhe_secret, session->master_secret.dhe_secret,
		session->dhe_key_size));

	session_manager->release_session (session_manager, session_id);

	ecc_engine_real.base.release_key_pair (&ecc_engine_real.base, &req_priv_key, &req_pub_key);
	ecc_engine_real.base.release_key_pair (&ecc_engine_real.base, NULL, &resp_pub_key);
	platform_free (req_pub_key_der);

	ECC_TESTING_ENGINE_RELEASE (&ecc_engine_real);
	AES_TESTING_ENGINE_RELEASE (&aes_engine_real);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info;
	struct ecc_point_public_key req_pub_key_point;
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	/* session_manager = NULL */
	status = session_manager->generate_shared_secret (NULL, session, &req_pub_key_point,
		resp_pub_key_point);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* session = NULL */
	status = session_manager->generate_shared_secret (session_manager, NULL, &req_pub_key_point,
		resp_pub_key_point);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* peer_pub_key_point = NULL */
	status = session_manager->generate_shared_secret (session_manager, session, NULL,
		resp_pub_key_point);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_pub_key_point = NULL */
	status = session_manager->generate_shared_secret (session_manager, session, &req_pub_key_point,
		NULL);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_ecc_der_encode_public_key_fail (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info;
	struct ecc_point_public_key req_pub_key_point = {0};
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	req_pub_key_point.key_length = 0;
	status = session_manager->generate_shared_secret (session_manager, session, &req_pub_key_point,
		resp_pub_key_point);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR, status);
	
	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_init_public_key_fail (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info;
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	status = mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_public_key,
		&testing.ecc_mock, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session, &ECC384_PUBKEY_POINT,
		resp_pub_key_point);
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);
	
	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_generate_key_pair_fail (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info;
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_public_key,
		&testing.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.generate_key_pair,
		&testing.ecc_mock, ECC_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session, &ECC384_PUBKEY_POINT,
		resp_pub_key_point);
	CuAssertIntEquals (test, ECC_ENGINE_GENERATE_KEY_FAILED, status);
	
	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_get_public_key_der_fail (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager* session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info;
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];

	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_public_key,
		&testing.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.generate_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 1, 1);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 2);

	status = mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.get_public_key_der,
		&testing.ecc_mock, ECC_ENGINE_PUBLIC_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false, &connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session, &ECC384_PUBKEY_POINT,
		resp_pub_key_point);
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_DER_FAILED, status);
	
	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}


TEST_SUITE_START (spdm_secure_session_manager);

TEST (spdm_secure_session_manager_test_static_init);
TEST (spdm_secure_session_manager_test_static_init_invalid_params);
TEST (spdm_secure_session_manager_test_init);
TEST (spdm_secure_session_manager_test_init_invalid_params);
TEST (spdm_secure_session_manager_test_release_null);
TEST (spdm_secure_session_manager_test_create_session);
TEST (spdm_secure_session_manager_test_create_session_invalid_params);
TEST (spdm_secure_session_manager_test_create_session_count_gt_max);
TEST (spdm_secure_session_manager_test_create_session_duplicate_session);
TEST (spdm_secure_session_manager_test_release_session);
TEST (spdm_secure_session_manager_test_release_session_invalid_params);
TEST (spdm_secure_session_manager_test_get_session);
TEST (spdm_secure_session_manager_test_get_session_invalid_param);
TEST (spdm_secure_session_manager_test_get_session_no_session);
TEST (spdm_secure_session_manager_test_set_session_state);
TEST (spdm_secure_session_manager_test_set_session_state_invalid_param);
TEST (spdm_secure_session_manager_test_reset);
TEST (spdm_secure_session_manager_test_reset_invalid_param);
TEST (spdm_secure_session_manager_test_generate_shared_secret);
TEST (spdm_secure_session_manager_test_generate_shared_secret_invalid_param);
TEST (spdm_secure_session_manager_test_generate_shared_secret_ecc_der_encode_public_key_fail);
TEST (spdm_secure_session_manager_test_generate_shared_secret_init_public_key_fail);
TEST (spdm_secure_session_manager_test_generate_shared_secret_generate_key_pair_fail);
TEST (spdm_secure_session_manager_test_generate_shared_secret_get_public_key_der_fail);
/* [TODO] TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_*);*/

TEST_SUITE_END;
