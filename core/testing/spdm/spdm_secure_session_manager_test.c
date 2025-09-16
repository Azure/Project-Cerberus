// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "crypto/ecdh.h"
#include "crypto/kat/ecc_kat_vectors.h"
#include "crypto/kdf.h"
#include "fips/fips_logging.h"
#include "spdm/spdm_commands.h"
#include "spdm/spdm_secure_session_manager_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/aes_gcm_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/hkdf_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/fips/error_state_entry_mock.h"
#include "testing/mock/spdm/spdm_protocol_session_observer_mock.h"
#include "testing/mock/spdm/spdm_transcript_manager_mock.h"


TEST_SUITE_LABEL ("spdm_secure_session_manager");

/**
 * Dependencies for testing.
 */
struct spdm_secure_session_manager_testing {
	struct spdm_secure_session_manager session_manager;					/**< The session manager being tested. */
	struct spdm_secure_session_manager_state state;						/**< The session manager state. */
	struct spdm_transcript_manager_mock transcript_manager_mock;		/**< The transcript manager. */
	struct spdm_secure_session_manager_state transcript_manager_state;	/**< The transcript manager state. */
	struct hash_engine_mock hash_engine_mock;							/**< Mock hash engine for the responder. */
	struct spdm_device_capability local_capabilities;					/**< Local capabilities. */
	struct spdm_local_device_algorithms local_algorithms;				/**< Local algorithms. */
	struct ecc_engine_mock ecc_mock;									/**< Mock ECC engine. */
	struct rng_engine_mock rng_mock;									/**< Mock RNG engine. */
	struct aes_gcm_engine_mock aes_mock;								/**< Mock AES engine. */
	struct hkdf_mock hkdf_mock;											/**< Mock for HKDF implementation */
	struct error_state_entry_mock error_state_mock;						/**< Mock for error state entry interface */
	struct spdm_secure_session_manager_algo_info algo_info;				/**< Metadata for crypto algorithms */
	struct spdm_protocol_session_observer_mock observer;				/**< Mock observer for SPDM secure session events. */
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
	testing->local_algorithms.device_algorithms.measurement_hash_algo =
		SPDM_MEAS_RSP_TPM_ALG_SHA_384;
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

	status = ecc_mock_init (&testing->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_mock_init (&testing->aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_mock_init (&testing->hkdf_mock);
	CuAssertIntEquals (test, 0, status);

	status = error_state_entry_mock_init (&testing->error_state_mock);
	CuAssertIntEquals (test, 0, status);

	status = spdm_protocol_session_observer_mock_init (&testing->observer);
	CuAssertIntEquals (test, 0, status);

	testing->algo_info.ecdh_instance_id = 0;
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

	status = aes_gcm_mock_validate_and_release (&testing->aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_mock_validate_and_release (&testing->hkdf_mock);
	CuAssertIntEquals (test, 0, status);

	status = error_state_entry_mock_validate_and_release (&testing->error_state_mock);
	CuAssertIntEquals (test, 0, status);

	status = spdm_protocol_session_observer_mock_validate_and_release (&testing->observer);
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
		(const struct spdm_device_algorithms*) &testing->local_algorithms, &testing->aes_mock.base,
		&testing->hash_engine_mock.base, &testing->rng_mock.base, &testing->ecc_mock.base,
		&testing->transcript_manager_mock.base, &testing->hkdf_mock.base,
		&testing->error_state_mock.base, testing->algo_info);
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

	const struct spdm_secure_session_manager session_manager =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, session_manager.create_session);
	CuAssertPtrNotNull (test, session_manager.release_session);
	CuAssertPtrNotNull (test, session_manager.get_session);
	CuAssertPtrNotNull (test, session_manager.set_session_state);
	CuAssertPtrNotNull (test, session_manager.reset);
	CuAssertPtrNotNull (test, session_manager.generate_shared_secret);
	CuAssertPtrNotNull (test, session_manager.generate_session_handshake_keys);
	CuAssertPtrNotNull (test, session_manager.generate_session_data_keys);
	CuAssertPtrNotNull (test, session_manager.is_last_session_id_valid);
	CuAssertPtrNotNull (test, session_manager.get_last_session_id);
	CuAssertPtrNotNull (test, session_manager.reset_last_session_id_validity);
	CuAssertPtrNotNull (test, session_manager.is_termination_policy_set);

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
	const struct spdm_secure_session_manager session_manager =
		spdm_secure_session_manager_static_init (NULL, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	const struct spdm_secure_session_manager session_manager2 =
		spdm_secure_session_manager_static_init (&testing.state, NULL,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager2);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	const struct spdm_secure_session_manager session_manager3 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities, NULL,
		&testing.aes_mock.base, &testing.hash_engine_mock.base, &testing.rng_mock.base,
		&testing.ecc_mock.base, &testing.transcript_manager_mock.base, &testing.hkdf_mock.base,
		NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager3);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* aes_engine = NULL */
	const struct spdm_secure_session_manager session_manager4 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, NULL,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager4);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	const struct spdm_secure_session_manager session_manager5 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		NULL, &testing.rng_mock.base, &testing.ecc_mock.base, &testing.transcript_manager_mock.base,
		&testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager5);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* rng_engine = NULL */
	const struct spdm_secure_session_manager session_manager6 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager6);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* ecc_engine = NULL */
	const struct spdm_secure_session_manager session_manager7 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, NULL,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager7);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	const struct spdm_secure_session_manager session_manager8 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,	NULL,
		&testing.hkdf_mock.base, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager8);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	struct spdm_secure_session_manager session_manager9 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);


	session_manager9.max_spdm_session_sequence_number = 0;

	status = spdm_secure_session_manager_init_state (&session_manager9);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* hkdf = NULL */
	const struct spdm_secure_session_manager session_manager10 =
		spdm_secure_session_manager_static_init (&testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, NULL, NULL, testing.algo_info);


	status = spdm_secure_session_manager_init_state (&session_manager10);
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
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, testing.session_manager.create_session);
	CuAssertPtrNotNull (test, testing.session_manager.release_session);
	CuAssertPtrNotNull (test, testing.session_manager.get_session);
	CuAssertPtrNotNull (test, testing.session_manager.set_session_state);
	CuAssertPtrNotNull (test, testing.session_manager.reset);
	CuAssertPtrNotNull (test, testing.session_manager.generate_shared_secret);
	CuAssertPtrNotNull (test, testing.session_manager.generate_session_handshake_keys);
	CuAssertPtrNotNull (test, testing.session_manager.generate_session_data_keys);
	CuAssertPtrNotNull (test, testing.session_manager.is_last_session_id_valid);
	CuAssertPtrNotNull (test, testing.session_manager.get_last_session_id);
	CuAssertPtrNotNull (test, testing.session_manager.reset_last_session_id_validity);
	CuAssertPtrNotNull (test, testing.session_manager.is_termination_policy_set);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_init_invalid_params (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;


	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	/* session_manager = NULL */
	status = spdm_secure_session_manager_init (NULL, &testing.state, &testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* state = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, NULL,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state, NULL,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities, NULL, &testing.aes_mock.base, &testing.hash_engine_mock.base,
		NULL, &testing.ecc_mock.base, &testing.transcript_manager_mock.base,
		&testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* aes_engine = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, NULL,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		NULL, NULL, &testing.ecc_mock.base, &testing.transcript_manager_mock.base,
		&testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* ecc_engine = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, NULL, &testing.transcript_manager_mock.base,
		&testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base, NULL,	&testing.hkdf_mock.base,
		NULL, testing.algo_info);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* hkdf = NULL */
	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, NULL, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, NULL, NULL, testing.algo_info);
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
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	connection_info.version.major_version = 1;
	connection_info.version.minor_version = 2;
	connection_info.version.alpha = 0;
	connection_info.version.update_version_number = 0;
	connection_info.secure_message_version.alpha = 0;
	connection_info.secure_message_version.major_version = 1;
	connection_info.secure_message_version.minor_version = 2;
	connection_info.secure_message_version.update_version_number = 0;

	connection_info.peer_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;
	connection_info.peer_algorithms.dhe_named_group = SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1;
	connection_info.peer_algorithms.aead_cipher_suite = SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM;
	connection_info.peer_algorithms.key_schedule = SPDM_ALG_KEY_SCHEDULE_HMAC_HASH;

	struct spdm_secure_session *session = session_manager->create_session (session_manager,
		session_id, false, &connection_info);


	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, SPDM_SESSION_TYPE_NONE, session->session_type);
	CuAssertIntEquals (test, session_id, session->session_id);
	CuAssertIntEquals (test, 0, session->session_index);
	CuAssertIntEquals (test, false, session->is_requester);
	CuAssertIntEquals (test, 1, session->version.major_version);
	CuAssertIntEquals (test, 2, session->version.minor_version);
	CuAssertIntEquals (test, 0, session->version.alpha);
	CuAssertIntEquals (test, 0, session->version.update_version_number);
	CuAssertIntEquals (test, 1, session->secure_message_version.major_version);
	CuAssertIntEquals (test, 2, session->secure_message_version.minor_version);
	CuAssertIntEquals (test, 0, session->secure_message_version.alpha);
	CuAssertIntEquals (test, 0, session->secure_message_version.update_version_number);
	CuAssertIntEquals (test, SPDM_TPM_ALG_SHA_384, session->base_hash_algo);
	CuAssertIntEquals (test, SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1, session->dhe_named_group);
	CuAssertIntEquals (test, SPDM_ALG_AEAD_CIPHER_SUITE_AES_256_GCM, session->aead_cipher_suite);
	CuAssertIntEquals (test, SPDM_ALG_KEY_SCHEDULE_HMAC_HASH, session->key_schedule);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_enc_mac (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	connection_info.peer_capabilities = testing.local_capabilities;

	struct spdm_secure_session *session = session_manager->create_session (session_manager,
		session_id, false, &connection_info);


	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, SPDM_SESSION_TYPE_ENC_MAC, session->session_type);
	CuAssertIntEquals (test, 0,
		testing_validate_array (&testing.local_capabilities, &session->peer_capabilities,
		sizeof (testing.local_capabilities)));

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_mac_only (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	connection_info.peer_capabilities.flags.encrypt_cap = 0;
	connection_info.peer_capabilities.flags.mac_cap = 1;
	testing.local_capabilities.flags.encrypt_cap = 0;

	struct spdm_secure_session *session = session_manager->create_session (session_manager,
		session_id, false, &connection_info);


	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, SPDM_SESSION_TYPE_MAC_ONLY, session->session_type);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_invalid_params (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	session_manager->state->current_session_count = SPDM_MAX_SESSION_COUNT;
	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_create_session_duplicate_session (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session_manager->state->current_session_count = 0;
	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrEquals (test, NULL, session);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_release_session (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_release_session_invalid_params (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
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
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
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
	struct spdm_secure_session_manager *session_manager;
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
	struct spdm_secure_session_manager *session_manager;
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
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_NOT_STARTED, session->session_state);

	session_manager->set_session_state (session_manager, session_id,
		SPDM_SESSION_STATE_HANDSHAKING);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_HANDSHAKING, session->session_state);

	session_manager->set_session_state (session_manager, session_id,
		SPDM_SESSION_STATE_ESTABLISHED);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_ESTABLISHED, session->session_state);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_set_session_state_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
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
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status =
		spdm_secure_session_manager_add_spdm_protocol_session_observer (&testing.session_manager,
		&testing.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.observer.mock, testing.observer.base.on_close_session,
		&testing.observer.base, 0, MOCK_ARG_PTR_CONTAINS (&session_id, sizeof (session_id)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
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
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	CuAssertIntEquals (test, 1, session_manager->state->current_session_count);

	session_manager->reset (NULL);
	CuAssertIntEquals (test, 1, session_manager->state->current_session_count);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc_engine_real);
	AES_GCM_TESTING_ENGINE (aes_engine_real);
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct spdm_connection_info connection_info = {0};
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
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
	status |= AES_GCM_TESTING_ENGINE_INIT (&aes_engine_real);
	CuAssertIntEquals (test, 0, status);

	status = spdm_secure_session_manager_init (session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base,	&ecc_engine_real.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base,
		&testing.error_state_mock.base, testing.algo_info);
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	/* Generate the responder shared secret. */
	status = session_manager->generate_shared_secret (session_manager, session,	&req_pub_key_point,
		resp_pub_key_point);
	CuAssertIntEquals (test, 0, status);

	/* Get the responder public key. */
	status = ecc_der_encode_public_key (resp_pub_key_point, resp_pub_key_point + ECC_KEY_LENGTH_384,
		ECC_KEY_LENGTH_384, resp_pub_key_der, sizeof (resp_pub_key_der));
	CuAssertTrue (test, ROT_IS_ERROR (status) == false);

	status = ecc_engine_real.base.init_public_key (&ecc_engine_real.base, resp_pub_key_der, status,
		&resp_pub_key);
	CuAssertIntEquals (test, 0, status);

	/* Compute the requester shared secret. */
	status = ecc_engine_real.base.compute_shared_secret (&ecc_engine_real.base,	&req_priv_key,
		&resp_pub_key, dhe_secret, sizeof (dhe_secret));
	CuAssertTrue (test, ROT_IS_ERROR (status) == false);

	/* Compare the shared secrets. */
	CuAssertIntEquals (test, 0,
		memcmp (dhe_secret, session->master_secret.dhe_secret, session->dhe_key_size));

	session_manager->release_session (session_manager, session_id);

	ecc_engine_real.base.release_key_pair (&ecc_engine_real.base, &req_priv_key, &req_pub_key);
	ecc_engine_real.base.release_key_pair (&ecc_engine_real.base, NULL, &resp_pub_key);
	platform_free (req_pub_key_der);

	ECC_TESTING_ENGINE_RELEASE (&ecc_engine_real);
	AES_GCM_TESTING_ENGINE_RELEASE (&aes_engine_real);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
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

static void spdm_secure_session_manager_test_generate_shared_secret_ecc_der_encode_public_key_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	req_pub_key_point.key_length = 0;
	status = session_manager->generate_shared_secret (session_manager, session, &req_pub_key_point,
		resp_pub_key_point);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INTERNAL_ERROR, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_init_public_key_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
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
		MOCK_ARG (ECC384_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session,
		&ECC384_PUBKEY_POINT, resp_pub_key_point);
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_generate_key_pair_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];
	struct debug_log_entry_info pct_error = {
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_FIPS,
		.msg_index = FIPS_LOGGING_ECDH_PCT_FAILED,
		.arg1 = 0,
		.arg2 = ECC_ENGINE_GENERATE_KEY_FAILED,
		.format = 1,
	};


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
		&testing.ecc_mock, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.generate_key_pair,
		&testing.ecc_mock, ECC_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&testing.error_state_mock.mock,
		testing.error_state_mock.base.enter_error_state, &testing.error_state_mock.base, 0,
		MOCK_ARG_PTR_CONTAINS (&pct_error, sizeof (pct_error)));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session,
		&ECC384_PUBKEY_POINT, resp_pub_key_point);
	CuAssertIntEquals (test, ECC_ENGINE_GENERATE_KEY_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_pct_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];
	struct debug_log_entry_info pct_error = {
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_FIPS,
		.msg_index = FIPS_LOGGING_ECDH_PCT_FAILED,
		.arg1 = 0,
		.arg2 = ECDH_PCT_FAILURE,
		.format = 1,
	};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	// session create/release
	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	// ecc operations
	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_public_key,
		&testing.ecc_mock, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.generate_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 1, 1);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 2);

	status |= mock_expect (&testing.ecc_mock.mock,
		testing.ecc_mock.base.get_shared_secret_max_length, &testing.ecc_mock.base,
		ECC_KEY_LENGTH_384, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 3);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 3, 4);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.compute_shared_secret,
		&testing.ecc_mock.base, 1, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.compute_shared_secret,
		&testing.ecc_mock.base, 2, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_SAVED_ARG (3), MOCK_ARG_SAVED_ARG (4));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&testing.error_state_mock.mock,
		testing.error_state_mock.base.enter_error_state, &testing.error_state_mock.base, 0,
		MOCK_ARG_PTR_CONTAINS (&pct_error, sizeof (pct_error)));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session,
		&ECC384_PUBKEY_POINT, resp_pub_key_point);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_pct_fail_algo_info (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t resp_pub_key_point[ECC_KEY_LENGTH_384 << 1];
	struct debug_log_entry_info pct_error = {
		.severity = DEBUG_LOG_SEVERITY_ERROR,
		.component = DEBUG_LOG_COMPONENT_FIPS,
		.msg_index = FIPS_LOGGING_ECDH_PCT_FAILED,
		.arg1 = 123,
		.arg2 = ECDH_PCT_FAILURE,
		.format = 1,
	};


	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base,
		&testing.error_state_mock.base,
		(struct spdm_secure_session_manager_algo_info) {.ecdh_instance_id = 123, });
	CuAssertIntEquals (test, 0, status);

	session_manager = &testing.session_manager;

	// session create/release
	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	// ecc operations
	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_public_key,
		&testing.ecc_mock, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.generate_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 1, 1);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 2);

	status |= mock_expect (&testing.ecc_mock.mock,
		testing.ecc_mock.base.get_shared_secret_max_length, &testing.ecc_mock.base,
		ECC_KEY_LENGTH_384, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 3);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 3, 4);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.compute_shared_secret,
		&testing.ecc_mock.base, 1, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.compute_shared_secret,
		&testing.ecc_mock.base, 2, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_SAVED_ARG (3), MOCK_ARG_SAVED_ARG (4));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_SAVED_ARG (2));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&testing.error_state_mock.mock,
		testing.error_state_mock.base.enter_error_state, &testing.error_state_mock.base, 0,
		MOCK_ARG_PTR_CONTAINS (&pct_error, sizeof (pct_error)));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session,
		&ECC384_PUBKEY_POINT, resp_pub_key_point);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_shared_secret_get_public_key_der_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
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
		&testing.ecc_mock, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.generate_key_pair,
		&testing.ecc_mock, 0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 1, 1);
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 2);

	status |= mock_expect (&testing.ecc_mock.mock,
		testing.ecc_mock.base.get_shared_secret_max_length, &testing.ecc_mock.base,
		ECC_KEY_LENGTH_384, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.compute_shared_secret,
		&testing.ecc_mock.base, 1, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.compute_shared_secret,
		&testing.ecc_mock.base, 1, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_MAX_KEY_LENGTH));

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = session_manager->generate_shared_secret (session_manager, session,
		&ECC384_PUBKEY_POINT, resp_pub_key_point);
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_DER_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_invalid_param (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	/* session_manager = NULL */
	status = session_manager->generate_session_handshake_keys (NULL, session);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* session = NULL */
	status = session_manager->generate_session_handshake_keys (session_manager, NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_get_hash_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock,
		SPDM_TRANSCRIPT_MANAGER_GET_HASH_FAILED, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (false), MOCK_ARG (true), MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	CuAssertIntEquals (test, 0, status);

	session->hash_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_GET_HASH_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret again
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate response handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, 0, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys2 (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	HASH_TESTING_ENGINE (hash_engine);
	struct hkdf_state hkdf_state;
	struct hkdf hkdf_engine;
	uint8_t th1_hash[HASH_MAX_HASH_LEN] = {
		0x89, 0xBE, 0xEB, 0x87, 0xAA, 0x13, 0xB9, 0x5E,
		0x09, 0x3E, 0xB8, 0x6E, 0x6C, 0x10, 0x8E, 0x40,
		0x14, 0x1A, 0x6A, 0x12, 0x88, 0x75, 0x95, 0x72,
		0x68, 0xEF, 0x81, 0x49, 0xEC, 0x74, 0xAB, 0x39,
		0x25, 0x37, 0x77, 0x3F, 0x69, 0xD3, 0x1F, 0xDB,
		0x5C, 0x5F, 0x32, 0x4B, 0x3B, 0x75, 0x3D, 0x95
	};
	uint8_t dhe_secret[] = {
		0x23, 0x1A, 0x2B, 0xF5, 0xBF, 0xAC, 0xE7, 0x71,
		0x4E, 0x15, 0xFC, 0xB1, 0xBA, 0xA2, 0x2F, 0xE1,
		0x00, 0x34, 0xD6, 0x2F, 0xD2, 0x78, 0xFF, 0xEC,
		0x8F, 0xC3, 0x15, 0x47, 0xE1, 0x34, 0x70, 0x04,
		0x4B, 0xFA, 0x27, 0x8B, 0xEF, 0xE2, 0x4F, 0x7B,
		0x67, 0xBB, 0xEF, 0x2A, 0xE7, 0xFC, 0xEC, 0xF6
	};
	uint8_t salt1[] = {
		0x3F, 0xDF, 0xDF, 0xE0, 0xD5, 0xD7, 0x08, 0xFD,
		0xF2, 0x89, 0x1F, 0xC1, 0x28, 0xCD, 0xF0, 0xA2,
		0xEC, 0x32, 0x27, 0x08, 0x5B, 0x57, 0x45, 0x6B,
		0xD7, 0xDF, 0x38, 0xB6, 0x1C, 0x7B, 0xCA, 0x68,
		0x2D, 0x87, 0x4B, 0x55, 0xBA, 0x92, 0xAC, 0x32,
		0x54, 0xA3, 0x06, 0x03, 0xB7, 0x1D, 0x79, 0x72
	};
	uint8_t request_finished_key[] = {
		0xA4, 0xBA, 0x9A, 0x09, 0x0C, 0x9B, 0xCC, 0x3D,
		0x31, 0xC4, 0x4E, 0x3D, 0x5D, 0x5A, 0x87, 0x66,
		0x7F, 0x56, 0x8F, 0xFF, 0x0B, 0x5E, 0xE2, 0x39,
		0xB4, 0x8D, 0x26, 0x2E, 0xD3, 0x67, 0xDB, 0xC2,
		0xA9, 0x85, 0xED, 0x59, 0x07, 0x4E, 0x67, 0xE0,
		0xA9, 0xE1, 0xC9, 0x4F, 0xB1, 0x98, 0xD1, 0x88
	};
	uint8_t response_finished_key[] = {
		0x9C, 0x42, 0x0B, 0xAA, 0x6C, 0x76, 0xEF, 0x48,
		0x62, 0xB1, 0x14, 0x61, 0xF9, 0x92, 0x0C, 0x47,
		0xE5, 0xC7, 0x33, 0x20, 0x00, 0x22, 0xB3, 0x22,
		0xD2, 0x7E, 0x32, 0x5B, 0xF5, 0x7C, 0x12, 0xBC,
		0x65, 0xC9, 0x7F, 0xCD, 0x55, 0xFD, 0xA0, 0x2B,
		0x4A, 0x99, 0xAC, 0xFC, 0x52, 0x55, 0x2C, 0x07
	};
	uint8_t request_enc_key[] = {
		0x11, 0xD0, 0x86, 0x36, 0xA9, 0x22, 0x8C, 0xED,
		0x67, 0x4E, 0xAF, 0x44, 0xCB, 0x74, 0x78, 0x71,
		0xB7, 0x7F, 0x20, 0x48, 0xDD, 0x8F, 0xFA, 0x72,
		0xCA, 0xE0, 0xBE, 0x6E, 0x0A, 0x08, 0xDA, 0x8F
	};
	uint8_t request_iv[] = {
		0x0F, 0x8F, 0x43, 0xE3, 0x76, 0x9D, 0x8C, 0x71, 0xF9, 0x9C, 0xA8, 0x5B
	};
	uint8_t response_enc_key[] = {
		0x58, 0x4B, 0x97, 0x3B, 0x6B, 0xD0, 0xAD, 0x8E,
		0x35, 0x0B, 0x0A, 0x33, 0xA8, 0xC9, 0x83, 0x58,
		0xB9, 0xDC, 0x64, 0x13, 0xA0, 0x71, 0xA6, 0xED,
		0x9D, 0x1C, 0x33, 0xE0, 0x48, 0x1D, 0x8F, 0x1A
	};
	uint8_t response_iv[] = {
		0x0B, 0xD1, 0xC2, 0x50, 0x39, 0x14, 0x2F, 0xA5, 0xC7, 0x75, 0xDA, 0xC0
	};


	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_init (&hkdf_engine, &hkdf_state, &hash_engine.base);
	CuAssertIntEquals (test, 0, status);

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&hash_engine.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &hkdf_engine.base, &testing.error_state_mock.base,
		testing.algo_info);
	CuAssertIntEquals (test, 0, status);

	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&testing.transcript_manager_mock.mock, 4, th1_hash,
		sizeof (th1_hash), -1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SPDM_MAX_AEAD_KEY_SIZE;
	session->aead_iv_size = SPDM_MAX_AEAD_IV_SIZE;
	session->version.major_version = 1;
	session->version.minor_version = 2;
	memcpy (session->master_secret.dhe_secret, dhe_secret, SHA384_HASH_LENGTH);

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (salt1, session->master_secret.master_secret_salt1,
		sizeof (salt1));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (request_finished_key,
		session->handshake_secret.request_finished_key, sizeof (request_finished_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (response_finished_key,
		session->handshake_secret.response_finished_key, sizeof (response_finished_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (request_enc_key,
		session->handshake_secret.request_handshake_encryption_key, sizeof (request_enc_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (request_iv, session->handshake_secret.request_handshake_salt,
		sizeof (request_iv));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (response_enc_key,
		session->handshake_secret.response_handshake_encryption_key, sizeof (response_enc_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (response_iv, session->handshake_secret.response_handshake_salt,
		sizeof (response_iv));
	CuAssertIntEquals (test, 0, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_extract_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, HASH_ENGINE_UNKNOWN_HASH, MOCK_ARG (HASH_TYPE_INVALID),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = UINT32_MAX;
	session->hash_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_extract2_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret again
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, HKDF_EXTRACT_FAILED, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_update_prk_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_INVALID),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, HKDF_UPDATE_PRK_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = UINT32_MAX;
	session->hash_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_UPDATE_PRK_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_update_prk2_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret again
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate response handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, HKDF_UPDATE_PRK_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_UPDATE_PRK_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand1_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand2_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand3_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand4_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand5_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret again
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate response handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand6_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret again
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate response handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand7_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate master secret Salt1
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.request_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// generate handshake secret again
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR (session->master_secret.dhe_secret), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	// generate response handshake PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response finished key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_finished_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_handshake_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->handshake_secret.response_handshake_salt),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_handshake_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}


static void spdm_secure_session_manager_test_generate_session_data_keys (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint32_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate response PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.response_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.response_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, 0, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys2 (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	HASH_TESTING_ENGINE (hash_engine);
	struct hkdf_state hkdf_state;
	struct hkdf hkdf_engine;
	uint8_t th2_hash[HASH_MAX_HASH_LEN] = {
		0xE9, 0xFE, 0x89, 0x84, 0x0A, 0x55, 0xAB, 0x4A,
		0xBE, 0xF3, 0x81, 0x2D, 0xC8, 0x71, 0x93, 0x3F,
		0x97, 0x3A, 0xF6, 0xD0, 0x05, 0x9E, 0x84, 0xEC,
		0xF3, 0x68, 0x16, 0x02, 0xB4, 0x45, 0x4B, 0xAE,
		0xFD, 0x1F, 0x5F, 0xF2, 0x0C, 0xBE, 0x3A, 0x04,
		0xA0, 0x25, 0xE5, 0xDC, 0x8C, 0x1C, 0x63, 0x50
	};
	uint8_t salt1[] = {
		0x3F, 0xDF, 0xDF, 0xE0, 0xD5, 0xD7, 0x08, 0xFD,
		0xF2, 0x89, 0x1F, 0xC1, 0x28, 0xCD, 0xF0, 0xA2,
		0xEC, 0x32, 0x27, 0x08, 0x5B, 0x57, 0x45, 0x6B,
		0xD7, 0xDF, 0x38, 0xB6, 0x1C, 0x7B, 0xCA, 0x68,
		0x2D, 0x87, 0x4B, 0x55, 0xBA, 0x92, 0xAC, 0x32,
		0x54, 0xA3, 0x06, 0x03, 0xB7, 0x1D, 0x79, 0x72
	};
	uint8_t request_enc_key[] = {
		0x5C, 0x76, 0x1B, 0xB9, 0xBC, 0xEC, 0xC2, 0xDA,
		0xEA, 0xBB, 0x99, 0x4C, 0x05, 0x22, 0xF5, 0xD7,
		0x0C, 0xC6, 0x28, 0xEC, 0xE7, 0xB3, 0x4D, 0x67,
		0x3E, 0x19, 0x26, 0x65, 0x3E, 0xB4, 0x6B, 0xBF
	};
	uint8_t request_iv[] = {
		0x0F, 0x81, 0xBF, 0xDB, 0x10, 0xC5, 0x78, 0x0D, 0xE5, 0xD2, 0x25, 0x4B
	};
	uint8_t response_enc_key[] = {
		0x71, 0xCD, 0xDD, 0x3D, 0xF0, 0x90, 0xDC, 0x02,
		0x87, 0xB0, 0x84, 0xB5, 0x72, 0x3C, 0x15, 0x8D,
		0x16, 0x0B, 0xD9, 0x07, 0x59, 0xCF, 0xFC, 0xED,
		0xE0, 0x8B, 0x65, 0xF3, 0xC1, 0x38, 0xBE, 0xCC
	};
	uint8_t response_iv[] = {
		0xE6, 0x03, 0xAF, 0x45, 0x37, 0xC8, 0x21, 0x5C, 0x35, 0x76, 0x08, 0x96
	};


	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash_engine);
	CuAssertIntEquals (test, 0, status);

	status = hkdf_init (&hkdf_engine, &hkdf_state, &hash_engine.base);
	CuAssertIntEquals (test, 0, status);

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&hash_engine.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &hkdf_engine.base, &testing.error_state_mock.base,
		testing.algo_info);
	CuAssertIntEquals (test, 0, status);

	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&testing.transcript_manager_mock.mock, 4, th2_hash,
		sizeof (th2_hash), -1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SPDM_MAX_AEAD_KEY_SIZE;
	session->aead_iv_size = SPDM_MAX_AEAD_IV_SIZE;
	session->version.major_version = 1;
	session->version.minor_version = 2;
	memcpy (session->master_secret.master_secret_salt1, salt1, sizeof (salt1));

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (request_enc_key,
		session->data_secret.request_data_encryption_key, sizeof (request_enc_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (request_iv, session->data_secret.request_data_salt,
		sizeof (request_iv));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (response_enc_key,
		session->data_secret.response_data_encryption_key, sizeof (response_enc_key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (response_iv, session->data_secret.response_data_salt,
		sizeof (response_iv));
	CuAssertIntEquals (test, 0, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	/* session_manager = NULL */
	status = session_manager->generate_session_data_keys (NULL, session);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* session = NULL */
	status = session_manager->generate_session_data_keys (session_manager, NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_extract_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint32_t zero[SHA384_HASH_LENGTH] = {0};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, HKDF_EXTRACT_FAILED, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_extract2_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, HKDF_EXTRACT_FAILED, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXTRACT_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_update_prk_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, HKDF_UPDATE_PRK_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_UPDATE_PRK_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_update_prk2_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate response PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, HKDF_UPDATE_PRK_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_UPDATE_PRK_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand1_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand2_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand3_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate response PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.response_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand4_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate request PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// request encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// request encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.request_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	// generate response PRK
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.update_prk,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1));

	// response encryption key
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.response_data_encryption_key),
		MOCK_ARG (SHA384_HASH_LENGTH));

	// response encryption IV
	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.expand,
		&testing.hkdf_mock.base, HKDF_EXPAND_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (1),
		MOCK_ARG_PTR (session->data_secret.response_data_salt), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	session->dhe_key_size = SHA384_HASH_LENGTH;
	session->aead_key_size = SHA384_HASH_LENGTH;
	session->aead_iv_size = SHA384_HASH_LENGTH;

	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, HKDF_EXPAND_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}


static void spdm_secure_session_manager_test_generate_session_data_keys_get_hash_fail (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	uint8_t zero[SHA384_HASH_LENGTH] = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	status = mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.extract,
		&testing.hkdf_mock.base, 0, MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_PTR_CONTAINS (zero, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR (session->master_secret.master_secret_salt1), MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock,
		SPDM_TRANSCRIPT_MANAGER_GET_HASH_FAILED, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (false), MOCK_ARG (true), MOCK_ARG (session->session_index), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	status |= mock_expect (&testing.hkdf_mock.mock, testing.hkdf_mock.base.clear_prk,
		&testing.hkdf_mock.base, 0);

	CuAssertIntEquals (test, 0, status);

	session->base_hash_algo = SPDM_TPM_ALG_SHA_384;
	session->hash_size = SHA384_HASH_LENGTH;
	status = session_manager->generate_session_data_keys (session_manager, session);
	CuAssertIntEquals (test, SPDM_TRANSCRIPT_MANAGER_GET_HASH_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;
	size_t encrypted_payload_length = 64;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;
	struct spdm_secured_message_cipher_header *enc_msg_header;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.request_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) +
		encrypted_payload_length;
	request.payload = buf;

	record_header_1 = (void*) request.payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1));
	record_header_2->length = encrypted_payload_length + aead_tag_size;

	enc_msg_header = (void*) (record_header_2 + 1);
	enc_msg_header->application_data_length = encrypted_payload_length - 1;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.decrypt_with_add_data,
		&testing.aes_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,	MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, enc_msg_header->application_data_length, request.payload_length);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct cmd_interface_msg request;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	/* session_manager = NULL */
	status = session_manager->decode_secure_message (NULL, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* request = NULL */
	status = session_manager->decode_secure_message (session_manager, NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_payload_lt_min (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct cmd_interface_msg request = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	request.payload_length = sizeof (struct spdm_secured_message_data_header_1) - 1;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_no_session (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = sizeof (struct spdm_secured_message_data_header_1);
	request.payload = buf;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_REQUEST, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void
spdm_secure_session_manager_test_decode_secure_message_sequence_number_overflow_session_state_handshaking
	(CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_HANDSHAKING;
	session->handshake_secret.request_handshake_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = sizeof (struct spdm_secured_message_data_header_1);
	request.payload = buf;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void
spdm_secure_session_manager_test_decode_secure_message_sequence_number_overflow_session_state_established
	(CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = sizeof (struct spdm_secured_message_data_header_1);
	request.payload = buf;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_payload_incorrect_length (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) - 1;
	request.payload = buf;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_payload_incorrect_length_2 (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;
	size_t encrypted_payload_length = 64;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) +
		encrypted_payload_length;
	request.payload = buf;

	record_header_1 = (void*) request.payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1));
	record_header_2->length = encrypted_payload_length + aead_tag_size + 1;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_payload_incorrect_length_3 (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;
	size_t encrypted_payload_length = 64;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) +
		encrypted_payload_length;
	request.payload = buf;

	record_header_1 = (void*) request.payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1));
	record_header_2->length = aead_tag_size - 1;

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_set_key_fail (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;
	size_t encrypted_payload_length = 64;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.request_data_encryption_key, aes_key, 32);

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) +
		encrypted_payload_length;
	request.payload = buf;

	record_header_1 = (void*) request.payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1));
	record_header_2->length = encrypted_payload_length + aead_tag_size;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		AES_GCM_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)),
		MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SET_KEY_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_decrypt_with_add_data_fail (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;
	size_t encrypted_payload_length = 64;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.request_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) +
		encrypted_payload_length;
	request.payload = buf;

	record_header_1 = (void*) request.payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1));
	record_header_2->length = encrypted_payload_length + aead_tag_size;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.decrypt_with_add_data,
		&testing.aes_mock, AES_GCM_ENGINE_DECRYPT_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, AES_GCM_ENGINE_DECRYPT_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_decode_secure_message_plaintext_size_gt_ciphertext_size
	(CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_secured_message_data_header_1 *secured_message_data_header_1 = (void*) buf;
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t aead_tag_size = 16;
	size_t encrypted_payload_length = 64;
	struct spdm_secured_message_data_header_1 *record_header_1;
	struct spdm_secured_message_data_header_2 *record_header_2;
	struct spdm_secured_message_cipher_header *enc_msg_header;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


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

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);
	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.request_data_sequence_number = SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.request_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	secured_message_data_header_1->session_id = 0xDEADBEEF;
	request.payload_length = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size) +
		encrypted_payload_length;
	request.payload = buf;

	record_header_1 = (void*) request.payload;
	record_header_2 = (void*) ((uint8_t*) record_header_1 +
		sizeof (struct spdm_secured_message_data_header_1));
	record_header_2->length = encrypted_payload_length + aead_tag_size;

	enc_msg_header = (void*) (record_header_2 + 1);
	enc_msg_header->application_data_length = encrypted_payload_length + 1;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.decrypt_with_add_data,
		&testing.aes_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,	MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = session_manager->decode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_MESSAGE_SIZE, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_finish_response (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t plaintext_payload_length = 64;
	size_t aead_tag_size = 16;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status =
		spdm_secure_session_manager_add_spdm_protocol_session_observer (&testing.session_manager,
		&testing.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.observer.mock, testing.observer.base.on_new_session,
		&testing.observer.base, 0, MOCK_ARG_PTR_CONTAINS (&session_id, sizeof (session_id)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.response_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	request.payload_length = plaintext_payload_length;
	request.max_response = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size +
		plaintext_payload_length + sizeof (struct spdm_secured_message_cipher_header));
	request.payload = buf + sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) +
		sizeof (struct spdm_secured_message_cipher_header);
	((struct spdm_protocol_header*) request.payload)->req_rsp_code = SPDM_RESPONSE_FINISH;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.encrypt_with_add_data,
		&testing.aes_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,	MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_SESSION_STATE_ESTABLISHED, session->session_state);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_end_session_response (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t plaintext_payload_length = 64;
	size_t aead_tag_size = 16;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status =
		spdm_secure_session_manager_add_spdm_protocol_session_observer (&testing.session_manager,
		&testing.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.observer.mock, testing.observer.base.on_close_session,
		&testing.observer.base, 0, MOCK_ARG_PTR_CONTAINS (&session_id, sizeof (session_id)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.response_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	request.payload_length = plaintext_payload_length;
	request.max_response = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size +
		plaintext_payload_length + sizeof (struct spdm_secured_message_cipher_header));
	request.payload = buf + sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) +
		sizeof (struct spdm_secured_message_cipher_header);
	((struct spdm_protocol_header*) request.payload)->req_rsp_code = SPDM_RESPONSE_END_SESSION;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.encrypt_with_add_data,
		&testing.aes_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,	MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, 0, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_invalid_param (CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct cmd_interface_msg request;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	/* session_manager = NULL */
	status = session_manager->encode_secure_message (NULL, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	/* request = NULL */
	status = session_manager->encode_secure_message (session_manager, NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void
spdm_secure_session_manager_test_encode_secure_message_last_spdm_request_secure_session_id_invalid (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	struct cmd_interface_msg request;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	session_manager->state->last_spdm_request_secure_session_id_valid = false;

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_no_session (CuTest *test)
{
	int status;
	struct cmd_interface_msg request;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = 0xDEADBEEF;

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INTERNAL_ERROR, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void
spdm_secure_session_manager_test_encode_secure_message_sequence_number_overflow_session_state_handshaking
	(CuTest *test)
{
	int status;
	struct cmd_interface_msg request;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_HANDSHAKING;
	session->handshake_secret.response_handshake_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER;

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void
spdm_secure_session_manager_test_encode_secure_message_sequence_number_overflow_session_state_established
	(CuTest *test)
{
	int status;
	struct cmd_interface_msg request;
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER;

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_SEQUENCE_NUMBER_OVERFLOW, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_max_response_size_lt_required (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t plaintext_payload_length = 64;
	size_t aead_tag_size = 16;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;

	request.payload_length = plaintext_payload_length;
	request.max_response = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size +
		plaintext_payload_length + sizeof (struct spdm_secured_message_cipher_header)) - 1;
	request.payload = buf + sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) +
		sizeof (struct spdm_secured_message_cipher_header);

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_BUFFER_TOO_SMALL, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_set_key_fail (CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t plaintext_payload_length = 64;
	size_t aead_tag_size = 16;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.response_data_encryption_key, aes_key, 32);

	request.payload_length = plaintext_payload_length;
	request.max_response = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size +
		plaintext_payload_length + sizeof (struct spdm_secured_message_cipher_header));
	request.payload = buf + sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) +
		sizeof (struct spdm_secured_message_cipher_header);

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		AES_GCM_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)),
		MOCK_ARG (sizeof (aes_key)));
	CuAssertIntEquals (test, 0, status);

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SET_KEY_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_encode_secure_message_encrypt_with_add_data_fail (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t plaintext_payload_length = 64;
	size_t aead_tag_size = 16;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.response_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	request.payload_length = plaintext_payload_length;
	request.max_response = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size +
		plaintext_payload_length + sizeof (struct spdm_secured_message_cipher_header));
	request.payload = buf + sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) +
		sizeof (struct spdm_secured_message_cipher_header);

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.encrypt_with_add_data,
		&testing.aes_mock, AES_GCM_ENGINE_DECRYPT_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, AES_GCM_ENGINE_DECRYPT_FAILED, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_is_termination_policy_set (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	int status;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->session_policy = 1;

	status = session_manager->is_termination_policy_set (session_manager);
	CuAssertIntEquals (test, 0, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_is_termination_policy_set_not_set (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	int status;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->session_policy = 0;

	status = session_manager->is_termination_policy_set (session_manager);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_TERMINATION_POLICY_NOT_SET, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_is_termination_policy_set_invalid_session_id (
	CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	int status;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->session_policy = 0;
	session->session_id = 0;

	status = session_manager->is_termination_policy_set (session_manager);
	CuAssertIntEquals (test, 0, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_is_termination_policy_set_no_established_session (
	CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	int status;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_NOT_STARTED;
	session->session_policy = 0;
	session->session_id = session_id;

	status = session_manager->is_termination_policy_set (session_manager);
	CuAssertIntEquals (test, 0, status);

	session->session_state = SPDM_SESSION_STATE_HANDSHAKING;

	status = session_manager->is_termination_policy_set (session_manager);
	CuAssertIntEquals (test, 0, status);

	session_manager->release_session (session_manager, session_id);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_is_termination_policy_set_invalid_param (CuTest *test)
{
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	int status;


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;

	status = session_manager->is_termination_policy_set (NULL);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_add_spdm_protocol_session_observer_invalid_arg (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;


	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, 0, status);

	status = spdm_secure_session_manager_add_spdm_protocol_session_observer (NULL,
		&testing.observer.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	status =
		spdm_secure_session_manager_add_spdm_protocol_session_observer (&testing.session_manager,
		NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_remove_spdm_protocol_session_observer (
	CuTest *test)
{
	int status;
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request = {0};
	struct spdm_secure_session_manager_testing testing;
	struct spdm_secure_session_manager *session_manager;
	uint32_t session_id = 0xDEADBEEF;
	struct spdm_secure_session *session;
	struct spdm_connection_info connection_info = {0};
	size_t plaintext_payload_length = 64;
	size_t aead_tag_size = 16;
	uint8_t aes_key[] = {
		0xf1, 0x3b, 0x43, 0x16, 0x2c, 0xe4, 0x05, 0x75, 0x73, 0xc5, 0x54, 0x10, 0xad, 0xd5, 0xc5,
		0xc6,
		0x0e, 0x9a, 0x37, 0xff, 0x3e, 0xa0, 0x02, 0x34, 0xd6, 0x41, 0x80, 0xfa, 0x1a, 0x0e, 0x0a,
		0x04
	};


	TEST_START;

	spdm_secure_session_manager_testing_init (test, &testing);
	session_manager = &testing.session_manager;
	session_manager->state->last_spdm_request_secure_session_id_valid = true;
	session_manager->state->last_spdm_request_secure_session_id = session_id;

	status =
		spdm_secure_session_manager_add_spdm_protocol_session_observer (&testing.session_manager,
		&testing.observer.base);
	CuAssertIntEquals (test, 0, status);

	status =
		spdm_secure_session_manager_remove_spdm_protocol_session_observer (&testing.session_manager,
		&testing.observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_session_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	session = session_manager->create_session (session_manager, session_id, false,
		&connection_info);
	CuAssertPtrNotNull (test, session);

	session->session_state = SPDM_SESSION_STATE_ESTABLISHED;
	session->data_secret.response_data_sequence_number =
		SPDM_MAX_SECURE_SESSION_SEQUENCE_NUMBER - 1;
	session->aead_tag_size = aead_tag_size;
	session->session_type = SPDM_SESSION_TYPE_ENC_MAC;
	session->aead_key_size = 32;
	memcpy (session->data_secret.response_data_encryption_key, aes_key, 32);
	session->aead_iv_size = 12;

	request.payload_length = plaintext_payload_length;
	request.max_response = (sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) + aead_tag_size +
		plaintext_payload_length + sizeof (struct spdm_secured_message_cipher_header));
	request.payload = buf + sizeof (struct spdm_secured_message_data_header_1) +
		sizeof (struct spdm_secured_message_data_header_2) +
		sizeof (struct spdm_secured_message_cipher_header);
	((struct spdm_protocol_header*) request.payload)->req_rsp_code = SPDM_RESPONSE_END_SESSION;

	status = mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.set_key, &testing.aes_mock,
		0, MOCK_ARG_PTR_CONTAINS_TMP (aes_key, sizeof (aes_key)), MOCK_ARG (sizeof (aes_key)));

	status |= mock_expect (&testing.aes_mock.mock, testing.aes_mock.base.encrypt_with_add_data,
		&testing.aes_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,	MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	// Get END_SESSION response and ensure that observer is not notified.
	status = session_manager->encode_secure_message (session_manager, &request);
	CuAssertIntEquals (test, 0, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

static void spdm_secure_session_manager_test_remove_spdm_protocol_session_observer_invalid_arg (
	CuTest *test)
{
	int status;
	struct spdm_secure_session_manager_testing testing;


	TEST_START;

	spdm_secure_session_manager_testing_init_dependencies (test, &testing);

	status = spdm_secure_session_manager_init (&testing.session_manager, &testing.state,
		&testing.local_capabilities,
		(const struct spdm_device_algorithms*) &testing.local_algorithms, &testing.aes_mock.base,
		&testing.hash_engine_mock.base, &testing.rng_mock.base, &testing.ecc_mock.base,
		&testing.transcript_manager_mock.base, &testing.hkdf_mock.base, NULL, testing.algo_info);
	CuAssertIntEquals (test, 0, status);

	status = spdm_secure_session_manager_remove_spdm_protocol_session_observer (NULL,
		&testing.observer.base);
	CuAssertIntEquals (test, SPDM_SECURE_SESSION_MANAGER_INVALID_ARGUMENT, status);

	status =
		spdm_secure_session_manager_remove_spdm_protocol_session_observer (&testing.session_manager,
		NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	spdm_secure_session_manager_testing_release (test, &testing);
}

// *INDENT-OFF*
TEST_SUITE_START (spdm_secure_session_manager);

/* TODO:  Add additional test coverage for multi-session handling where applicable. */
TEST (spdm_secure_session_manager_test_static_init);
TEST (spdm_secure_session_manager_test_static_init_invalid_params);
TEST (spdm_secure_session_manager_test_init);
TEST (spdm_secure_session_manager_test_init_invalid_params);
TEST (spdm_secure_session_manager_test_release_null);
TEST (spdm_secure_session_manager_test_create_session);
TEST (spdm_secure_session_manager_test_create_session_enc_mac);
TEST (spdm_secure_session_manager_test_create_session_mac_only);
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
TEST (spdm_secure_session_manager_test_generate_shared_secret_pct_fail);
TEST (spdm_secure_session_manager_test_generate_shared_secret_pct_fail_algo_info);
TEST (spdm_secure_session_manager_test_generate_shared_secret_get_public_key_der_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys2);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_invalid_param);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_get_hash_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_extract_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_extract2_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_update_prk_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_update_prk2_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand1_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand2_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand3_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand4_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand5_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand6_fail);
TEST (spdm_secure_session_manager_test_generate_session_handshake_keys_hkdf_expand7_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys);
TEST (spdm_secure_session_manager_test_generate_session_data_keys2);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_invalid_param);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_extract_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_extract2_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_update_prk_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_update_prk2_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand1_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand2_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand3_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_hkdf_expand4_fail);
TEST (spdm_secure_session_manager_test_generate_session_data_keys_get_hash_fail);
TEST (spdm_secure_session_manager_test_decode_secure_message);
TEST (spdm_secure_session_manager_test_decode_secure_message_invalid_param);
TEST (spdm_secure_session_manager_test_decode_secure_message_payload_lt_min);
TEST (spdm_secure_session_manager_test_decode_secure_message_no_session);
TEST (spdm_secure_session_manager_test_decode_secure_message_sequence_number_overflow_session_state_handshaking);
TEST (spdm_secure_session_manager_test_decode_secure_message_sequence_number_overflow_session_state_established);
TEST (spdm_secure_session_manager_test_decode_secure_message_payload_incorrect_length);
TEST (spdm_secure_session_manager_test_decode_secure_message_payload_incorrect_length_2);
TEST (spdm_secure_session_manager_test_decode_secure_message_payload_incorrect_length_3);
TEST (spdm_secure_session_manager_test_decode_secure_message_set_key_fail);
TEST (spdm_secure_session_manager_test_decode_secure_message_decrypt_with_add_data_fail);
TEST (spdm_secure_session_manager_test_decode_secure_message_plaintext_size_gt_ciphertext_size);
TEST (spdm_secure_session_manager_test_encode_secure_message_finish_response);
TEST (spdm_secure_session_manager_test_encode_secure_message_end_session_response);
TEST (spdm_secure_session_manager_test_encode_secure_message_invalid_param);
TEST (spdm_secure_session_manager_test_encode_secure_message_last_spdm_request_secure_session_id_invalid);
TEST (spdm_secure_session_manager_test_encode_secure_message_no_session);
TEST (spdm_secure_session_manager_test_encode_secure_message_sequence_number_overflow_session_state_handshaking);
TEST (spdm_secure_session_manager_test_encode_secure_message_sequence_number_overflow_session_state_established);
TEST (spdm_secure_session_manager_test_encode_secure_message_max_response_size_lt_required);
TEST (spdm_secure_session_manager_test_encode_secure_message_set_key_fail);
TEST (spdm_secure_session_manager_test_encode_secure_message_encrypt_with_add_data_fail);
TEST (spdm_secure_session_manager_test_is_termination_policy_set);
TEST (spdm_secure_session_manager_test_is_termination_policy_set_not_set);
TEST (spdm_secure_session_manager_test_is_termination_policy_set_invalid_session_id);
TEST (spdm_secure_session_manager_test_is_termination_policy_set_no_established_session);
TEST (spdm_secure_session_manager_test_is_termination_policy_set_invalid_param);
TEST (spdm_secure_session_manager_test_add_spdm_protocol_session_observer_invalid_arg);
TEST (spdm_secure_session_manager_test_remove_spdm_protocol_session_observer);
TEST (spdm_secure_session_manager_test_remove_spdm_protocol_session_observer_invalid_arg);

TEST_SUITE_END;
// *INDENT-ON*
