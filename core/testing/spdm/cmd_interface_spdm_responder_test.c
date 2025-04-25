// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "spdm/cmd_interface_spdm_responder_static.h"
#include "spdm/spdm_commands.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rng_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/mock/cmd_interface/cmd_interface_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/spdm/spdm_measurements_mock.h"
#include "testing/mock/spdm/spdm_measurements_mock.h"
#include "testing/mock/spdm/spdm_secure_session_manager_mock.h"
#include "testing/mock/spdm/spdm_transcript_manager_mock.h"
#include "testing/mock/spdm/spdm_transcript_manager_mock.h"
#include "testing/riot/riot_core_testing.h"


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

#define SECURED_MESSAGE_VERSION_COUNT	2

/**
 * Dependencies for testing.
 */
struct cmd_interface_spdm_responder_testing {
	struct cmd_interface_spdm_responder spdm_responder;											/**< The SPDM responder being tested. */
	struct spdm_state spdm_responder_state;														/**< The SPDM responder state. */
	struct spdm_transcript_manager_state state;													/**< The transcript manager state. */
	struct spdm_transcript_manager_mock transcript_manager_mock;								/**< The transcript manager. */
	struct spdm_transcript_manager_state transcript_manager_state;								/**< The transcript manager state. */
	struct spdm_secure_session_manager_mock session_manager_mock;								/**< The session manager. */
	struct spdm_secure_session_manager_state session_manager_state;								/**< The session manager state. */
	struct hash_engine_mock hash_engine_mock[SPDM_RESPONDER_HASH_ENGINE_REQUIRED_COUNT];		/**< Mock hash engine for the responder. */
	const struct hash_engine *hash_engine[SPDM_RESPONDER_HASH_ENGINE_REQUIRED_COUNT];			/**< Hash engines. */
	struct spdm_version_num_entry version_num[1];												/**< Version number entries. */
	struct spdm_version_num_entry secure_message_version_num[SECURED_MESSAGE_VERSION_COUNT];	/**< Secured version number entries. */
	struct spdm_device_capability local_capabilities;											/**< Local capabilities. */
	struct spdm_local_device_algorithms local_algorithms;										/**< Local algorithms. */
	struct riot_key_manager_state key_state;													/**< Context for the device key manager. */
	struct riot_key_manager key_manager;														/**< Device key manager for testing. */
	struct keystore_mock keystore;																/**< Mock for the device keystore. */
	X509_TESTING_ENGINE (x509);																	/**< X.509 engine for the key manager. */
	struct riot_keys keys;																		/**< RIoT keys for testing. */
	struct spdm_measurements_mock measurements_mock;											/**< Mock measurements engine. */
	struct ecc_engine_mock ecc_mock;															/**< Mock ECC engine. */
	struct rng_engine_mock rng_mock;															/**< Mock RNG engine. */
	struct cmd_interface_mock vdm_mock;															/**< Mock for VDM command handler */
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
	struct spdm_version_num_entry version_num[1] =
	{{0, 0, 2, 1}};
	struct spdm_version_number secure_message_version_num[SECURED_MESSAGE_VERSION_COUNT] =
	{{0, 0, 0, 1}, {0, 0, 1, 1}};
	uint8_t idx;
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;

	memcpy (testing->version_num, version_num, sizeof (version_num));
	memcpy (testing->secure_message_version_num, secure_message_version_num,
		sizeof (secure_message_version_num));

	status = spdm_transcript_manager_mock_init (&testing->transcript_manager_mock);
	CuAssertIntEquals (test, 0, status);

	for (idx = 0; idx < ARRAY_SIZE (testing->hash_engine_mock); idx++) {
		status = hash_mock_init (&testing->hash_engine_mock[idx]);
		CuAssertIntEquals (test, 0, status);
		testing->hash_engine[idx] = &testing->hash_engine_mock[idx].base;
	}

	/* Set the default capabilities. */
	memset (&testing->local_capabilities, 0, sizeof (testing->local_capabilities));
	testing->local_capabilities.ct_exponent = SPDM_MAX_CT_EXPONENT;
	testing->local_capabilities.flags.cache_cap = 0;
	testing->local_capabilities.flags.cert_cap = 1;
	testing->local_capabilities.flags.chal_cap = 1;
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

	status = X509_TESTING_ENGINE_INIT (&testing->x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&testing->keystore);
	CuAssertIntEquals (test, 0, status);

	testing->keys.devid_csr = RIOT_CORE_DEVID_CSR_384;
	testing->keys.devid_csr_length = RIOT_CORE_DEVID_CSR_384_LEN;
	testing->keys.devid_cert = RIOT_CORE_DEVID_CERT_384;
	testing->keys.devid_cert_length = RIOT_CORE_DEVID_CERT_384_LEN;
	testing->keys.alias_key = RIOT_CORE_ALIAS_KEY_384;
	testing->keys.alias_key_length = RIOT_CORE_ALIAS_KEY_384_LEN;
	testing->keys.alias_cert = RIOT_CORE_ALIAS_CERT_384;
	testing->keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_384_LEN;

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_ECC384_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	int_der = platform_malloc (X509_CERTCA_ECC384_CA2_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, int_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_INTR_SIGNED_CERT_384,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN);
	memcpy (ca_der, X509_CERTSS_ECC384_CA_NOPL_DER, X509_CERTSS_ECC384_CA_NOPL_DER_LEN);
	memcpy (int_der, X509_CERTCA_ECC384_CA2_NOPL_DER, X509_CERTCA_ECC384_CA2_NOPL_DER_LEN);

	status = mock_expect (&testing->keystore.mock, testing->keystore.base.load_key,
		&testing->keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&testing->keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	status |= mock_expect_output_tmp (&testing->keystore.mock, 2,
		&RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN,
		sizeof (RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN), -1);

	status |= mock_expect (&testing->keystore.mock, testing->keystore.base.load_key,
		&testing->keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&testing->keystore.mock, 1, &ca_der, sizeof (ca_der), -1);
	status |= mock_expect_output_tmp (&testing->keystore.mock, 2,
		&X509_CERTSS_ECC384_CA_NOPL_DER_LEN, sizeof (X509_CERTSS_ECC384_CA_NOPL_DER_LEN), -1);

	status |= mock_expect (&testing->keystore.mock, testing->keystore.base.load_key,
		&testing->keystore, 0, MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&testing->keystore.mock, 1, &int_der, sizeof (int_der), -1);
	status |= mock_expect_output_tmp (&testing->keystore.mock, 2,
		&X509_CERTCA_ECC384_CA2_NOPL_DER_LEN, sizeof (X509_CERTCA_ECC384_CA2_NOPL_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_init_static_keys (&testing->key_manager, &testing->key_state,
		&testing->keystore.base, &testing->keys, &testing->x509.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_measurements_mock_init (&testing->measurements_mock);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&testing->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&testing->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status = spdm_secure_session_manager_mock_init (&testing->session_manager_mock);
	CuAssertIntEquals (test, 0, status);

	status = cmd_interface_mock_init (&testing->vdm_mock);
	CuAssertIntEquals (test, 0, status);
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
	int status = 0;
	uint8_t idx;

	for (idx = 0; idx < ARRAY_SIZE (testing->hash_engine_mock); idx++) {
		status |= hash_mock_validate_and_release (&testing->hash_engine_mock[idx]);
	}

	status |= spdm_transcript_manager_mock_validate_and_release (&testing->transcript_manager_mock);
	status |= keystore_mock_validate_and_release (&testing->keystore);
	status |= spdm_measurements_mock_validate_and_release (&testing->measurements_mock);
	status |= ecc_mock_validate_and_release (&testing->ecc_mock);
	status |= rng_mock_validate_and_release (&testing->rng_mock);
	status |=
		spdm_secure_session_manager_mock_validate_and_release (&testing->session_manager_mock);
	status |= cmd_interface_mock_validate_and_release (&testing->vdm_mock);

	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&testing->key_manager);
	X509_TESTING_ENGINE_RELEASE (&testing->x509);
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
		testing->hash_engine, ARRAY_SIZE (testing->hash_engine), testing->version_num,
		ARRAY_SIZE (testing->version_num), testing->secure_message_version_num,
		ARRAY_SIZE (testing->secure_message_version_num), &testing->local_capabilities,
		&testing->local_algorithms,	&testing->key_manager, &testing->measurements_mock.base,
		&testing->ecc_mock.base, &testing->rng_mock.base, &testing->session_manager_mock.base,
		&testing->vdm_mock.base);
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
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, spdm_responder.base.process_response);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_non_secure (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		NULL, 0, &testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base, NULL,
		NULL);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, spdm_responder.base.process_response);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_invalid_arg (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (NULL, &testing.transcript_manager_mock.base,
		testing.hash_engine, ARRAY_SIZE (testing.hash_engine), testing.version_num,
		ARRAY_SIZE (testing.version_num), testing.secure_message_version_num,
		ARRAY_SIZE (testing.secure_message_version_num), &testing.local_capabilities,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder2 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state, NULL,
		testing.hash_engine, ARRAY_SIZE (testing.hash_engine), testing.version_num,
		ARRAY_SIZE (testing.version_num), testing.secure_message_version_num,
		ARRAY_SIZE (testing.secure_message_version_num), &testing.local_capabilities,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder3 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, NULL, ARRAY_SIZE (testing.hash_engine),
		testing.version_num, ARRAY_SIZE (testing.version_num), testing.secure_message_version_num,
		ARRAY_SIZE (testing.secure_message_version_num), &testing.local_capabilities,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder4 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine) - 1, testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder5 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), NULL,	ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder6 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, 0,
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder7 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		NULL, ARRAY_SIZE (testing.secure_message_version_num), &testing.local_capabilities,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder8 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num), NULL,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder9 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, NULL, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder10 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, NULL,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder11 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager, NULL,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base,
		&testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder12 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, NULL, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder13 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, NULL,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	struct cmd_interface_spdm_responder spdm_responder14 =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base, NULL,
		&testing.vdm_mock.base);

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

	/* hash_engine_count < SPDM_RESPONDER_HASH_ENGINE_REQUIRED_COUNT */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder4);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder5);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num_count = 0 */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder6);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* secure_message_version_num > 0 && secure_message_version_num = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder7);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder8);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder9);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* key_manager = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder10);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* measurements = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder11);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* ecc = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder12);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* rng = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder13);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* session_manager = NULL */
	status = cmd_interface_spdm_responder_init_state (&spdm_responder14);
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
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

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
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_data_transfer_size_lt_min_size (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size = SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2 - 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_data_transfer_size_gt_max_size (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size =
		testing.local_capabilities.max_spdm_msg_size + 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_static_init_data_transfer_size_ne_max_size (
	CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.flags.chunk_cap = 0;
	testing.local_capabilities.max_spdm_msg_size =
		testing.local_capabilities.data_transfer_size + 1;

	const struct cmd_interface_spdm_responder spdm_responder =
		cmd_interface_spdm_responder_static_init (&testing.spdm_responder_state,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);

	status = cmd_interface_spdm_responder_init_state (&spdm_responder);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_deinit (&spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, &testing.vdm_mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_response);

	cmd_interface_spdm_responder_deinit (&testing.spdm_responder);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init_non_secure (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		NULL, 0, &testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base, NULL,
		NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_request);
	CuAssertPtrNotNull (test, testing.spdm_responder.base.process_response);

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
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* state = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder, NULL,
		&testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_INVALID_ARGUMENT, status);

	/* transcript_manager = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, NULL, testing.hash_engine, ARRAY_SIZE (testing.hash_engine),
		testing.version_num, ARRAY_SIZE (testing.version_num), testing.secure_message_version_num,
		ARRAY_SIZE (testing.secure_message_version_num), &testing.local_capabilities,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* hash_engine = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, NULL,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* hash_engine_count < SPDM_RESPONDER_HASH_ENGINE_REQUIRED_COUNT */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine) - 1, testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), NULL, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* version_num_count = 0 */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, 0,
		testing.secure_message_version_num, ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* secure_message_version_num_count > 0 && secure_message_version_num = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		NULL, ARRAY_SIZE (testing.secure_message_version_num), &testing.local_capabilities,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base, &testing.rng_mock.base,	&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_capabilities = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num), NULL,
		&testing.local_algorithms, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base,	&testing.rng_mock.base, &testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* local_algorithms = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, NULL, &testing.key_manager, &testing.measurements_mock.base,
		&testing.ecc_mock.base,	&testing.rng_mock.base, &testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* key_manager = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, NULL,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INVALID_ARGUMENT, status);

	/* measurements = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager, NULL,
		&testing.ecc_mock.base,	&testing.rng_mock.base, &testing.session_manager_mock.base, NULL);

	/* ecc = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, NULL, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);

	/* rng = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, NULL,
		&testing.session_manager_mock.base, NULL);

	/* session_manager = NULL */
	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base, NULL,
		NULL);

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
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_INCOMPATIBLE_CAPABILITIES, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init_ct_exponent_gt_max (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.ct_exponent = SPDM_MAX_CT_EXPONENT + 1;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_init_data_transfer_size_lt_min_size (CuTest *test)
{
	int status;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init_dependencies (test, &testing);

	testing.local_capabilities.data_transfer_size = SPDM_MIN_DATA_TRANSFER_SIZE_VERSION_1_2 - 1;

	status = cmd_interface_spdm_responder_init (&testing.spdm_responder,
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
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
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
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
		&testing.spdm_responder_state, &testing.transcript_manager_mock.base, testing.hash_engine,
		ARRAY_SIZE (testing.hash_engine), testing.version_num, ARRAY_SIZE (testing.version_num),
		testing.secure_message_version_num,	ARRAY_SIZE (testing.secure_message_version_num),
		&testing.local_capabilities, &testing.local_algorithms, &testing.key_manager,
		&testing.measurements_mock.base, &testing.ecc_mock.base, &testing.rng_mock.base,
		&testing.session_manager_mock.base, NULL);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_CAPABILITY, status);

	cmd_interface_spdm_responder_testing_release_dependencies (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_version (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	uint8_t expected_buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_get_version_request rq = {0};
	struct spdm_get_version_response *resp = (struct spdm_get_version_response*) buf;
	struct spdm_get_version_response *expected_rsp =
		(struct spdm_get_version_response*) expected_buf;
	struct cmd_interface_msg request;
	size_t version_count = 1;
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset,	&testing.transcript_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_version_request)),
		MOCK_ARG (sizeof (struct spdm_get_version_request)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset, &testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (expected_rsp, sizeof (struct spdm_get_version_response) +
		version_length), MOCK_ARG (sizeof (struct spdm_get_version_response) + version_length),
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
	CuAssertIntEquals (test, 1, resp->version_num_entry_count);

	version_num = spdm_get_version_resp_version_table (resp);
	status = memcmp (version_num, testing.version_num,
		sizeof (struct spdm_version_num_entry) * ARRAY_SIZE (testing.version_num));
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_version_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

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
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.set_spdm_version,
		&testing.transcript_manager_mock.base, 0,
		MOCK_ARG (SPDM_MAKE_VERSION (rq.base_capabilities.header.spdm_major_version,
			rq.base_capabilities.header.spdm_minor_version)));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_capabilities)),
		MOCK_ARG (sizeof (struct spdm_get_capabilities)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
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
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

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
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	uint8_t rq_copy[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA),	MOCK_ARG_PTR_CONTAINS (&rq_copy, req_length),
		MOCK_ARG (req_length), MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_VCA), MOCK_ARG_PTR_PTR_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_negotiate_algorithms_response_no_ext_alg)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.set_hash_algo,	&testing.transcript_manager_mock.base,
		0, MOCK_ARG_NOT_NULL);

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
	CuAssertIntEquals (test, local_algorithms->device_algorithms.measurement_spec,
		rsp->measurement_specification);
	CuAssertIntEquals (test,
		local_algorithms->device_algorithms.other_params_support.opaque_data_format,
		rsp->other_params_selection.opaque_data_format);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.measurement_hash_algo,
		rsp->measurement_hash_algo);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.base_asym_algo,
		rsp->base_asym_sel);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.base_hash_algo,
		rsp->base_hash_sel);

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
		resp_no_ext_alg->algstruct_table[3].alg_supported);

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
	CuAssertIntEquals (test,
		local_algorithms->device_algorithms.other_params_support.opaque_data_format,
		spdm_state->connection_info.peer_algorithms.other_params_support.opaque_data_format);
	CuAssertIntEquals (test, local_algorithms->device_algorithms.req_base_asym_alg,
		spdm_state->connection_info.peer_algorithms.req_base_asym_alg);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_negotiate_algorithms_fail (
	CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNEXPECTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_digests (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_get_digests_request rq = {0};
	struct spdm_get_digests_response *rsp = (struct spdm_get_digests_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	uint8_t expected_digest[SHA384_HASH_LENGTH] = {
		0xe0, 0xd3, 0x9f, 0x09, 0xd2, 0xea, 0x3c,
		0x9b, 0x0a, 0xeb, 0xb0, 0x50, 0xd9, 0x4f, 0x31, 0x44, 0xa7, 0x5e, 0x17, 0xd2, 0x15, 0x23,
		0x5f, 0xd3, 0x25, 0x0f, 0x0e, 0x56, 0x2a, 0xaf, 0x29, 0xde, 0x0e, 0xe9, 0x51, 0xe1, 0xdc,
		0x01, 0x81, 0x88, 0x50, 0xd2, 0x2a, 0x4a, 0x0d, 0xce, 0xca, 0x01
	};

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_digests_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;

	rq.header.req_rsp_code = SPDM_REQUEST_GET_DIGESTS;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.spdm_minor_version = 2;
	rq.reserved = 0;
	rq.reserved2 = 0;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_digests_request));

	spdm_state->connection_info.peer_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_digests_request)),
		MOCK_ARG (sizeof (struct spdm_get_digests_request)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.calculate_sha384, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC384_CA_NOPL_DER, X509_CERTSS_ECC384_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC384_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	for (uint8_t i = 0; i < SPDM_MAX_CERT_COUNT_IN_CHAIN; i++) {
		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	}

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.hash_engine_mock[0].mock, 0, expected_digest,
		sizeof (expected_digest), -1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG_PTR_CONTAINS (rsp,	sizeof (struct spdm_get_digests_response) + SHA384_HASH_LENGTH),
		MOCK_ARG (sizeof (struct spdm_get_digests_response) + SHA384_HASH_LENGTH), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_get_digests_response) +
		SHA384_HASH_LENGTH, request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_DIGESTS, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 1, rsp->slot_mask);
	CuAssertIntEquals (test, SPDM_CONNECTION_STATE_AFTER_DIGESTS,
		spdm_state->connection_info.connection_state);

	status = memcmp (expected_digest, rsp + 1, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_digests_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_get_digests_request *rq = (struct spdm_get_digests_request*) buf;
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
	request.payload_length = sizeof (struct spdm_get_digests_request) - 1;
	request.length = request.payload_length;

	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_DIGESTS;

	TEST_START;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_certificate (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_get_certificate_request rq = {0};
	struct spdm_get_certificate_response *rsp = (struct spdm_get_certificate_response*) buf;
	uint32_t cert_chain_length;
	struct spdm_cert_chain_header *cert_chain_header;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_certificate_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;

	rq.header.req_rsp_code = SPDM_REQUEST_GET_CERTIFICATE;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.spdm_minor_version = 2;
	rq.slot_num = 0;
	rq.offset = 0;
	rq.length = 0xFFFF;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_certificate_request));

	spdm_state->connection_info.peer_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;

	cert_chain_length = sizeof (struct spdm_cert_chain_header) + SHA384_HASH_LENGTH +
		X509_CERTSS_ECC384_CA_NOPL_DER_LEN + X509_CERTCA_ECC384_CA2_NOPL_DER_LEN +
		RIOT_CORE_ALIAS_CERT_384_LEN + RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_certificate_request)),
		MOCK_ARG (sizeof (struct spdm_get_certificate_request)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.calculate_sha384, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC384_CA_NOPL_DER, X509_CERTSS_ECC384_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC384_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&testing.hash_engine_mock[0].mock, 2, SHA384_TEST_HASH,
		SHA384_HASH_LENGTH, -1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG_PTR_CONTAINS (rsp,
		(cert_chain_length + sizeof (struct spdm_get_certificate_response))),
		MOCK_ARG (cert_chain_length + sizeof (struct spdm_get_certificate_response)),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_get_certificate_response) + cert_chain_length,
		request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_CERTIFICATE, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, 0, rsp->slot_num);
	CuAssertIntEquals (test, cert_chain_length, rsp->portion_len);
	CuAssertIntEquals (test, 0, rsp->remainder_len);
	CuAssertIntEquals (test, SPDM_CONNECTION_STATE_AFTER_CERTIFICATE,
		spdm_state->connection_info.connection_state);

	cert_chain_header = (struct spdm_cert_chain_header*) (rsp + 1);
	CuAssertIntEquals (test, cert_chain_length, cert_chain_header->length);
	CuAssertIntEquals (test, 0, cert_chain_header->reserved);

	status = testing_validate_array (SHA384_TEST_HASH, cert_chain_header + 1, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = memcmp ((uint8_t*) cert_chain_header + sizeof (struct spdm_cert_chain_header) +
		SHA384_HASH_LENGTH, X509_CERTSS_ECC384_CA_NOPL_DER, X509_CERTSS_ECC384_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = memcmp ((uint8_t*) cert_chain_header + sizeof (struct spdm_cert_chain_header) +
		SHA384_HASH_LENGTH + X509_CERTSS_ECC384_CA_NOPL_DER_LEN, X509_CERTCA_ECC384_CA2_NOPL_DER,
		X509_CERTCA_ECC384_CA2_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = memcmp ((uint8_t*) cert_chain_header + sizeof (struct spdm_cert_chain_header) +
		SHA384_HASH_LENGTH + X509_CERTSS_ECC384_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC384_CA2_NOPL_DER_LEN, RIOT_CORE_DEVID_INTR_SIGNED_CERT_384,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN);
	CuAssertIntEquals (test, 0, status);

	status = memcmp ((uint8_t*) cert_chain_header + sizeof (struct spdm_cert_chain_header) +
		SHA384_HASH_LENGTH + X509_CERTSS_ECC384_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC384_CA2_NOPL_DER_LEN + RIOT_CORE_DEVID_INTR_SIGNED_CERT_384_LEN,
		RIOT_CORE_ALIAS_CERT_384, RIOT_CORE_ALIAS_CERT_384_LEN);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_certificate_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_get_certificate_request *rq = (struct spdm_get_certificate_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_certificate_request) - 1;
	request.length = request.payload_length;

	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;
	rq->slot_num = 0;
	rq->offset = 0;
	rq->length = 0xFFFF;
	rq->header.req_rsp_code = SPDM_REQUEST_GET_CERTIFICATE;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = spdm_responder->base.process_request (&spdm_responder->base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_challenge (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_challenge_request rq = {0};
	struct spdm_challenge_response *rsp = (struct spdm_challenge_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	uint8_t expected_nonce[SPDM_NONCE_LEN];
	uint32_t i;
	uint8_t expected_digest[SHA384_HASH_LENGTH] = {
		0xe0, 0xd3, 0x9f, 0x09, 0xd2, 0xea, 0x3c, 0x9b,
		0x0a, 0xeb, 0xb0, 0x50, 0xd9, 0x4f, 0x31, 0x44,
		0xa7, 0x5e, 0x17, 0xd2, 0x15, 0x23, 0x5f, 0xd3,
		0x25, 0x0f, 0x0e, 0x56, 0x2a, 0xaf, 0x29, 0xde,
		0x0e, 0xe9, 0x51, 0xe1, 0xdc, 0x01, 0x81, 0x88,
		0x50, 0xd2, 0x2a, 0x4a, 0x0d, 0xce, 0xca, 0x01
	};
	uint32_t hash_size = SHA384_HASH_LENGTH;
	uint32_t signature_size = (ECC_KEY_LENGTH_384 << 1);
	uint32_t response_size = sizeof (struct spdm_challenge_response) + 2 * hash_size +
		SPDM_NONCE_LEN + sizeof (uint16_t) + signature_size;
	uint16_t expected_opaque_size = 0;
	uint8_t *response_ptr;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_challenge_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_state->connection_info.peer_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;
	spdm_state->connection_info.peer_algorithms.base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
	spdm_state->connection_info.peer_algorithms.measurement_spec = SPDM_MEASUREMENT_SPEC_DMTF;
	spdm_state->connection_info.peer_algorithms.measurement_hash_algo =
		SPDM_MEAS_RSP_TPM_ALG_SHA_384;

	rq.header.req_rsp_code = SPDM_REQUEST_CHALLENGE;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.spdm_minor_version = 2;
	rq.req_measurement_summary_hash_type = SPDM_MEASUREMENT_SUMMARY_HASH_ALL;
	rq.slot_num = 0;

	for (i = 0; i < SPDM_NONCE_LEN; i++) {
		rq.nonce[i] = rand ();
		expected_nonce[i] = rand ();
	}
	memcpy (request.payload, &rq, sizeof (struct spdm_challenge_request));

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2), MOCK_ARG_PTR (request.payload),
		MOCK_ARG (request.payload_length), MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.calculate_sha384, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC384_CA_NOPL_DER, X509_CERTSS_ECC384_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC384_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	for (uint8_t i = 0; i < SPDM_MAX_CERT_COUNT_IN_CHAIN; i++) {
		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	}

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.hash_engine_mock[0].mock, 0, expected_digest,
		sizeof (expected_digest), -1);

	status |= mock_expect (&testing.rng_mock.mock, testing.rng_mock.base.generate_random_buffer,
		&testing.rng_mock, 0, MOCK_ARG (SPDM_NONCE_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.rng_mock.mock, 1, expected_nonce, SPDM_NONCE_LEN, -1);

	status |= mock_expect (&testing.measurements_mock.mock,
		testing.measurements_mock.base.get_measurement_summary_hash,
		&testing.measurements_mock.base, 0,	MOCK_ARG_PTR (testing.hash_engine[0]),
		MOCK_ARG (HASH_TYPE_SHA384), MOCK_ARG_PTR (testing.hash_engine[1]),
		MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG (rq.req_measurement_summary_hash_type == SPDM_MEASUREMENT_SUMMARY_HASH_TCB),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&testing.measurements_mock.mock, 5, expected_digest, hash_size,
		-1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG_PTR_CONTAINS (rsp, response_size - signature_size),
		MOCK_ARG (response_size - signature_size), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2), MOCK_ARG (true), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.get_active_algorithm, &testing.hash_engine_mock[0].base,
		HASH_TYPE_SHA384);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&testing.hash_engine_mock[0].mock, 0, SHA384_TEST_HASH,
		SHA384_HASH_LENGTH, -1);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_key_pair,
		&testing.ecc_mock.base, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY_384, RIOT_CORE_ALIAS_KEY_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.sign,
		&testing.ecc_mock.base, ECC384_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P384_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&testing.ecc_mock.mock, 4, ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN, 5);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, response_size, request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_CHALLENGE, rsp->header.req_rsp_code);

	response_ptr = (uint8_t*) (rsp + 1);
	status = testing_validate_array (expected_digest, response_ptr, hash_size);
	CuAssertIntEquals (test, 0, status);
	response_ptr += hash_size;

	status = testing_validate_array (expected_nonce, response_ptr, SPDM_NONCE_LEN);
	CuAssertIntEquals (test, 0, status);
	response_ptr += SPDM_NONCE_LEN;

	status = testing_validate_array (expected_digest, response_ptr, hash_size);
	CuAssertIntEquals (test, 0, status);
	response_ptr += hash_size;

	status = testing_validate_array (&expected_opaque_size, response_ptr, sizeof (uint16_t));
	CuAssertIntEquals (test, 0, status);
	response_ptr += sizeof (uint16_t);

	status = testing_validate_array (ECC384_SIGNATURE_TEST_STRUCT.r, response_ptr,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);
	response_ptr += ECC_KEY_LENGTH_384;

	status = testing_validate_array (ECC384_SIGNATURE_TEST_STRUCT.s, response_ptr,
		ECC_KEY_LENGTH_384);
	CuAssertIntEquals (test, 0, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_challenge_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_challenge_request rq = {0};
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
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_challenge_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;
	spdm_state->connection_info.peer_algorithms.measurement_spec = SPDM_MEASUREMENT_SPEC_DMTF;
	spdm_state->connection_info.peer_algorithms.measurement_hash_algo =
		SPDM_MEAS_RSP_TPM_ALG_SHA_384;

	rq.header.req_rsp_code = SPDM_REQUEST_CHALLENGE;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.spdm_minor_version = 2;
	rq.req_measurement_summary_hash_type = SPDM_MEASUREMENT_SUMMARY_HASH_ALL;
	rq.slot_num = 0;

	memcpy (request.payload, &rq, sizeof (struct spdm_challenge_request));

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNEXPECTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_measurements (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_get_measurements_request rq = {0};
	struct spdm_get_measurements_response *rsp = (struct spdm_get_measurements_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	const uint32_t measurement_count = 10;
	const uint32_t measurement_length = 128;
	uint8_t expected_nonce[SPDM_NONCE_LEN];
	uint8_t expected_measurement_record[measurement_length];
	uint32_t i;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = buf;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_get_measurements_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_state->connection_info.peer_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;
	spdm_state->connection_info.peer_algorithms.measurement_spec = SPDM_MEASUREMENT_SPEC_DMTF;
	spdm_state->connection_info.peer_algorithms.measurement_hash_algo =
		SPDM_MEAS_RSP_TPM_ALG_SHA_384;

	rq.header.req_rsp_code = SPDM_REQUEST_GET_MEASUREMENTS;
	rq.header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq.header.spdm_minor_version = 2;
	rq.sig_required = false;
	rq.raw_bit_stream_requested = true;
	rq.measurement_operation = SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_ALL_MEASUREMENTS;
	memcpy (request.payload, &rq, sizeof (struct spdm_get_measurements_request));

	for (i = 0; i < SPDM_NONCE_LEN; i++) {
		expected_nonce[i] = rand ();
	}
	for (i = 0; i < measurement_length; i++) {
		expected_measurement_record[i] = rand ();
	}

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG_PTR_CONTAINS (&rq, sizeof (struct spdm_get_measurements_request)),
		MOCK_ARG (sizeof (struct spdm_get_measurements_request)), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.measurements_mock.mock,
		testing.measurements_mock.base.get_measurement_count, &testing.measurements_mock.base,
		measurement_count);

	status |= mock_expect (&testing.measurements_mock.mock,
		testing.measurements_mock.base.get_all_measurement_blocks, &testing.measurements_mock.base,
		measurement_length,	MOCK_ARG (rq.raw_bit_stream_requested),
		MOCK_ARG_PTR (&testing.hash_engine_mock[0].base), MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG_NOT_NULL, MOCK_ARG (request.max_response - SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH));
	status |= mock_expect_output (&testing.measurements_mock.mock, 3, expected_measurement_record,
		measurement_length, -1);

	status |= mock_expect (&testing.rng_mock.mock, testing.rng_mock.base.generate_random_buffer,
		&testing.rng_mock, 0, MOCK_ARG (SPDM_NONCE_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&testing.rng_mock.mock, 1, expected_nonce, SPDM_NONCE_LEN, -1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG_PTR_CONTAINS (rsp,	(SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH + measurement_length)),
		MOCK_ARG (SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH + measurement_length), MOCK_ARG (false),
		MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_GET_MEASUREMENTS_RESP_MIN_LENGTH + measurement_length,
		request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_GET_MEASUREMENTS, rsp->header.req_rsp_code);
	CuAssertIntEquals (test, measurement_count, rsp->number_of_blocks);
	CuAssertIntEquals (test, 0,
		memcmp (&measurement_length, rsp->measurement_record_len,
		sizeof (rsp->measurement_record_len)));
	CuAssertIntEquals (test, 0,
		memcmp (&expected_measurement_record, spdm_get_measurements_resp_measurement_record (rsp),
		measurement_length));
	CuAssertIntEquals (test, 0,
		memcmp (&expected_nonce, spdm_get_measurements_resp_nonce (rsp), SPDM_NONCE_LEN));

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_get_measurements_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_get_measurements_request *rq = (struct spdm_get_measurements_request*) buf;
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
	request.payload_length = sizeof (struct spdm_get_measurements_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;

	rq->header.req_rsp_code = SPDM_REQUEST_GET_MEASUREMENTS;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNEXPECTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_key_exchange (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_key_exchange_request *rq = (struct spdm_key_exchange_request*) buf;
	struct spdm_key_exchange_response *rsp = (struct spdm_key_exchange_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	size_t dhe_key_size = (ECC_KEY_LENGTH_384 << 1);
	size_t pub_key_component_size = ECC_KEY_LENGTH_384;
	size_t sig_size = (ECC_KEY_LENGTH_384 << 1);
	uint8_t *ptr;
	uint16_t opaque_rq_data_length = sizeof (struct spdm_general_opaque_data_table_header) +
		sizeof (struct spdm_secured_message_opaque_element_table_header) +
		sizeof (struct spdm_secured_message_opaque_element_supported_version) +
		sizeof (struct spdm_version_number) * 1	/* Secure Version Count */;

	opaque_rq_data_length = (opaque_rq_data_length + 3) & ~3;	/* Add Padding. */

	uint16_t opaque_resp_data_length = sizeof (struct spdm_general_opaque_data_table_header) +
		sizeof (struct spdm_secured_message_opaque_element_table_header) +
		sizeof (struct spdm_secured_message_opaque_element_version_selection);

	opaque_resp_data_length = (opaque_resp_data_length + 3) & ~3;	/* Add Padding. */

	size_t response_size = sizeof (struct spdm_key_exchange_response) + dhe_key_size +
		SHA384_HASH_LENGTH /* measurement summary hash*/ + sizeof (uint16_t) +
		opaque_resp_data_length + sig_size + SHA384_HASH_LENGTH	/* HMAC */;

	struct spdm_general_opaque_data_table_header *general_opaque_data_table_header;
	struct spdm_secured_message_opaque_element_table_header *opaque_element_table_header;
	struct spdm_secured_message_opaque_element_supported_version *opaque_element_support_version;
	struct spdm_version_number *versions_list;
	struct spdm_secure_session secure_session = {0};
	uint8_t idx;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length =
		sizeof (struct spdm_key_exchange_request) + dhe_key_size + sizeof (uint16_t) +
		opaque_rq_data_length;
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;
	spdm_state->connection_info.peer_capabilities.flags.key_ex_cap = 1;
	spdm_state->connection_info.peer_algorithms.measurement_spec = SPDM_MEASUREMENT_SPEC_DMTF;
	spdm_state->connection_info.peer_algorithms.measurement_hash_algo =
		SPDM_MEAS_RSP_TPM_ALG_SHA_384;
	spdm_state->connection_info.peer_algorithms.base_hash_algo = SPDM_TPM_ALG_SHA_384;
	spdm_state->connection_info.peer_algorithms.base_asym_algo = SPDM_TPM_ALG_ECDSA_ECC_NIST_P384;
	spdm_state->connection_info.peer_algorithms.dhe_named_group =
		SPDM_ALG_DHE_NAMED_GROUP_SECP_384_R1;
	spdm_state->connection_info.peer_algorithms.other_params_support.opaque_data_format =
		SPDM_ALGORITHMS_OPAQUE_DATA_FORMAT_1;

	rq->header.req_rsp_code = SPDM_REQUEST_KEY_EXCHANGE;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;
	rq->measurement_summary_hash_type = SPDM_MEASUREMENT_SUMMARY_HASH_TCB;
	rq->slot_id = 0;

	/* Copy the DHE public key. */
	ptr = (uint8_t*) rq + sizeof (struct spdm_key_exchange_request);
	memcpy (ptr, &ECC384_PUBKEY_POINT.x, pub_key_component_size);
	memcpy (&ptr[pub_key_component_size], &ECC384_PUBKEY_POINT.y, pub_key_component_size);
	ptr += dhe_key_size;

	/* Set opaque data length. */
	ptr[0] = (uint8_t) (opaque_rq_data_length & 0xFF);
	ptr[1] = (uint8_t) ((opaque_rq_data_length >> 8) & 0xFF);
	ptr += sizeof (uint16_t);

	general_opaque_data_table_header = (struct spdm_general_opaque_data_table_header*) ptr;
	general_opaque_data_table_header->total_elements = 1;
	opaque_element_table_header =
		(struct spdm_secured_message_opaque_element_table_header*) (general_opaque_data_table_header
			+
			1);
	opaque_element_table_header->id = SPDM_REGISTRY_ID_DMTF;
	opaque_element_table_header->vendor_len = 0;
	opaque_element_table_header->opaque_element_data_len =
		sizeof (struct spdm_secured_message_opaque_element_supported_version) +
		sizeof (struct spdm_version_number) *
		1 /* Secure Version Count */;

	opaque_element_support_version = (void*) (opaque_element_table_header + 1);
	opaque_element_support_version->sm_data_version =
		SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_DATA_VERSION;
	opaque_element_support_version->sm_data_id =
		SPDM_SECURED_MESSAGE_OPAQUE_ELEMENT_SMDATA_ID_SUPPORTED_VERSION;
	opaque_element_support_version->version_count = 1;	/*Secure Version Count */

	versions_list = (void*) (opaque_element_support_version + 1);
	versions_list->major_version = 1;
	versions_list->minor_version = 0;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.create_session, &testing.session_manager_mock.base,
		MOCK_RETURN_PTR (&secure_session), MOCK_ARG_NOT_NULL, MOCK_ARG (false),
		MOCK_ARG_PTR (&spdm_state->connection_info));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.calculate_sha384, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC384_CA_NOPL_DER, X509_CERTSS_ECC384_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC384_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	for (uint8_t i = 0; i < SPDM_MAX_CERT_COUNT_IN_CHAIN; i++) {
		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	}

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base,	0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base,	0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG_PTR (rq), MOCK_ARG (request.payload_length),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.rng_mock.mock, testing.rng_mock.base.generate_random_buffer,
		&testing.rng_mock, 0, MOCK_ARG (SPDM_NONCE_LEN), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.generate_shared_secret,
		&testing.session_manager_mock.base,	0, MOCK_ARG_PTR (&secure_session), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&testing.measurements_mock.mock,
		testing.measurements_mock.base.get_measurement_summary_hash,
		&testing.measurements_mock.base, 0,	MOCK_ARG_PTR (testing.hash_engine[0]),
		MOCK_ARG (HASH_TYPE_SHA384), MOCK_ARG_PTR (testing.hash_engine[1]),
		MOCK_ARG (HASH_TYPE_SHA384),
		MOCK_ARG (rq->measurement_summary_hash_type == SPDM_MEASUREMENT_SUMMARY_HASH_TCB),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (response_size - sig_size - SHA384_HASH_LENGTH	/* HMAC */), MOCK_ARG (true),
		MOCK_ARG (0));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE + SHA384_HASH_LENGTH));

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.get_active_algorithm, &testing.hash_engine_mock[0].base,
		HASH_TYPE_SHA384);

	status |= mock_expect (&testing.hash_engine_mock[0].mock,
		testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&testing.hash_engine_mock[0].mock, 0, SHA384_TEST_HASH,
		SHA384_HASH_LENGTH, -1);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.init_key_pair,
		&testing.ecc_mock.base, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY_384, RIOT_CORE_ALIAS_KEY_384_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_384_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&testing.ecc_mock.mock, 2, 0);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.sign,
		&testing.ecc_mock.base, ECC384_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P384_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&testing.ecc_mock.mock, 4, ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN, 5);

	status |= mock_expect (&testing.ecc_mock.mock, testing.ecc_mock.base.release_key_pair,
		&testing.ecc_mock.base, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base,	0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG_NOT_NULL, MOCK_ARG (sig_size),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.generate_session_handshake_keys,
		&testing.session_manager_mock.base, 0, MOCK_ARG_PTR (&secure_session));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	/* HMAC Rounds. */
	for (idx = 0; idx < 2; idx++) {
		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	}

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base,	0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG (true), MOCK_ARG (0));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.set_session_state, &testing.session_manager_mock.base, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SPDM_SESSION_STATE_HANDSHAKING));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, response_size, request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_KEY_EXCHANGE, rsp->header.req_rsp_code);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_key_exchange_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct spdm_key_exchange_request *rq = (struct spdm_key_exchange_request*) buf;
	struct cmd_interface_msg request;
	int status;
	struct spdm_error_response *error_response = (struct spdm_error_response*) buf;
	struct cmd_interface_spdm_responder_testing testing;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);

	TEST_START;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_key_exchange_request) - 1;
	request.length = request.payload_length;

	rq->header.req_rsp_code = SPDM_REQUEST_KEY_EXCHANGE;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_INVALID_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_finish (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_finish_request *rq = (struct spdm_finish_request*) buf;
	struct spdm_finish_response *rsp = (struct spdm_finish_response*) buf;
	uint8_t rq_copy[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_secure_session session = {0};
	size_t request_size = sizeof (struct spdm_finish_request) + SHA384_HASH_LENGTH;
	uint8_t idx;

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = request_size;
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;

	rq->header.req_rsp_code = SPDM_REQUEST_FINISH;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;
	rq->signature_included = 0;

	session.session_state = SPDM_SESSION_STATE_HANDSHAKING;
	session.hash_size = SHA384_HASH_LENGTH;
	session.session_index = 0;
	session.base_hash_algo = SPDM_TPM_ALG_SHA_384;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 1);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.get_last_session_id, &testing.session_manager_mock.base,
		0xDEADBEEF);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.get_session, &testing.session_manager_mock.base,
		MOCK_RETURN_PTR (&session), MOCK_ARG (0xDEADBEEF));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG_PTR_CONTAINS (rq_copy, sizeof (struct spdm_finish_request)),
		MOCK_ARG (sizeof (struct spdm_finish_request)), MOCK_ARG (true),
		MOCK_ARG (session.session_index));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.get_hash, &testing.transcript_manager_mock, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG (false), MOCK_ARG (true),
		MOCK_ARG (session.session_index), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA384_HASH_LENGTH));

	/* HMAC Rounds. */
	for (idx = 0; idx < 2; idx++) {
		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.start_sha384, &testing.hash_engine_mock[0].base, 0);

		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.update, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

		status |= mock_expect (&testing.hash_engine_mock[0].mock,
			testing.hash_engine_mock[0].base.finish, &testing.hash_engine_mock[0].base, 0,
			MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	}
	status |= mock_expect_output (&testing.hash_engine_mock[0].mock, 0, SHA384_TEST_HASH,
		SHA384_HASH_LENGTH, -1);

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH),
		MOCK_ARG_PTR_CONTAINS (SHA384_TEST_HASH, SHA384_HASH_LENGTH), MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG (true), MOCK_ARG (session.session_index));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.update, &testing.transcript_manager_mock.base, 0,
		MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_TH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_finish_response)), MOCK_ARG (true),
		MOCK_ARG (session.session_index));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.generate_session_data_keys,
		&testing.session_manager_mock.base, 0, MOCK_ARG_PTR (&session));

	CuAssertIntEquals (test, 0, status);

	memcpy (rq_copy, rq, request_size);
	memcpy ((rq + 1), SHA384_TEST_HASH, SHA384_HASH_LENGTH);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_finish_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_FINISH, rsp->header.req_rsp_code);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_finish_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_finish_request *rq = (struct spdm_finish_request*) buf;
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
	request.payload_length = sizeof (struct spdm_finish_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;

	rq->header.req_rsp_code = SPDM_REQUEST_FINISH;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNEXPECTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_end_session (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_end_session_request *rq = (struct spdm_end_session_request*) buf;
	struct spdm_end_session_response *rsp = (struct spdm_end_session_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_secure_session session = {0};

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_end_session_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;

	rq->header.req_rsp_code = SPDM_REQUEST_END_SESSION;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	session.session_state = SPDM_SESSION_STATE_ESTABLISHED;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 1);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.get_last_session_id, &testing.session_manager_mock.base,
		0xDEADBEEF);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.get_session, &testing.session_manager_mock.base,
		MOCK_RETURN_PTR (&session), MOCK_ARG (0xDEADBEEF));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_L1L2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	status |= mock_expect (&testing.transcript_manager_mock.mock,
		testing.transcript_manager_mock.base.reset_transcript,
		&testing.transcript_manager_mock.base, 0, MOCK_ARG (TRANSCRIPT_CONTEXT_TYPE_M1M2),
		MOCK_ARG (false), MOCK_ARG (SPDM_MAX_SESSION_COUNT));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_end_session_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_END_SESSION, rsp->header.req_rsp_code);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_end_session_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_end_session_request *rq = (struct spdm_end_session_request*) buf;
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
	request.payload_length = sizeof (struct spdm_end_session_request);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;

	rq->header.req_rsp_code = SPDM_REQUEST_END_SESSION;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPDM_ERROR_UNEXPECTED_REQUEST, error_response->error_code);
	CuAssertIntEquals (test, 0, error_response->error_data);
	CuAssertIntEquals (test, SPDM_RESPONSE_ERROR, error_response->header.req_rsp_code);
	CuAssertIntEquals (test, sizeof (struct spdm_error_response), request.payload_length);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_vdm (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_vendor_defined_request_response *rq =
		(struct spdm_vendor_defined_request_response*) buf;
	struct spdm_vendor_defined_request_response *rsp =
		(struct spdm_vendor_defined_request_response*) buf;
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
	request.payload_length = sizeof (struct spdm_vendor_defined_request_response);
	request.length = request.payload_length;
	request.is_encrypted = false;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;

	rq->header.req_rsp_code = SPDM_REQUEST_VENDOR_DEFINED_REQUEST;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.vdm_mock.mock, testing.vdm_mock.base.process_request,
		&testing.vdm_mock.base, 0, MOCK_ARG_PTR (&request));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_vendor_defined_request_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_VENDOR_DEFINED_REQUEST, rsp->header.req_rsp_code);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_vdm_encrypt (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_vendor_defined_request_response *rq =
		(struct spdm_vendor_defined_request_response*) buf;
	struct spdm_vendor_defined_request_response *rsp =
		(struct spdm_vendor_defined_request_response*) buf;
	struct cmd_interface_spdm_responder *spdm_responder;
	struct spdm_state *spdm_state;
	struct cmd_interface_spdm_responder_testing testing;
	struct spdm_secure_session session = {0};

	TEST_START;

	cmd_interface_spdm_responder_testing_init (test, &testing);
	spdm_responder = &testing.spdm_responder;
	spdm_state = spdm_responder->state;

	memset (&request, 0, sizeof (request));
	request.data = buf;
	request.payload = (uint8_t*) rq;
	request.max_response = sizeof (buf);
	request.payload_length = sizeof (struct spdm_vendor_defined_request_response);
	request.length = request.payload_length;
	request.is_encrypted = true;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;
	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NEGOTIATED;

	rq->header.req_rsp_code = SPDM_REQUEST_VENDOR_DEFINED_REQUEST;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	session.session_state = SPDM_SESSION_STATE_ESTABLISHED;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.decode_secure_message, &testing.session_manager_mock.base,
		0, MOCK_ARG_PTR (&request));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.is_last_session_id_valid,
		&testing.session_manager_mock.base, 1);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.get_last_session_id, &testing.session_manager_mock.base,
		0xDEADBEEF);

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.get_session, &testing.session_manager_mock.base,
		MOCK_RETURN_PTR (&session), MOCK_ARG (0xDEADBEEF));

	status |= mock_expect (&testing.vdm_mock.mock, testing.vdm_mock.base.process_request,
		&testing.vdm_mock.base, 0, MOCK_ARG_PTR (&request));

	status |= mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.encode_secure_message, &testing.session_manager_mock.base,
		0, MOCK_ARG_PTR (&request));

	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);

	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, sizeof (struct spdm_vendor_defined_request_response), request.length);
	CuAssertIntEquals (test, request.length, request.payload_length);
	CuAssertPtrEquals (test, buf, request.data);
	CuAssertPtrEquals (test, rsp, request.payload);
	CuAssertIntEquals (test, 2, rsp->header.spdm_minor_version);
	CuAssertIntEquals (test, SPDM_MAJOR_VERSION, rsp->header.spdm_major_version);
	CuAssertIntEquals (test, SPDM_RESPONSE_VENDOR_DEFINED_REQUEST, rsp->header.req_rsp_code);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_vdm_fail (CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY] = {0};
	struct cmd_interface_msg request;
	int status;
	struct spdm_vendor_defined_request_response *rq =
		(struct spdm_vendor_defined_request_response*) buf;
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
	request.payload_length = sizeof (struct spdm_vendor_defined_request_response);
	request.length = request.payload_length;

	spdm_state->connection_info.version.major_version = SPDM_MAJOR_VERSION;
	spdm_state->connection_info.version.minor_version = 2;
	spdm_state->response_state = SPDM_RESPONSE_STATE_NORMAL;

	rq->header.req_rsp_code = SPDM_REQUEST_VENDOR_DEFINED_REQUEST;
	rq->header.spdm_major_version = SPDM_MAJOR_VERSION;
	rq->header.spdm_minor_version = 2;

	spdm_state->connection_info.connection_state = SPDM_CONNECTION_STATE_NOT_STARTED;

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

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

static void
cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_short_payload (
	CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = testing.spdm_responder.base.process_request (&testing.spdm_responder.base, &request);
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_PAYLOAD_TOO_SHORT, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}

static void cmd_interface_spdm_responder_test_process_request_unsupported_request_code (
	CuTest *test)
{
	uint8_t buf[MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
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

	status = mock_expect (&testing.session_manager_mock.mock,
		testing.session_manager_mock.base.reset_last_session_id_validity,
		&testing.session_manager_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

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

	status =
		testing.spdm_responder.base.process_response ((const struct cmd_interface*) (0xDEADBEEF),
		(struct cmd_interface_msg*) (0xBAADF00D));
	CuAssertIntEquals (test, CMD_HANDLER_SPDM_RESPONDER_UNSUPPORTED_OPERATION, status);

	cmd_interface_spdm_responder_testing_release (test, &testing);
}


// *INDENT-OFF*
TEST_SUITE_START (cmd_interface_spdm_responder);

TEST (cmd_interface_spdm_responder_test_static_init);
TEST (cmd_interface_spdm_responder_test_static_init_non_secure);
TEST (cmd_interface_spdm_responder_test_static_init_invalid_arg);
TEST (cmd_interface_spdm_responder_test_static_init_incompatible_capabilities);
TEST (cmd_interface_spdm_responder_test_static_init_ct_exponent_gt_max);
TEST (cmd_interface_spdm_responder_test_static_init_data_transfer_size_lt_min_size);
TEST (cmd_interface_spdm_responder_test_static_init_data_transfer_size_gt_max_size);
TEST (cmd_interface_spdm_responder_test_static_init_data_transfer_size_ne_max_size);
TEST (cmd_interface_spdm_responder_test_init);
TEST (cmd_interface_spdm_responder_test_init_non_secure);
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
TEST (cmd_interface_spdm_responder_test_process_request_get_digests);
TEST (cmd_interface_spdm_responder_test_process_request_get_digests_fail);
TEST (cmd_interface_spdm_responder_test_process_request_get_certificate);
TEST (cmd_interface_spdm_responder_test_process_request_get_certificate_fail);
TEST (cmd_interface_spdm_responder_test_process_request_challenge);
TEST (cmd_interface_spdm_responder_test_process_request_challenge_fail);
TEST (cmd_interface_spdm_responder_test_process_request_get_measurements);
TEST (cmd_interface_spdm_responder_test_process_request_get_measurements_fail);
TEST (cmd_interface_spdm_responder_test_process_request_key_exchange);
TEST (cmd_interface_spdm_responder_test_process_request_key_exchange_fail);
TEST (cmd_interface_spdm_responder_test_process_request_finish);
TEST (cmd_interface_spdm_responder_test_process_request_finish_fail);
TEST (cmd_interface_spdm_responder_test_process_request_end_session);
TEST (cmd_interface_spdm_responder_test_process_request_end_session_fail);
TEST (cmd_interface_spdm_responder_test_process_request_vdm);
TEST (cmd_interface_spdm_responder_test_process_request_vdm_encrypt);
TEST (cmd_interface_spdm_responder_test_process_request_vdm_fail);
TEST (cmd_interface_spdm_responder_test_process_request_invalid_arg);
TEST (cmd_interface_spdm_responder_test_process_request_spdm_get_command_id_failure_short_payload);
TEST (cmd_interface_spdm_responder_test_process_request_unsupported_request_code);
TEST (cmd_interface_spdm_responder_test_process_response);

TEST_SUITE_END;
// *INDENT-ON*
