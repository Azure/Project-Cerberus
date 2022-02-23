// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_io.h"
#include "platform.h"
#include "testing.h"
#include "attestation/attestation_master.h"
#include "cmd_interface/device_manager.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/crypto/x509_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("attestation_master");


static struct riot_keys keys = {
	.devid_cert = RIOT_CORE_DEVID_CERT,
	.devid_cert_length = 0,
	.devid_csr = NULL,
	.devid_csr_length = 0,
	.alias_key = RIOT_CORE_ALIAS_KEY,
	.alias_key_length = 0,
	.alias_cert = RIOT_CORE_ALIAS_CERT,
	.alias_cert_length = 0
};


/**
 * Helper function to setup the attestation manager to use mock crypto engines
 *
 * @param test The test framework
 * @param attestation The attestation manager instance to initialize
 * @param hash The hash engine mock to initialize
 * @param ecc The ECC engine mock to initialize
 * @param rsa The RSA engine mock to initialize
 * @param x509 The x509 engine mock to initialize
 * @param rng The RNG engine mock to initialize
 * @param riot RIoT keys manager to initialize
 * @param keystore The keystore to initialize
 * @param manager Device manager to initialize
 */
static void setup_attestation_master_mock_test (CuTest *test,
	struct attestation_master *attestation, struct hash_engine_mock *hash,
	struct ecc_engine_mock *ecc, struct rsa_engine_mock *rsa, struct x509_engine_mock *x509,
	struct rng_engine_mock *rng, struct riot_key_manager *riot, struct keystore_mock *keystore,
	struct device_manager *manager)
{
	uint8_t *dev_id_der = NULL;
	int status;

	status = device_manager_init (manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (riot, &keystore->base, &keys, &x509->base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (attestation, riot, &hash->base, &ecc->base, &rsa->base,
		&x509->base, &rng->base, manager, 1);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release attestation manager instance
 *
 * @param test The test framework
 * @param attestation The attestation manager instance to release
 * @param hash The hash engine mock to release
 * @param ecc The ECC engine mock to release
 * @param rsa The RSA engine mock to release
 * @param x509 The x509 engine mock to release
 * @param rng The RNG engine mock to release
 * @param keystore The keystore mock to release
 * @param manager Device manager to release
 * @param riot RIoT key manager to release
 */
static void complete_attestation_master_mock_test (CuTest *test,
	struct attestation_master *attestation, struct hash_engine_mock *hash,
	struct ecc_engine_mock *ecc, struct rsa_engine_mock *rsa, struct x509_engine_mock *x509,
	struct rng_engine_mock *rng, struct keystore_mock *keystore, struct device_manager *manager,
	struct riot_key_manager *riot)
{
	int status;

	attestation_master_release (attestation);

	status = hash_mock_validate_and_release (hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (riot);
	device_manager_release (manager);
}

/**
 * Helper function to add an intermediate and root CA to RIoT key manager cert chain
 *
 * @param test The test framework
 * @param riot RIoT keys manager to utilize
 * @param keystore The keystore to utilize
 * @param x509 The x509 engine mock to utilize
 * @param dev_id_der Buffer for signed device ID cert
 * @param ca_der Buffer for root CA cert
 * @param int_der Buffer for intermediate CA cert
 */
static void add_int_ca_to_riot_key_manager (CuTest *test, struct riot_key_manager *riot,
	struct keystore_mock *keystore, struct x509_engine_mock *x509, uint8_t **dev_id_der,
 	uint8_t **ca_der, uint8_t **int_der)
{
	int status;

	*dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	*ca_der = platform_malloc (X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	*int_der = platform_malloc (X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, int_der);

	memcpy (*dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	memcpy (*ca_der, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	memcpy (*int_der, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore->mock, 1, dev_id_der, sizeof (*dev_id_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &RIOT_CORE_DEVID_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);
	status |= mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore->mock, 1, ca_der, sizeof (*ca_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &X509_CERTSS_RSA_CA_NOPL_DER_LEN,
		sizeof (X509_CERTSS_RSA_CA_NOPL_DER_LEN), -1);
	status |= mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore->mock, 1, int_der, sizeof (*int_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		sizeof (X509_CERTCA_ECC_CA_NOPL_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509->mock, x509->base.load_certificate, x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	mock_expect_save_arg (&x509->mock, 0, 0);
	status |= mock_expect (&x509->mock, x509->base.init_ca_cert_store, x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509->mock, 0, 1);
	status |= mock_expect (&x509->mock, x509->base.add_root_ca, x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));
	status |= mock_expect (&x509->mock, x509->base.add_intermediate_ca, x509, 0,
		MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));
	status |= mock_expect (&x509->mock, x509->base.add_intermediate_ca, x509, 0,
		MOCK_ARG_SAVED_ARG (1),	MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT,
		RIOT_CORE_DEVID_SIGNED_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));
	status |= mock_expect (&x509->mock, x509->base.authenticate, x509, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509->mock, x509->base.release_ca_cert_store, x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509->mock, x509->base.release_certificate, x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_verify_stored_certs (riot);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void attestation_master_test_init (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, &manager, 1);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, attestation.generate_challenge_request);
	CuAssertPtrNotNull (test, attestation.compare_digests);
	CuAssertPtrNotNull (test, attestation.store_certificate);
	CuAssertPtrNotNull (test, attestation.process_challenge_response);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_init_null (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct device_manager manager;
	struct keystore_mock keystore;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (NULL, &riot, &hash.base, &ecc.base, &rsa.base, &x509.base,
		&rng.base, &manager, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_master_init (&attestation, NULL, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, &manager, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_master_init (&attestation, &riot, NULL, &ecc.base, &rsa.base, &x509.base,
		&rng.base, &manager, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, NULL, &rsa.base, &x509.base,
		&rng.base, &manager, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base, NULL,
		&rng.base, &manager, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, NULL, &manager, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, NULL, 1);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	device_manager_release (&manager);
}

static void attestation_master_test_release_null (CuTest *test)
{
	TEST_START;

	attestation_master_release (NULL);
}

static void attestation_master_test_generate_challenge_request (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t nonce[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG (challenge.nonce));
	status |= mock_expect_output (&rng.mock, 1, &nonce, sizeof (nonce), -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);
	CuAssertIntEquals (test, 0, challenge.slot_num);
	CuAssertPtrNotNull (test, challenge.nonce);

	status = testing_validate_array (nonce, challenge.nonce, sizeof (nonce));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_generate_challenge_request_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 1, &challenge);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_generate_challenge_request_invalid_device (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.generate_challenge_request (&attestation, 0xCC, 0, &challenge);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_generate_challenge_request_rng_fail (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, -1, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_generate_challenge_request_null (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.generate_challenge_request (NULL, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_first (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (3, SHA256_HASH_LENGTH);

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_incomplete_chain_stored (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	digests.num_cert = 2;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (2, SHA256_HASH_LENGTH);

	digests.digest[SHA256_HASH_LENGTH] = 0xAA;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digests.digest, SHA256_HASH_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 2, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_new_chain (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (3, SHA256_HASH_LENGTH);

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	platform_free (digests.digest);

	digests.num_cert = 4;
	digests.digest = platform_calloc (4, SHA256_HASH_LENGTH);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_same (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (3, SHA256_HASH_LENGTH);

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 2, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digests.digest, SHA256_HASH_LENGTH, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &digests.digest[32], SHA256_HASH_LENGTH, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &digests.digest[64], SHA256_HASH_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 0, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_mismatch (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (3, SHA256_HASH_LENGTH);

	digests.digest[32] = 0xAA;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 2, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, digests.digest, SHA256_HASH_LENGTH, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &digests.digest, SHA256_HASH_LENGTH, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &digests.digest[64], SHA256_HASH_LENGTH, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 2, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_hash_fail (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	digests.num_cert = 1;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (1, SHA256_HASH_LENGTH);

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = device_manager_update_cert (attestation.device_manager, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, -1,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, -1, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_invalid_device (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xEE, &digests);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_compare_digests_null (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (NULL, 0xAA, &digests);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.compare_digests (&attestation, 0xAA, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_store_certificate (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[10];

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;
	digests.digest = platform_calloc (3, SHA256_HASH_LENGTH);

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, buf, sizeof (buf));
	CuAssertIntEquals (test, 0, status);

	platform_free (digests.digest);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_store_certificate_invalid_cert_num (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[10];

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 3, buf, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_INVALID_CERT_NUM, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_store_certificate_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[10];

	digests.num_cert = 3;
	digests.digest_len = SHA256_HASH_LENGTH;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 1, 1, buf, sizeof (buf));
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_store_certificate_invalid_device (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[10];


	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.store_certificate (&attestation, 0xEE, 0, 0, buf, sizeof (buf));
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_store_certificate_null (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[10];


	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.store_certificate (NULL, 0xAA, 0, 1, buf, sizeof (buf));
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_3_device_cert_ecc (CuTest *test)
{
	int status;
	X509_TESTING_ENGINE x509;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	TEST_START;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (uint8_t*), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, &manager, 1);
	CuAssertIntEquals (test, 0, status);

	dev_id_der = platform_malloc (X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	int_der = platform_malloc (X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, int_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_INTR_SIGNED_CERT, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	memcpy (int_der, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), -1);
	status |= mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &ca_der, sizeof (ca_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &X509_CERTSS_RSA_CA_NOPL_DER_LEN,
		sizeof (X509_CERTSS_RSA_CA_NOPL_DER_LEN), -1);
	status |= mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &int_der, sizeof (int_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		sizeof (X509_CERTCA_ECC_CA_NOPL_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_verify_stored_certs (&riot);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);
	status |= mock_expect (&ecc.mock, ecc.base.verify, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_PTR_CONTAINS (&buf[72], 65), MOCK_ARG (65));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG (0),
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, X509_CERTSS_RSA_CA_NOPL_DER,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, 0, status);

	attestation_master_release (&attestation);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	X509_TESTING_ENGINE_RELEASE (&x509);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	device_manager_release (&manager);
}

static void attestation_master_test_process_challenge_response_3_device_cert_no_riot_ca_ecc (
	CuTest *test)
{
	int status;
	X509_TESTING_ENGINE x509;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	uint8_t *dev_id_der;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	TEST_START;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (uint8_t*), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, &manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);
	status |= mock_expect (&ecc.mock, ecc.base.verify, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_PTR_CONTAINS (&buf[72], 65), MOCK_ARG (65));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG (0),
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, X509_CERTSS_RSA_CA_NOPL_DER,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, X509_CERTCA_ECC_CA_NOPL_DER,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, 0, status);

	attestation_master_release (&attestation);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	X509_TESTING_ENGINE_RELEASE (&x509);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	device_manager_release (&manager);
}

static void attestation_master_test_process_challenge_response_2_device_cert_ecc (CuTest *test)
{
	int status;
	X509_TESTING_ENGINE x509;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	uint8_t *dev_id_der;
	uint8_t *ca_der;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 2;

	TEST_START;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (uint8_t*), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, &manager, 1);
	CuAssertIntEquals (test, 0, status);

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RIOT_CORE_DEVID_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);
	status |= mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &ca_der, sizeof (ca_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &X509_CERTSS_ECC_CA_NOPL_DER_LEN,
		sizeof (X509_CERTSS_ECC_CA_NOPL_DER_LEN), -1);
	status |= mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_verify_stored_certs (&riot);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);
	status |= mock_expect (&ecc.mock, ecc.base.verify, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_PTR_CONTAINS (&buf[72], 65), MOCK_ARG (65));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG (0),
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0,
		X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1,
		RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, 0, status);

	attestation_master_release (&attestation);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	X509_TESTING_ENGINE_RELEASE (&x509);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	device_manager_release (&manager);
}

static void attestation_master_test_process_challenge_response_2_device_cert_no_riot_ca_ecc (
	CuTest *test)
{
	int status;
	X509_TESTING_ENGINE x509;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	uint8_t *dev_id_der;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 2;

	TEST_START;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (uint8_t*), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, &rsa.base,
		&x509.base, &rng.base, &manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);
	status |= mock_expect (&ecc.mock, ecc.base.verify, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_PTR_CONTAINS (&buf[72], 65), MOCK_ARG (65));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG (0),
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0,
		X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1,
		RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, 0, status);

	attestation_master_release (&attestation);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	X509_TESTING_ENGINE_RELEASE (&x509);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	device_manager_release (&manager);
}

static void attestation_master_test_process_challenge_response_full_chain_rsa (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[329] = {0};
	uint16_t buf_len = 329;
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_RSA,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 3);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0, MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));
	status |= mock_expect (&x509.mock, x509.base.add_intermediate_ca, &x509, 0,
		MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 4);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, 0, MOCK_ARG_SAVED_ARG (4),
		MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&x509.mock, x509.base.get_public_key, &x509, 0, MOCK_ARG_SAVED_ARG (4),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (4));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (3));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_public_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (&buf[72], 257), MOCK_ARG (257), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_invalid_buf_len (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf;
	uint16_t buf_len = 72;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.process_challenge_response (&attestation, &buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_invalid_device (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf;
	uint16_t buf_len = 137;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.process_challenge_response (&attestation, &buf, buf_len, 0xEE);
	CuAssertIntEquals (test, DEVICE_MGR_UNKNOWN_DEVICE, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf = 1;
	uint16_t buf_len = 137;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.process_challenge_response (&attestation, &buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_invalid_min_protocol_version (
	CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[4] = {0, 0, 1, 0};
	uint16_t buf_len = 137;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_PROTOCOL_VERSION, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_invalid_max_protocol_version (
	CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[4] = {0, 0, 1, 1};
	uint16_t buf_len = 137;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	attestation.protocol_version = 2;

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_PROTOCOL_VERSION, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_init_cert_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, X509_ENGINE_NO_MEMORY,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, X509_ENGINE_NO_MEMORY, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_get_pub_key_type_failure (
	CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_ENGINE_NO_MEMORY,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, X509_ENGINE_NO_MEMORY, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_start_hash_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_hash_challenge_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, -1, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_hash_response_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, -1, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_finish_hash_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, -1, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_unsupported_algorithm (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	struct riot_key_manager riot;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, 2,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_ALGORITHM, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_rsa_not_enabled (CuTest *test)
{
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	struct riot_key_manager riot;
	uint8_t *dev_id_der = NULL;
	int status;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	status = device_manager_init (&manager, 1, DEVICE_MANAGER_PA_ROT_MODE,
		DEVICE_MANAGER_MASTER_AND_SLAVE_BUS_ROLE);
	CuAssertIntEquals (test, 0, status);

	status = device_manager_update_device_entry (&manager, 0, 0xAA, 0xBB);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_master_init (&attestation, &riot, &hash.base, &ecc.base, NULL,	&x509.base,
		&rng.base, &manager, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_RSA,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_ALGORITHM, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_only_leaf (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;
	struct riot_key_manager riot;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 1;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_CHAIN, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_init_cert_store_failure (
	CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, -1,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_add_root_ca_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, -1,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_add_cert_as_root_ca_failure (
	CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, -1,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_add_int_cert_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.add_intermediate_ca, &x509, -1,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_load_cert_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.add_intermediate_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, -1,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_authenticate_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.add_intermediate_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, -1, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_SAVED_ARG (1));
		status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_get_public_key_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 3;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.add_intermediate_ca, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.get_public_key, &x509, -1, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_ALIAS_CERT,
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 2, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_ecc_public_key_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 2;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.get_public_key, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, -1, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_rsa_public_key_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[329] = {0};
	uint16_t buf_len = 329;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 2;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_RSA,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.get_public_key, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_public_key, &rsa, -1, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, -1, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_ecc_verify_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[137] = {0};
	uint16_t buf_len = 137;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 2;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_ECC,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.get_public_key, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, 0, MOCK_ARG_ANY,
		MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);
	status |= mock_expect (&ecc.mock, ecc.base.verify, &ecc, ECC_ENGINE_NO_MEMORY,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (32),
		MOCK_ARG_PTR_CONTAINS (&buf[72], 65), MOCK_ARG (65));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG (0),
		MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_rsa_verify_failure (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge;
	struct attestation_chain_digest digests;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf[329] = {0};
	uint16_t buf_len = 329;

	TEST_START;

	buf[1] = 1;
	buf[2] = 0;
	buf[3] = 4;

	digests.num_cert = 2;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);
	status |= mock_expect (&x509.mock, x509.base.get_public_key_type, &x509, X509_PUBLIC_KEY_RSA,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));
	status |= mock_expect (&x509.mock, x509.base.init_ca_cert_store, &x509, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509.mock, 0, 1);
	status |= mock_expect (&x509.mock, x509.base.add_root_ca, &x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 2);
	status |= mock_expect (&x509.mock, x509.base.authenticate, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.get_public_key, &x509, 0, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (2));
	status |= mock_expect (&x509.mock, x509.base.release_ca_cert_store, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_public_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY, MOCK_ARG_ANY);
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.sig_verify, &rsa, RSA_ENGINE_NO_MEMORY,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR_CONTAINS (&buf[72], 257), MOCK_ARG (257),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (34));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (buf, 72),
		MOCK_ARG (72));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.compare_digests (&attestation, 0xAA, &digests);
	CuAssertIntEquals (test, 1, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 0, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.store_certificate (&attestation, 0xAA, 0, 1, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.generate_challenge_request (&attestation, 0xAA, 0, &challenge);
	CuAssertIntEquals (test, sizeof (struct attestation_challenge), status);

	status = attestation.process_challenge_response (&attestation, buf, buf_len, 0xAA);
	CuAssertIntEquals (test, RSA_ENGINE_NO_MEMORY, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

static void attestation_master_test_process_challenge_response_null (CuTest *test)
{
	int status;
	struct attestation_master attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct keystore_mock keystore;
	struct device_manager manager;
	uint8_t buf;
	uint16_t buf_len = 137;

	TEST_START;

	setup_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &keystore, &manager);

	status = attestation.process_challenge_response (NULL, &buf, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.process_challenge_response (&attestation, NULL, buf_len, 0xAA);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_master_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&keystore, &manager, &riot);
}

TEST_SUITE_START (attestation_master);

TEST (attestation_master_test_init);
TEST (attestation_master_test_init_null);
TEST (attestation_master_test_release_null);
TEST (attestation_master_test_generate_challenge_request);
TEST (attestation_master_test_generate_challenge_request_invalid_slot_num);
TEST (attestation_master_test_generate_challenge_request_invalid_device);
TEST (attestation_master_test_generate_challenge_request_rng_fail);
TEST (attestation_master_test_generate_challenge_request_null);
TEST (attestation_master_test_compare_digests_first);
TEST (attestation_master_test_compare_digests_incomplete_chain_stored);
TEST (attestation_master_test_compare_digests_new_chain);
TEST (attestation_master_test_compare_digests_same);
TEST (attestation_master_test_compare_digests_mismatch);
TEST (attestation_master_test_compare_digests_hash_fail);
TEST (attestation_master_test_compare_digests_invalid_device);
TEST (attestation_master_test_compare_digests_null);
TEST (attestation_master_test_store_certificate);
TEST (attestation_master_test_store_certificate_invalid_device);
TEST (attestation_master_test_store_certificate_invalid_cert_num);
TEST (attestation_master_test_store_certificate_invalid_slot_num);
TEST (attestation_master_test_store_certificate_null);
TEST (attestation_master_test_process_challenge_response_3_device_cert_ecc);
TEST (attestation_master_test_process_challenge_response_3_device_cert_no_riot_ca_ecc);
TEST (attestation_master_test_process_challenge_response_2_device_cert_ecc);
TEST (attestation_master_test_process_challenge_response_2_device_cert_no_riot_ca_ecc);
TEST (attestation_master_test_process_challenge_response_full_chain_rsa);
TEST (attestation_master_test_process_challenge_response_invalid_buf_len);
TEST (attestation_master_test_process_challenge_response_invalid_device);
TEST (attestation_master_test_process_challenge_response_invalid_slot_num);
TEST (attestation_master_test_process_challenge_response_invalid_min_protocol_version);
TEST (attestation_master_test_process_challenge_response_invalid_max_protocol_version);
TEST (attestation_master_test_process_challenge_response_init_cert_failure);
TEST (attestation_master_test_process_challenge_response_get_pub_key_type_failure);
TEST (attestation_master_test_process_challenge_response_start_hash_failure);
TEST (attestation_master_test_process_challenge_response_hash_challenge_failure);
TEST (attestation_master_test_process_challenge_response_hash_response_failure);
TEST (attestation_master_test_process_challenge_response_finish_hash_failure);
TEST (attestation_master_test_process_challenge_response_unsupported_algorithm);
TEST (attestation_master_test_process_challenge_response_rsa_not_enabled);
TEST (attestation_master_test_process_challenge_response_only_leaf);
TEST (attestation_master_test_process_challenge_response_init_cert_store_failure);
TEST (attestation_master_test_process_challenge_response_add_root_ca_failure);
TEST (attestation_master_test_process_challenge_response_add_cert_as_root_ca_failure);
TEST (attestation_master_test_process_challenge_response_add_int_cert_failure);
TEST (attestation_master_test_process_challenge_response_load_cert_failure);
TEST (attestation_master_test_process_challenge_response_authenticate_failure);
TEST (attestation_master_test_process_challenge_response_get_public_key_failure);
TEST (attestation_master_test_process_challenge_response_ecc_public_key_failure);
TEST (attestation_master_test_process_challenge_response_rsa_public_key_failure);
TEST (attestation_master_test_process_challenge_response_ecc_verify_failure);
TEST (attestation_master_test_process_challenge_response_rsa_verify_failure);
TEST (attestation_master_test_process_challenge_response_null);

TEST_SUITE_END;
