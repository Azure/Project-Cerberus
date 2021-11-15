// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_io.h"
#include "platform.h"
#include "testing.h"
#include "attestation/attestation_slave.h"
#include "attestation/pcr_store.h"
#include "attestation/aux_attestation.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/mock/crypto/x509_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/mock/logging/logging_mock.h"
#include "testing/attestation/aux_attestation_testing.h"
#include "testing/attestation/attestation_testing.h"
#include "testing/crypto/x509_testing.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("attestation_slave");

/**
 * RIoT keys for testing.
 */
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
 * Dependencies for testing slave attestation processing.
 */
struct attestation_slave_testing {
	struct hash_engine_mock hash;		/**< Mock for hash operations. */
	struct ecc_engine_mock ecc;			/**< Mock for ECC operations. */
	struct rsa_engine_mock rsa;			/**< Mock for RSA operations. */
	struct x509_engine_mock x509;		/**< Mock for X.509 operations. */
	struct rng_engine_mock rng;			/**< Mock for random number generation. */
	struct keystore_mock keystore;		/**< Mock for the attestation keystore. */
	struct riot_key_manager riot;		/**< Key manager for RIoT keys. */
	struct pcr_store store;				/**< Slave PCRs. */
	struct aux_attestation aux;			/**< Manager for auxiliary attesattion flows. */
	struct attestation_slave slave;		/**< Attestation slave being tested. */
};

/**
 * Initialize all testing dependencies.
 *
 * @param test The test framework
 * @param attestation Testing dependencies to initialize
 *
 */
static void attestation_slave_testing_init_dependencies (CuTest *test,
	struct attestation_slave_testing *attestation)
{
	uint8_t num_pcr_measurements[1] = {0};
	uint8_t *dev_id_der = NULL;
	int status;

	status = hash_mock_init (&attestation->hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation->ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation->rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation->x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation->rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation->store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation->keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation->keystore.mock, attestation->keystore.base.load_key,
		&attestation->keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&attestation->keystore.mock, 1, &dev_id_der,
		sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&attestation->riot, &attestation->keystore.base, &keys,
		&attestation->x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation->aux, &attestation->keystore.base,
		&attestation->rsa.base, &attestation->riot, &attestation->ecc.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate mocks.
 *
 * @param test The test framework
 * @param attestation Testing dependencies to release
 *
 */
static void attestation_slave_testing_release_dependencies (CuTest *test,
	struct attestation_slave_testing *attestation)
{
	int status;

	status = hash_mock_validate_and_release (&attestation->hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&attestation->ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&attestation->rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&attestation->x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&attestation->rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&attestation->keystore);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&attestation->aux);
	riot_key_manager_release (&attestation->riot);
	pcr_store_release (&attestation->store);
}

/**
 * Helper function to setup the attestation manager to use mock crypto engines.
 *
 * @param test The test framework
 * @param attestation Testing dependencies to initialize
 */
static void setup_attestation_slave_mock_test (CuTest *test,
	struct attestation_slave_testing *attestation)
{
	int status;

	attestation_slave_testing_init_dependencies (test, attestation);

	status = mock_expect (&attestation->ecc.mock, attestation->ecc.base.init_key_pair,
		&attestation->ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation->ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation->slave, &attestation->riot,
		&attestation->hash.base, &attestation->ecc.base, &attestation->rng.base,
		&attestation->store, &attestation->aux, 1, 2);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to setup the attestation manager without aux attestation to use mock crypto
 * engines.
 *
 * @param test The test framework
 * @param attestation Testing dependencies to initialize
 */
static void setup_attestation_slave_no_aux_mock_test (CuTest *test,
	struct attestation_slave_testing *attestation)
{
	int status;

	attestation_slave_testing_init_dependencies (test, attestation);

	status = mock_expect (&attestation->ecc.mock, attestation->ecc.base.init_key_pair,
		&attestation->ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation->ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (&attestation->slave, &attestation->riot,
		&attestation->hash.base, &attestation->ecc.base, &attestation->rng.base,
		&attestation->store, 1, 2);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release attestation manager instance.
 *
 * @param test The test framework
 * @param attestation Testing dependencies to release
 */
static void complete_attestation_slave_mock_test (CuTest *test,
	struct attestation_slave_testing *attestation)
{
	int status;

	status = mock_expect (&attestation->ecc.mock, attestation->ecc.base.release_key_pair,
		&attestation->ecc, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	attestation_slave_release (&attestation->slave);

	attestation_slave_testing_release_dependencies (test, attestation);
}

/**
 * Helper function to add an intermediate and root CA to RIoT key manager cert chain.
 *
 * @param test The test framework
 * @param riot RIoT keys manager to utilize
 * @param keystore The keystore to utilize
 * @param x509 The x509 engine mock to utilize
 */
void attestation_testing_add_int_ca_to_riot_key_manager (CuTest *test,
	struct riot_key_manager *riot, struct keystore_mock *keystore, struct x509_engine_mock *x509)
{
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;
	int status;

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	int_der = platform_malloc (X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, int_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_INTR_SIGNED_CERT, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	memcpy (int_der, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), -1);

	status |= mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &ca_der, sizeof (ca_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &X509_CERTSS_RSA_CA_NOPL_DER_LEN,
		sizeof (X509_CERTSS_RSA_CA_NOPL_DER_LEN), -1);

	status |= mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (2),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &int_der, sizeof (int_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &X509_CERTCA_ECC_CA_NOPL_DER_LEN,
		sizeof (X509_CERTCA_ECC_CA_NOPL_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509->mock, x509->base.load_certificate, x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect_save_arg (&x509->mock, 0, 0);

	status |= mock_expect (&x509->mock, x509->base.init_ca_cert_store, x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509->mock, 0, 1);

	status |= mock_expect (&x509->mock, x509->base.add_root_ca, x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));
	status |= mock_expect (&x509->mock, x509->base.add_intermediate_ca, x509, 0,
		MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));
	status |= mock_expect (&x509->mock, x509->base.add_intermediate_ca, x509, 0,
		MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN));

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

/**
 * Helper function to add a root CA to RIoT key manager cert chain.
 *
 * @param test The test framework
 * @param riot RIoT keys manager to utilize
 * @param keystore The keystore to utilize
 * @param x509 The x509 engine mock to utilize
 */
void attestation_testing_add_root_ca_to_riot_key_manager (CuTest *test,
	struct riot_key_manager *riot, struct keystore_mock *keystore, struct x509_engine_mock *x509)
{
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	int status;

	dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	ca_der = platform_malloc (X509_CERTSS_ECC_CA_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	memcpy (dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	memcpy (ca_der, X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &RIOT_CORE_DEVID_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);

	status |= mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&keystore->mock, 1, &ca_der, sizeof (ca_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &X509_CERTSS_ECC_CA_DER_LEN,
		sizeof (X509_CERTSS_ECC_CA_DER_LEN), -1);

	status |= mock_expect (&keystore->mock, keystore->base.load_key, keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&x509->mock, x509->base.load_certificate, x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));
	status |= mock_expect_save_arg (&x509->mock, 0, 0);

	status |= mock_expect (&x509->mock, x509->base.init_ca_cert_store, x509, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&x509->mock, 0, 1);

	status |= mock_expect (&x509->mock, x509->base.add_root_ca, x509, 0, MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC_CA_DER_LEN));
	status |= mock_expect (&x509->mock, x509->base.add_intermediate_ca, x509, 0,
		MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN));

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

/**
 * Helper function to add an auxiliary attestation cert.
 *
 * @param test The test framework
 * @param aux The aux handler to update
 */
void attestation_testing_add_aux_certificate (CuTest *test, struct aux_attestation *aux)
{
	uint8_t *aux_der;
	int status;

	aux_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, aux_der);

	memcpy (aux_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = aux_attestation_set_certificate (aux, aux_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void attestation_slave_test_init (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;

	TEST_START;

	attestation_slave_testing_init_dependencies (test, &attestation);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, attestation.slave.get_digests);
	CuAssertPtrNotNull (test, attestation.slave.get_certificate);
	CuAssertPtrNotNull (test, attestation.slave.challenge_response);
	CuAssertPtrNotNull (test, attestation.slave.aux_attestation_unseal);
	CuAssertPtrNotNull (test, attestation.slave.aux_decrypt);
	CuAssertPtrNotNull (test, attestation.slave.generate_ecdh_seed);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_init_init_keypair_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;

	TEST_START;

	attestation_slave_testing_init_dependencies (test, &attestation);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	attestation_slave_testing_release_dependencies (test, &attestation);
}

static void attestation_slave_test_init_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;

	TEST_START;

	attestation_slave_testing_init_dependencies (test, &attestation);

	status = attestation_slave_init (NULL, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation.slave, NULL, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, NULL,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		NULL, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, NULL, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, NULL, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, NULL, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	attestation_slave_testing_release_dependencies (test, &attestation);
}

static void attestation_slave_test_init_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;

	TEST_START;

	attestation_slave_testing_init_dependencies (test, &attestation);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (&attestation.slave, &attestation.riot,
		&attestation.hash.base, &attestation.ecc.base, &attestation.rng.base, &attestation.store, 1,
		2);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, attestation.slave.get_digests);
	CuAssertPtrNotNull (test, attestation.slave.get_certificate);
	CuAssertPtrNotNull (test, attestation.slave.challenge_response);
	CuAssertPtrNotNull (test, attestation.slave.aux_attestation_unseal);
	CuAssertPtrNotNull (test, attestation.slave.aux_decrypt);
	CuAssertPtrNotNull (test, attestation.slave.generate_ecdh_seed);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_init_no_aux_init_keypair_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;

	TEST_START;

	attestation_slave_testing_init_dependencies (test, &attestation);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (&attestation.slave, &attestation.riot,
		&attestation.hash.base, &attestation.ecc.base, &attestation.rng.base, &attestation.store, 1,
		2);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	attestation_slave_testing_release_dependencies (test, &attestation);
}

static void attestation_slave_test_init_no_aux_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;

	TEST_START;

	attestation_slave_testing_init_dependencies (test, &attestation);

	status = attestation_slave_init_no_aux (NULL, &attestation.riot,
		&attestation.hash.base, &attestation.ecc.base, &attestation.rng.base, &attestation.store, 1,
		2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation.slave, NULL,
		&attestation.hash.base, &attestation.ecc.base, &attestation.rng.base, &attestation.store, 1,
		2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation.slave, &attestation.riot,
		NULL, &attestation.ecc.base, &attestation.rng.base, &attestation.store, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation.slave, &attestation.riot,
		&attestation.hash.base, NULL, &attestation.rng.base, &attestation.store, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation.slave, &attestation.riot,
		&attestation.hash.base, &attestation.ecc.base, NULL, &attestation.store, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation.slave, &attestation.riot,
		&attestation.hash.base, &attestation.ecc.base, &attestation.rng.base, NULL, 1, 2);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	attestation_slave_testing_release_dependencies (test, &attestation);
}

static void attestation_slave_test_release_null (CuTest *test)
{
	TEST_START;

	attestation_slave_release (NULL);
}

static void attestation_slave_test_get_digests (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t cert_hash[] = {
		0x00,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x01,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x02,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x03,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[0], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[32], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[64], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[96], 32, -1);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, sizeof (cert_hash), status);
	CuAssertIntEquals (test, 4, num_cert);

	status = testing_validate_array (cert_hash, buf, sizeof (cert_hash));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t cert_hash[] = {
		0x00,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x01,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x02,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x03,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[0], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[32], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[64], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[96], 32, -1);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, sizeof (cert_hash), status);
	CuAssertIntEquals (test, 4, num_cert);

	status = testing_validate_array (cert_hash, buf, sizeof (cert_hash));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_aux_slot (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t cert_hash[] = {
		0x00,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x01,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x02,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x03,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[0], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[32], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[64], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_RSA_EE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[96], 32, -1);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 1, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, sizeof (cert_hash), status);
	CuAssertIntEquals (test, 4, num_cert);

	status = testing_validate_array (cert_hash, buf, sizeof (cert_hash));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_aux_slot_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_digests (&attestation.slave, 1, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4];
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf) - 1,
		&num_cert);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_int_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 3] = {0};
	uint8_t cert_hash[] = {
		0x00,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x01,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x02,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_ECC_CA_DER, X509_CERTSS_ECC_CA_DER_LEN),
		MOCK_ARG (X509_CERTSS_ECC_CA_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[0], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[32], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[64], 32, -1);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, sizeof (cert_hash), status);
	CuAssertIntEquals (test, 3, num_cert);

	status = testing_validate_array (cert_hash, buf, sizeof (cert_hash));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_int_ca_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 3];
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf) - 1,
		&num_cert);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_root_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 2] = {0};
	uint8_t cert_hash[] = {
		0x00,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0x01,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[0], 32, -1);

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&attestation.hash.mock, 2, &cert_hash[32], 32, -1);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, sizeof (cert_hash), status);
	CuAssertIntEquals (test, 2, num_cert);

	status = testing_validate_array (cert_hash, buf, sizeof (cert_hash));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_root_ca_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 2];
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf) - 1,
		&num_cert);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_dev_id (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 1;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_no_alias (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 1;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.devid_cert = RIOT_CORE_DEVID_CERT;
	bad_keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_aux_slot_no_dev_id (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 1;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 1, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_aux_slot_no_aux_cert (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 1;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_digests (&attestation.slave, 1, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_devid_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_alias_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_aux_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN),
		MOCK_ARG (X509_CERTCA_RSA_EE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 1, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_int_ca_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_root_ca_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_digests (NULL, 0, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, NULL, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.get_digests (&attestation.slave, 0, buf, sizeof (buf), NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_digests_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[32 * 4] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_digests (&attestation.slave, 2, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_aux_slot (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_aux_slot_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_aux_slot_no_aux_cert (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_no_int_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_SIGNED_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_SIGNED_CERT,
		RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_no_root_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 0, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_no_dev_id (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	struct der_cert cert;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_dev_id_certificate_no_alias (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	struct der_cert cert;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.devid_cert = RIOT_CORE_DEVID_CERT;
	bad_keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_alias_certificate (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 3, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_alias_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 3, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_alias_certificate_no_int_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_alias_certificate_no_root_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_alias_certificate_no_dev_id (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	struct der_cert cert;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 1, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_alias_certificate_no_alias (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	struct der_cert cert;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.devid_cert = RIOT_CORE_DEVID_CERT;
	bad_keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG (NULL), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 1, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_int_ca_certificate (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, cert.cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_int_ca_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, cert.cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_int_ca_certificate_aux_slot (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, cert.cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_int_ca_certificate_aux_slot_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 1, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_int_ca_certificate_aux_slot_no_aux_cert (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 1, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_root_ca_certificate (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 0, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTSS_RSA_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, cert.cert,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_root_ca_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 0, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTSS_RSA_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, cert.cert,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_root_ca_certificate_aux_slot (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 0, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTSS_RSA_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, cert.cert,
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_root_ca_certificate_aux_slot_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_root_ca_certificate_aux_slot_no_aux_cert (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_aux_certificate (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 3, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert.cert, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_aux_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 3, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_aux_certificate_no_aux_cert (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 3, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_aux_certificate_no_int_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert.cert, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_aux_certificate_no_root_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert.cert, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_aux_certificate_no_dev_id (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	struct der_cert cert;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&attestation.hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&attestation.ecc);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_init (&attestation.rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&attestation.x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&attestation.rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&attestation.store, num_pcr_measurements,
		sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&attestation.keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&attestation.riot, &attestation.keystore.base, &bad_keys,
		&attestation.x509.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&attestation.aux, &attestation.keystore.base,
		&attestation.rsa.base, &attestation.riot, &attestation.ecc.base);
	CuAssertIntEquals (test, 0, status);

	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, 0);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation.slave, &attestation.riot, &attestation.hash.base,
		&attestation.ecc.base, &attestation.rng.base, &attestation.store, &attestation.aux, 1, 2);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 1, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_certificate (&attestation.slave, 2, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_cert_num (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 4, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_cert_num_aux_slot (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_int_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 1, 4, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_cert_num_no_int_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 3, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_cert_num_no_int_ca_aux_slot (
	CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_root_ca_to_riot_key_manager (test, &attestation.riot,
		&attestation.keystore, &attestation.x509);
	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 3, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_cert_num_no_root_ca (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_invalid_cert_num_no_root_ca_aux_slot (
	CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation_testing_add_aux_certificate (test, &attestation.aux);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_get_certificate_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct der_cert cert;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.get_certificate (NULL, 0, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.get_certificate (&attestation.slave, 0, 0, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	struct attestation_response *response;
	uint8_t buf[136] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t signature[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	response = (struct attestation_response*)buf;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.rng.mock, attestation.rng.base.generate_random_buffer,
		&attestation.rng, 0, MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.finish, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.sign, &attestation.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&attestation.ecc.mock, 3, signature, sizeof (signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, 136, status);
	CuAssertIntEquals (test, 0, response->slot_num);
	CuAssertIntEquals (test, 1, response->slot_mask);
	CuAssertIntEquals (test, 1, response->min_protocol_version);
	CuAssertIntEquals (test, 2, response->max_protocol_version);
	CuAssertIntEquals (test, 1, response->num_digests);
	CuAssertIntEquals (test, 32, response->digests_size);

	status = testing_validate_array (measurement, buf + sizeof (struct attestation_response),
		sizeof (measurement));
	status |= testing_validate_array (signature,
		buf + sizeof (struct attestation_response) + sizeof (measurement),
		sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	struct attestation_response *response;
	uint8_t buf[136] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t signature[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	response = (struct attestation_response*)buf;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	status = mock_expect (&attestation.rng.mock, attestation.rng.base.generate_random_buffer,
		&attestation.rng, 0, MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.finish, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.sign, &attestation.ecc, 64,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&attestation.ecc.mock, 3, signature, sizeof (signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, 136, status);
	CuAssertIntEquals (test, 0, response->slot_num);
	CuAssertIntEquals (test, 1, response->slot_mask);
	CuAssertIntEquals (test, 1, response->min_protocol_version);
	CuAssertIntEquals (test, 2, response->max_protocol_version);
	CuAssertIntEquals (test, 1, response->num_digests);
	CuAssertIntEquals (test, 32, response->digests_size);

	status = testing_validate_array (measurement, buf + sizeof (struct attestation_response),
		sizeof (measurement));
	status |= testing_validate_array (signature,
		buf + sizeof (struct attestation_response) + sizeof (measurement),
		sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[137];
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	buf[0] = 1;

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_compute_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[137] = {0};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	attestation.slave.pcr_store = NULL;

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_buf_smaller_than_response (
	CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[72] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_start_hash_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[137] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_update_challenge_hash_fail (
	CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	uint8_t buf[137] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.cancel, &attestation.hash,
		0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_rng_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	uint8_t buf[137] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.rng.mock, attestation.rng.base.generate_random_buffer,
		&attestation.rng, RNG_ENGINE_NO_MEMORY, MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.cancel, &attestation.hash,
		0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, RNG_ENGINE_NO_MEMORY, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_update_response_hash_fail (
	CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	uint8_t buf[137] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.rng.mock, attestation.rng.base.generate_random_buffer,
		&attestation.rng, 0, MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.cancel, &attestation.hash,
		0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_finish_hash_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	uint8_t buf[137] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.rng.mock, attestation.rng.base.generate_random_buffer,
		&attestation.rng, 0, MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.finish, &attestation.hash,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.cancel, &attestation.hash,
		0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_sign_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	struct attestation_challenge challenge = {0};
	uint8_t buf[136] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*) &challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.rng.mock, attestation.rng.base.generate_random_buffer,
		&attestation.rng, 0, MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.hash.mock, attestation.hash.base.start_sha256,
		&attestation.hash, 0);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.finish, &attestation.hash,
		0, MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.sign, &attestation.ecc,
		ECC_ENGINE_NO_MEMORY, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[1];
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.challenge_response (&attestation.slave, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_BAD_LENGTH, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_pa_rot_challenge_response_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t buf[137];
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.challenge_response (NULL, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.challenge_response (&attestation.slave, NULL, buf_len);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_attestation_unseal (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t key[SHA256_HASH_LENGTH];
	uint8_t *key_der;
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&attestation.keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.rsa.mock, attestation.rsa.base.init_private_key,
		&attestation.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&attestation.rsa.mock, 0, 0);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.decrypt, &attestation.rsa,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&attestation.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.release_key,
		&attestation.rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&attestation.hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&attestation.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= hash_mock_expect_hmac_init (&attestation.hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&attestation.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	status |= hash_mock_expect_hmac_init (&attestation.hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&attestation.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, key, status);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_attestation_unseal_sha256 (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t key[SHA256_HASH_LENGTH];
	uint8_t *key_der;
	uint8_t separator = 0;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&attestation.keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.rsa.mock, attestation.rsa.base.init_private_key,
		&attestation.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&attestation.rsa.mock, 0, 0);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.decrypt, &attestation.rsa,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP_SHA256, KEY_SEED_ENCRYPT_OAEP_SHA256_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_SHA256_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&attestation.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.release_key,
		&attestation.rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&attestation.hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN - 1));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&attestation.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= hash_mock_expect_hmac_init (&attestation.hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN), MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&attestation.hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	status |= hash_mock_expect_hmac_init (&attestation.hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN - 1));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (&separator, sizeof (separator)), MOCK_ARG (sizeof (separator)));
	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.update, &attestation.hash,
		0, MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&attestation.hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP_SHA256, KEY_SEED_ENCRYPT_OAEP_SHA256_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA256, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ENCRYPTION_KEY, key, status);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_attestation_unseal_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t key[SHA256_HASH_LENGTH];

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_OPERATION, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_attestation_unseal_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t key[SHA256_HASH_LENGTH];

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_LOAD_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL,
		 MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&attestation.store, 0, PCR0_VALUE, PCR0_VALUE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_attestation_unseal_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t key[32];

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.aux_attestation_unseal (NULL, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, NULL,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, NULL, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, 0,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, NULL, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		NULL, CIPHER_TEXT_LEN, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, 0, SEALING_POLICY, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, NULL, 1, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 0, key, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.aux_attestation_unseal (&attestation.slave, &attestation.hash.base,
		AUX_ATTESTATION_KEY_256BIT, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		AUX_ATTESTATION_SEED_RSA, AUX_ATTESTATION_PARAM_OAEP_SHA1, PAYLOAD_HMAC, HMAC_SHA256,
		CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, 1, NULL, sizeof (key));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_decrypt (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t decrypted[4224];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&attestation.keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.rsa.mock, attestation.rsa.base.init_private_key,
		&attestation.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&attestation.rsa.mock, 0, 0);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.decrypt, &attestation.rsa,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL),
		MOCK_ARG (0), MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&attestation.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.release_key,
		&attestation.rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_decrypt (&attestation.slave, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_decrypt_with_label (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t decrypted[4224];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&attestation.keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.rsa.mock, attestation.rsa.base.init_private_key,
		&attestation.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&attestation.rsa.mock, 0, 0);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.decrypt, &attestation.rsa,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN),
		MOCK_ARG (RSA_ENCRYPT_LABEL_LEN), MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&attestation.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.release_key,
		&attestation.rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_decrypt (&attestation.slave, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, (uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN,
		HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_decrypt_sha256 (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t decrypted[4224];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&attestation.keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&attestation.keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&attestation.rsa.mock, attestation.rsa.base.init_private_key,
		&attestation.rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&attestation.rsa.mock, 0, 0);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.decrypt, &attestation.rsa,
		KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&attestation.rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&attestation.rsa.mock, attestation.rsa.base.release_key,
		&attestation.rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_decrypt (&attestation.slave, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, NULL, 0, HASH_TYPE_SHA256, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_decrypt_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t decrypted[4224];

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	status = attestation.slave.aux_decrypt (&attestation.slave, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_OPERATION, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_decrypt_fail (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t decrypted[4224];

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.keystore.mock, attestation.keystore.base.load_key,
		&attestation.keystore, KEYSTORE_LOAD_FAILED, MOCK_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.aux_decrypt (&attestation.slave, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_aux_decrypt_null (CuTest *test)
{
	int status;
	struct attestation_slave_testing attestation;
	uint8_t decrypted[4224];

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.aux_decrypt (NULL, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_generate_ecdh_seed (CuTest *test)
{
	struct attestation_slave_testing attestation;
	uint8_t seed[32];
	int status;
	int arg_base;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	arg_base = mock_expect_next_save_id (&attestation.ecc.mock);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_public_key,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, arg_base);

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, arg_base + 1);

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.get_shared_secret_max_length,
		&attestation.ecc, 32, MOCK_ARG_SAVED_ARG (arg_base + 1));

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.compute_shared_secret,
		&attestation.ecc, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (arg_base + 1),
		MOCK_ARG_SAVED_ARG (arg_base), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&attestation.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.release_key_pair,
		&attestation.ecc, 0, MOCK_ARG_SAVED_ARG (arg_base + 1), MOCK_ARG (NULL));
	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.release_key_pair,
		&attestation.ecc, 0, MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (arg_base));

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false, seed, sizeof (seed));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, seed, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_generate_ecdh_seed_sha256 (CuTest *test)
{
	struct attestation_slave_testing attestation;
	uint8_t seed[32];
	int status;
	int arg_base;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	arg_base = mock_expect_next_save_id (&attestation.ecc.mock);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_public_key,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, arg_base);

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_key_pair,
		&attestation.ecc, 0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&attestation.ecc.mock, 2, arg_base + 1);

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.get_shared_secret_max_length,
		&attestation.ecc, 32, MOCK_ARG_SAVED_ARG (arg_base + 1));

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.compute_shared_secret,
		&attestation.ecc, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (arg_base + 1),
		MOCK_ARG_SAVED_ARG (arg_base), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&attestation.ecc.mock, 2, KEY_SEED, KEY_SEED_LEN, 3);

	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.release_key_pair,
		&attestation.ecc, 0, MOCK_ARG_SAVED_ARG (arg_base + 1), MOCK_ARG (NULL));
	status |= mock_expect (&attestation.ecc.mock, attestation.ecc.base.release_key_pair,
		&attestation.ecc, 0, MOCK_ARG (NULL), MOCK_ARG_SAVED_ARG (arg_base));

	status |= mock_expect (&attestation.hash.mock, attestation.hash.base.calculate_sha256,
		&attestation.hash, 0, MOCK_ARG_PTR_CONTAINS (KEY_SEED, KEY_SEED_LEN),
		MOCK_ARG (KEY_SEED_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&attestation.hash.mock, 2, KEY_SEED_HASH, KEY_SEED_HASH_LEN, 3);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, true, seed, sizeof (seed));
	CuAssertIntEquals (test, KEY_SEED_HASH_LEN, status);

	status = testing_validate_array (KEY_SEED_HASH, seed, KEY_SEED_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_generate_ecdh_seed_no_aux (CuTest *test)
{
	struct attestation_slave_testing attestation;
	uint8_t seed[32];
	int status;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false, seed, sizeof (seed));
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_OPERATION, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_generate_ecdh_seed_fail (CuTest *test)
{
	struct attestation_slave_testing attestation;
	uint8_t seed[32];
	int status;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = mock_expect (&attestation.ecc.mock, attestation.ecc.base.init_public_key,
		&attestation.ecc, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false, seed, sizeof (seed));
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation);
}

static void attestation_slave_test_generate_ecdh_seed_null (CuTest *test)
{
	struct attestation_slave_testing attestation;
	uint8_t seed[32];
	int status;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation);

	status = attestation.slave.generate_ecdh_seed (NULL, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false, seed, sizeof (seed));
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, NULL,
		ECC_PUBKEY_DER_LEN, false, seed, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, ECC_PUBKEY_DER,
		0, false, seed, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.slave.generate_ecdh_seed (&attestation.slave, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, false, NULL, sizeof (seed));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation);
}


TEST_SUITE_START (attestation_slave);

TEST (attestation_slave_test_init);
TEST (attestation_slave_test_init_init_keypair_fail);
TEST (attestation_slave_test_init_null);
TEST (attestation_slave_test_init_no_aux);
TEST (attestation_slave_test_init_no_aux_init_keypair_fail);
TEST (attestation_slave_test_init_no_aux_null);
TEST (attestation_slave_test_release_null);
TEST (attestation_slave_test_get_digests);
TEST (attestation_slave_test_get_digests_no_aux);
TEST (attestation_slave_test_get_digests_aux_slot);
TEST (attestation_slave_test_get_digests_aux_slot_no_aux);
TEST (attestation_slave_test_get_digests_buf_too_small);
TEST (attestation_slave_test_get_digests_no_int_ca);
TEST (attestation_slave_test_get_digests_no_int_ca_buf_too_small);
TEST (attestation_slave_test_get_digests_no_root_ca);
TEST (attestation_slave_test_get_digests_no_root_ca_buf_too_small);
TEST (attestation_slave_test_get_digests_no_dev_id);
TEST (attestation_slave_test_get_digests_no_alias);
TEST (attestation_slave_test_get_digests_aux_slot_no_dev_id);
TEST (attestation_slave_test_get_digests_aux_slot_no_aux_cert);
TEST (attestation_slave_test_get_digests_devid_fail);
TEST (attestation_slave_test_get_digests_alias_fail);
TEST (attestation_slave_test_get_digests_aux_fail);
TEST (attestation_slave_test_get_digests_int_ca_fail);
TEST (attestation_slave_test_get_digests_root_ca_fail);
TEST (attestation_slave_test_get_digests_null);
TEST (attestation_slave_test_get_digests_invalid_slot_num);
TEST (attestation_slave_test_get_dev_id_certificate);
TEST (attestation_slave_test_get_dev_id_certificate_no_aux);
TEST (attestation_slave_test_get_dev_id_certificate_aux_slot);
TEST (attestation_slave_test_get_dev_id_certificate_aux_slot_no_aux);
TEST (attestation_slave_test_get_dev_id_certificate_aux_slot_no_aux_cert);
TEST (attestation_slave_test_get_dev_id_certificate_no_int_ca);
TEST (attestation_slave_test_get_dev_id_certificate_no_root_ca);
TEST (attestation_slave_test_get_dev_id_certificate_no_dev_id);
TEST (attestation_slave_test_get_dev_id_certificate_no_alias);
TEST (attestation_slave_test_get_alias_certificate);
TEST (attestation_slave_test_get_alias_certificate_no_aux);
TEST (attestation_slave_test_get_alias_certificate_no_int_ca);
TEST (attestation_slave_test_get_alias_certificate_no_root_ca);
TEST (attestation_slave_test_get_alias_certificate_no_dev_id);
TEST (attestation_slave_test_get_alias_certificate_no_alias);
TEST (attestation_slave_test_get_int_ca_certificate);
TEST (attestation_slave_test_get_int_ca_certificate_no_aux);
TEST (attestation_slave_test_get_int_ca_certificate_aux_slot);
TEST (attestation_slave_test_get_int_ca_certificate_aux_slot_no_aux);
TEST (attestation_slave_test_get_int_ca_certificate_aux_slot_no_aux_cert);
TEST (attestation_slave_test_get_root_ca_certificate);
TEST (attestation_slave_test_get_root_ca_certificate_no_aux);
TEST (attestation_slave_test_get_root_ca_certificate_aux_slot);
TEST (attestation_slave_test_get_root_ca_certificate_aux_slot_no_aux);
TEST (attestation_slave_test_get_root_ca_certificate_aux_slot_no_aux_cert);
TEST (attestation_slave_test_get_aux_certificate);
TEST (attestation_slave_test_get_aux_certificate_no_aux);
TEST (attestation_slave_test_get_aux_certificate_no_aux_cert);
TEST (attestation_slave_test_get_aux_certificate_no_int_ca);
TEST (attestation_slave_test_get_aux_certificate_no_root_ca);
TEST (attestation_slave_test_get_aux_certificate_no_dev_id);
TEST (attestation_slave_test_get_certificate_invalid_slot_num);
TEST (attestation_slave_test_get_certificate_invalid_cert_num);
TEST (attestation_slave_test_get_certificate_invalid_cert_num_aux_slot);
TEST (attestation_slave_test_get_certificate_invalid_cert_num_no_int_ca);
TEST (attestation_slave_test_get_certificate_invalid_cert_num_no_int_ca_aux_slot);
TEST (attestation_slave_test_get_certificate_invalid_cert_num_no_root_ca);
TEST (attestation_slave_test_get_certificate_invalid_cert_num_no_root_ca_aux_slot);
TEST (attestation_slave_test_get_certificate_null);
TEST (attestation_slave_test_pa_rot_challenge_response);
TEST (attestation_slave_test_pa_rot_challenge_response_no_aux);
TEST (attestation_slave_test_pa_rot_challenge_response_invalid_slot_num);
TEST (attestation_slave_test_pa_rot_challenge_response_compute_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_buf_smaller_than_response);
TEST (attestation_slave_test_pa_rot_challenge_response_start_hash_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_update_challenge_hash_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_rng_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_update_response_hash_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_finish_hash_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_sign_fail);
TEST (attestation_slave_test_pa_rot_challenge_response_buf_too_small);
TEST (attestation_slave_test_pa_rot_challenge_response_null);
TEST (attestation_slave_test_aux_attestation_unseal);
TEST (attestation_slave_test_aux_attestation_unseal_sha256);
TEST (attestation_slave_test_aux_attestation_unseal_no_aux);
TEST (attestation_slave_test_aux_attestation_unseal_fail);
TEST (attestation_slave_test_aux_attestation_unseal_null);
TEST (attestation_slave_test_aux_decrypt);
TEST (attestation_slave_test_aux_decrypt_with_label);
TEST (attestation_slave_test_aux_decrypt_sha256);
TEST (attestation_slave_test_aux_decrypt_no_aux);
TEST (attestation_slave_test_aux_decrypt_fail);
TEST (attestation_slave_test_aux_decrypt_null);
TEST (attestation_slave_test_generate_ecdh_seed);
TEST (attestation_slave_test_generate_ecdh_seed_sha256);
TEST (attestation_slave_test_generate_ecdh_seed_no_aux);
TEST (attestation_slave_test_generate_ecdh_seed_fail);
TEST (attestation_slave_test_generate_ecdh_seed_null);

TEST_SUITE_END;
