// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "platform_io.h"
#include "platform.h"
#include "testing.h"
#include "mock/ecc_mock.h"
#include "mock/rsa_mock.h"
#include "mock/x509_mock.h"
#include "mock/hash_mock.h"
#include "mock/rng_mock.h"
#include "mock/keystore_mock.h"
#include "mock/logging_mock.h"
#include "attestation/attestation_slave.h"
#include "attestation/pcr_store.h"
#include "attestation/aux_attestation.h"
#include "riot_core_testing.h"
#include "x509_testing.h"
#include "aux_attestation_testing.h"


static const char *SUITE = "attestation_slave";

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
 * Helper function to setup the attestation manager to use mock crypto engines.
 *
 * @param test The test framework
 * @param attestation The attestation manager instance to initialize
 * @param hash The hash engine mock to initialize
 * @param ecc The ECC engine mock to initialize
 * @param rsa The RSA engine mock to initialize
 * @param x509 The x509 engine mock to initialize
 * @param rng The RNG engine mock to initialize
 * @param riot RIoT keys manager to initialize
 * @param store PCR store to initialize
 * @param keystore The keystore to initialize
 * @param aux Attestation service handler to initialize
 */
static void setup_attestation_slave_mock_test (CuTest *test,
	struct attestation_slave *attestation, struct hash_engine_mock *hash,
	struct ecc_engine_mock *ecc, struct rsa_engine_mock *rsa, struct x509_engine_mock *x509,
	struct rng_engine_mock *rng, struct riot_key_manager *riot, struct pcr_store *store,
	struct keystore_mock *keystore, struct aux_attestation *aux)
{
	uint8_t num_pcr_measurements[1] = {1};
	uint8_t *dev_id_der = NULL;
	int status;

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

	status = pcr_store_init (store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (aux, &keystore->base, &rsa->base);
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

	status = mock_expect (&ecc->mock, ecc->base.init_key_pair, ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation->ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (attestation, riot, &hash->base, &ecc->base, &rng->base,
		store, aux);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release attestation manager instance.
 *
 * @param test The test framework
 * @param attestation The attestation manager instance to release
 * @param hash The hash engine mock to release
 * @param ecc The ECC engine mock to release
 * @param rsa The RSA engine mock to release
 * @param x509 The x509 engine mock to release
 * @param rng The RNG engine mock to release
 * @param store PCR store to release
 * @param keystore The keystore mock to release
 * @param aux The attestation service handler to release
 * @param riot RIoT key manager to release
 */
static void complete_attestation_slave_mock_test (CuTest *test,
	struct attestation_slave *attestation, struct hash_engine_mock *hash,
	struct ecc_engine_mock *ecc, struct rsa_engine_mock *rsa, struct x509_engine_mock *x509,
	struct rng_engine_mock *rng, struct pcr_store *store, struct keystore_mock *keystore,
	struct aux_attestation *aux, struct riot_key_manager *riot)
{
	int status;

	status = mock_expect (&ecc->mock, ecc->base.release_key_pair, ecc, 0,
		MOCK_ARG (&attestation->ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	attestation_slave_release (attestation);

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

	aux_attestation_release (aux);
	riot_key_manager_release (riot);
	pcr_store_release (store);
}

/**
 * Helper function to setup the attestation manager without attestation to use mock crypto engines.
 *
 * @param test The test framework
 * @param attestation The attestation manager instance to initialize
 * @param hash The hash engine mock to initialize
 * @param ecc The ECC engine mock to initialize
 * @param x509 The x509 engine mock to initialize
 * @param rng The RNG engine mock to initialize
 * @param riot RIoT keys manager to initialize
 * @param store PCR store to initialize
 * @param keystore The keystore to initialize
 */
static void setup_attestation_slave_no_aux_mock_test (CuTest *test,
	struct attestation_slave *attestation, struct hash_engine_mock *hash,
	struct ecc_engine_mock *ecc, struct x509_engine_mock *x509, struct rng_engine_mock *rng,
	struct riot_key_manager *riot, struct pcr_store *store, struct keystore_mock *keystore)
{
	uint8_t num_pcr_measurements[1] = {3};
	uint8_t *dev_id_der = NULL;
	int status;

	status = hash_mock_init (hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (store, num_pcr_measurements, sizeof (num_pcr_measurements));
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

	status = mock_expect (&ecc->mock, ecc->base.init_key_pair, ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation->ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (attestation, riot, &hash->base, &ecc->base,
		&rng->base, store);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release attestation manager instance with attestation.
 *
 * @param test The test framework
 * @param attestation The attestation manager instance to release
 * @param hash The hash engine mock to release
 * @param ecc The ECC engine mock to release
 * @param x509 The x509 engine mock to release
 * @param rng The RNG engine mock to release
 * @param store PCR store to release
 * @param keystore The keystore mock to release
 * @param riot RIoT key manager to release
 */
static void complete_attestation_slave_no_aux_mock_test (CuTest *test,
	struct attestation_slave *attestation, struct hash_engine_mock *hash,
	struct ecc_engine_mock *ecc, struct x509_engine_mock *x509, struct rng_engine_mock *rng,
	struct pcr_store *store, struct keystore_mock *keystore, struct riot_key_manager *riot)
{
	int status;

	status = mock_expect (&ecc->mock, ecc->base.release_key_pair, ecc, 0,
		MOCK_ARG (&attestation->ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	attestation_slave_release (attestation);

	status = hash_mock_validate_and_release (hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (riot);
	pcr_store_release (store);
}

/**
 * Helper function to add an intermediate and root CA to RIoT key manager cert chain.
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

	*dev_id_der = platform_malloc (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertPtrNotNull (test, dev_id_der);

	*ca_der = platform_malloc (X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, ca_der);

	*int_der = platform_malloc (X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertPtrNotNull (test, int_der);

	memcpy (*dev_id_der, RIOT_CORE_DEVID_INTR_SIGNED_CERT, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	memcpy (*ca_der, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	memcpy (*int_der, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	status = mock_expect (&keystore->mock, keystore->base.load_key, keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore->mock, 1, dev_id_der, sizeof (*dev_id_der), -1);
	status |= mock_expect_output (&keystore->mock, 2, &RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN,
		sizeof (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), -1);
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

/*******************
 * Test cases
 *******************/

static void attestation_slave_test_init (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;

	TEST_START;

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

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, &rng.base,
		&store, &aux);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, attestation.get_digests);
	CuAssertPtrNotNull (test, attestation.get_certificate);
	CuAssertPtrNotNull (test, attestation.challenge_response);
	CuAssertPtrNotNull (test, attestation.aux_attestation_unseal);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_init_init_keypair_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	uint8_t num_pcr_measurements[1] = {6};
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t *dev_id_der = NULL;

	TEST_START;

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

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, -1,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, &rng.base,
		&store, &aux);
	CuAssertIntEquals (test, -1, status);

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

	aux_attestation_release (&aux);
	riot_key_manager_release (&riot);
	pcr_store_release (&store);
}

static void attestation_slave_test_init_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	uint8_t num_pcr_measurements[1] = {6};
	struct aux_attestation aux;
	struct keystore_mock keystore;
	uint8_t *dev_id_der = NULL;

	TEST_START;

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

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (NULL, &riot, &hash.base, &ecc.base, &rng.base, &store,
		&aux);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation, NULL, &hash.base, &ecc.base, &rng.base,
		&store, &aux);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation, &riot, NULL, &ecc.base, &rng.base, &store,
		&aux);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, NULL, &rng.base, &store,
		&aux);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, NULL, &store,
		&aux);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, &rng.base, NULL,
		&aux);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, &rng.base, &store,
		NULL);
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

	aux_attestation_release (&aux);
	riot_key_manager_release (&riot);
	pcr_store_release (&store);
}

static void attestation_slave_test_init_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (&attestation, &riot, &hash.base, &ecc.base,
		&rng.base, &store);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, attestation.get_digests);
	CuAssertPtrNotNull (test, attestation.get_certificate);
	CuAssertPtrNotNull (test, attestation.challenge_response);
	CuAssertPtrNotNull (test, attestation.aux_attestation_unseal);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_init_no_aux_init_keypair_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	uint8_t num_pcr_measurements[1] = {6};
	struct keystore_mock keystore;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, -1,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (&attestation, &riot, &hash.base, &ecc.base,
		&rng.base, &store);
	CuAssertIntEquals (test, -1, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	pcr_store_release (&store);
}

static void attestation_slave_test_init_no_aux_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	uint8_t num_pcr_measurements[1] = {6};
	struct keystore_mock keystore;
	uint8_t *dev_id_der = NULL;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;
	keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
	keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init_no_aux (NULL, &riot, &hash.base, &ecc.base, &rng.base,
		&store);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation, NULL, &hash.base, &ecc.base, &rng.base,
		&store);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation, &riot, NULL, &ecc.base,	&rng.base,
		&store);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation, &riot, &hash.base, NULL, &rng.base,
		&store);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation, &riot, &hash.base, &ecc.base, NULL,
		&store);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation_slave_init_no_aux (&attestation, &riot, &hash.base, &ecc.base, &rng.base,
		NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&riot);
	pcr_store_release (&store);
}

static void attestation_slave_test_release_null (CuTest *test)
{
	TEST_START;

	attestation_slave_release (NULL);
}

static void attestation_slave_test_get_digests (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[96] = {0};
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;
	uint8_t cert_hash[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, cert_hash, 32, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &cert_hash[32], 32, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &cert_hash[64], 32, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, 96, status);
	CuAssertIntEquals (test, 3, num_cert);

	status = testing_validate_array (cert_hash, buf, 96);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	uint8_t buf[96] = {0};
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;
	uint8_t cert_hash[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, cert_hash, 32, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &cert_hash[32], 32, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &cert_hash[64], 32, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, 96, status);
	CuAssertIntEquals (test, 3, num_cert);

	status = testing_validate_array (cert_hash, buf, 96);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_get_digests_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[1] = {0};
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_no_int_ca (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[96] = {0};
	uint8_t cert_hash[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, cert_hash, 32, -1);
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect_output (&hash.mock, 2, &cert_hash[32], 32, -1);
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, 64, status);
	CuAssertIntEquals (test, 2, num_cert);

	status = testing_validate_array (cert_hash, buf, 64);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_no_int_ca_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[1] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_devid_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[96] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_alias_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[96] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_int_ca_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[96] = {0};
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_INTR_SIGNED_CERT,
			RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_digests (&attestation, buf, sizeof (buf), &num_cert);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_digests_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint16_t buf_len = 96;
	uint8_t buf[96] = {0};
	uint8_t num_cert = 0;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_digests (NULL, buf, buf_len, &num_cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.get_digests (&attestation, NULL, buf_len, &num_cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.get_digests (&attestation, buf, buf_len, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_dev_id_certificate (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (&attestation, 0, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_dev_id_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	status = attestation.get_certificate (&attestation, 0, 1, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_DEVID_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_get_alias_certificate (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (&attestation, 0, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_alias_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	status = attestation.get_certificate (&attestation, 0, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RIOT_CORE_ALIAS_CERT_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (cert.cert, RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_get_int_ca_certificate (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = attestation.get_certificate (&attestation, 0, 0, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, cert.cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_int_ca_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	uint8_t *dev_id_der;
	uint8_t *ca_der;
	uint8_t *int_der;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	add_int_ca_to_riot_key_manager (test, &riot, &keystore, &x509, &dev_id_der, &ca_der, &int_der);

	status = attestation.get_certificate (&attestation, 0, 0, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_ECC_CA_NOPL_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, cert.cert,
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_get_aux_certificate (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t *aux_der;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	aux_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, aux_der);

	memcpy (aux_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);
	status = aux_attestation_set_certificate (&aux, aux_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_certificate (&attestation, 1, 2, &cert);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert.length);
	CuAssertPtrNotNull (test, cert.cert);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert.cert, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_aux_certificate_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	status = attestation.get_certificate (&attestation, 1, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_get_dev_id_certificate_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;

	TEST_START;

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

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &bad_keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, &rng.base,
		&store, &aux);
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_certificate (&attestation, 0, 1, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_alias_certificate_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	struct riot_keys bad_keys;
	uint8_t num_pcr_measurements[1] = {6};
	uint8_t *dev_id_der = NULL;

	TEST_START;

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

	status = pcr_store_init (&store, num_pcr_measurements, sizeof (num_pcr_measurements));
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &dev_id_der, sizeof (dev_id_der), -1);
	CuAssertIntEquals (test, 0, status);

	memset (&bad_keys, 0, sizeof (bad_keys));
	bad_keys.alias_key = RIOT_CORE_ALIAS_KEY;
	bad_keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	status = riot_key_manager_init_static (&riot, &keystore.base, &bad_keys, &x509.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = attestation_slave_init (&attestation, &riot, &hash.base, &ecc.base, &rng.base,
		&store, &aux);
	CuAssertIntEquals (test, 0, status);

	status = attestation.get_certificate (&attestation, 0, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_int_ca_certificate_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (&attestation, 0, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_aux_certificate_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (&attestation, 1, 2, &cert);
	CuAssertIntEquals (test, ATTESTATION_CERT_NOT_AVAILABLE, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_certificate_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (&attestation, NUM_ATTESTATION_SLOT_NUM, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_certificate_invalid_cert_num (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (&attestation, 0, 3, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_CERT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_get_certificate_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct der_cert cert;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.get_certificate (NULL, 0, 0, &cert);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.get_certificate (&attestation, 0, 0, NULL);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct attestation_response *response;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[136] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
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

	response = (struct attestation_response*)buf;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));


	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.sign, &ecc, 64, MOCK_ARG (&attestation.ecc_priv_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&ecc.mock, 3, signature, sizeof (signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, 136, status);
	CuAssertIntEquals (test, 0, response->slot_num);
	CuAssertIntEquals (test, 1, response->slot_mask);
	CuAssertIntEquals (test, 1, response->min_protocol_version);
	CuAssertIntEquals (test, 1, response->max_protocol_version);
	CuAssertIntEquals (test, 1, response->num_digests);
	CuAssertIntEquals (test, 32, response->digests_size);

	status = testing_validate_array (measurement, buf + sizeof (struct attestation_response),
		sizeof (measurement));
	status |= testing_validate_array (signature,
		buf + sizeof (struct attestation_response) + sizeof (measurement),
		sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct attestation_response *response;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	uint8_t buf[136] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t digest1[] = {
		0xfc,0x3d,0x9d,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0x77,0x5b,0x12,0xc7,0x4d,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4e,0x7f,0x38,0x9c,0x4f,0x6f,0x38,0x9c,0x4a
	};
	uint8_t digest2[] = {
		0xf3,0xaa,0x91,0xe6,0x00,0x13,0xd6,0x11,0x12,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7d,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x34,0x9c,0x4f
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

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest1, sizeof (digest1), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digest1, sizeof (digest1)), MOCK_ARG (sizeof (digest1)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, digest2, sizeof (digest2), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (digest2, sizeof (digest2)), MOCK_ARG (sizeof (digest2)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.sign, &ecc, 64, MOCK_ARG (&attestation.ecc_priv_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_NOT_NULL, MOCK_ARG (64));
	status |= mock_expect_output (&ecc.mock, 3, signature, sizeof (signature), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, 136, status);
	CuAssertIntEquals (test, 0, response->slot_num);
	CuAssertIntEquals (test, 1, response->slot_mask);
	CuAssertIntEquals (test, 1, response->min_protocol_version);
	CuAssertIntEquals (test, 1, response->max_protocol_version);
	CuAssertIntEquals (test, 3, response->num_digests);
	CuAssertIntEquals (test, 32, response->digests_size);

	status = testing_validate_array (measurement, buf + sizeof (struct attestation_response),
		sizeof (measurement));
	status |= testing_validate_array (signature,
		buf + sizeof (struct attestation_response) + sizeof (measurement),
		sizeof (signature));
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_invalid_slot_num (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137];
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	buf[0] = 1;

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_INVALID_SLOT_NUM, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_compute_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137] = {0};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	attestation.pcr_store = NULL;

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, PCR_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_buf_smaller_than_response (
	CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[72] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_start_hash_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_update_challenge_hash_fail (
	CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_rng_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, RNG_ENGINE_NO_MEMORY,
		MOCK_ARG (32), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, RNG_ENGINE_NO_MEMORY, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_update_response_hash_fail (
	CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_finish_hash_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (32));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_sign_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct attestation_challenge challenge = {0};
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[136] = {0};
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t measurement[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	challenge.nonce[0] = 0xAA;
	challenge.nonce[31] = 0xBB;

	memcpy (buf, (uint8_t*)&challenge, sizeof (struct attestation_challenge));

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (32),
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (measurement, sizeof (measurement)), MOCK_ARG (sizeof (measurement)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&hash.mock, 0, measurement, sizeof (measurement), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (&challenge, sizeof (struct attestation_challenge)),
		MOCK_ARG (sizeof (struct attestation_challenge)));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32 + sizeof (struct attestation_response)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (32));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.sign, &ecc, ECC_ENGINE_NO_MEMORY,
		MOCK_ARG (&attestation.ecc_priv_key), MOCK_ARG_NOT_NULL, MOCK_ARG (32), MOCK_ARG_NOT_NULL,
		MOCK_ARG (64));
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, measurement, sizeof (measurement));
	CuAssertIntEquals (test, 0, status);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, ECC_ENGINE_NO_MEMORY, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_buf_too_small (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[1];
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.challenge_response (&attestation, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_BAD_LENGTH, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_pa_rot_challenge_response_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buf[137];
	uint16_t buf_len = sizeof (buf);

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.challenge_response (NULL, buf, buf_len);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.challenge_response (&attestation, NULL, buf_len);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_attestation_unseal (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct hash_engine_mock aux_hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t key[SHA256_HASH_LENGTH];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = hash_mock_init (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux_hash.mock, aux_hash.base.start_sha256, &aux_hash, 0);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer1, sizeof (buffer1)), MOCK_ARG (sizeof (buffer1)));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.finish, &aux_hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&aux_hash.mock, 0, PCR0_VALUE, PCR0_VALUE_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&aux_hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux_hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= hash_mock_expect_hmac_init (&aux_hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux_hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	status |= hash_mock_expect_hmac_init (&aux_hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux_hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_attestation_unseal (&attestation, &aux_hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, key,
		sizeof (key), 0);
	CuAssertIntEquals (test, ENCRYPTION_KEY_LEN, status);

	status = testing_validate_array (ENCRYPTION_KEY, key, status);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_attestation_unseal_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	uint8_t key[SHA256_HASH_LENGTH];

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&riot, &store, &keystore);

	status = attestation.aux_attestation_unseal (&attestation, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, key,
		sizeof (key), 0);
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_OPERATION, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_aux_attestation_unseal_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct hash_engine_mock aux_hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t key[SHA256_HASH_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = hash_mock_init (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux_hash.mock, aux_hash.base.start_sha256, &aux_hash, 0);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer1, sizeof (buffer1)), MOCK_ARG (sizeof (buffer1)));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.finish, &aux_hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&aux_hash.mock, 0, PCR0_VALUE, PCR0_VALUE_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, -1, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_attestation_unseal (&attestation, &aux_hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, key,
		sizeof (key), 0);
	CuAssertIntEquals (test, -1, status);

	status = hash_mock_validate_and_release (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_attestation_unseal_get_measurement_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct hash_engine_mock aux_hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t key[SHA256_HASH_LENGTH];
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = hash_mock_init (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux_hash.mock, aux_hash.base.start_sha256, &aux_hash,
		HASH_ENGINE_NO_MEMORY);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_attestation_unseal (&attestation, &aux_hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, key,
		sizeof (key), 0);
	CuAssertIntEquals (test, HASH_ENGINE_NO_MEMORY, status);

	status = hash_mock_validate_and_release (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_attestation_unseal_invalid_key_len (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct hash_engine_mock aux_hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t key[SHA256_HASH_LENGTH];
	uint8_t buffer0[PCR_DIGEST_LENGTH] = {0};
	uint8_t buffer1[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f,0x7f,0x38,0x9c,0x4f
	};
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = hash_mock_init (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aux_hash.mock, aux_hash.base.start_sha256, &aux_hash, 0);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer0, sizeof (buffer0)), MOCK_ARG (sizeof (buffer0)));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (buffer1, sizeof (buffer1)), MOCK_ARG (sizeof (buffer1)));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.finish, &aux_hash, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (PCR_DIGEST_LENGTH));
	status |= mock_expect_output (&aux_hash.mock, 0, PCR0_VALUE, PCR0_VALUE_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_init (&aux_hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux_hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= hash_mock_expect_hmac_init (&aux_hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&aux_hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);
	status |= hash_mock_expect_hmac_init (&aux_hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));
	status |= mock_expect (&aux_hash.mock, aux_hash.base.update, &aux_hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&aux_hash, KEY_SEED, KEY_SEED_LEN, NULL,
		SHA256_HASH_LENGTH, ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = pcr_store_update_digest (&store, 0, buffer1, sizeof (buffer1));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_attestation_unseal (&attestation, &aux_hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY, key,
		sizeof (key) - 1, 0);
	CuAssertIntEquals (test, ATTESTATION_BUF_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_attestation_unseal_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct hash_engine_mock aux_hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	const uint8_t seed = 0;
	const uint8_t hmac = 0;
	const uint8_t ciphertext = 0;
	const uint8_t sealing = 0;
	uint8_t key[2];
	size_t seed_length = 1;
	size_t cipher_length = 1;

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = hash_mock_init (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_attestation_unseal (NULL, &aux_hash.base, &seed, seed_length, &hmac,
		&ciphertext, cipher_length, &sealing, key, sizeof (key), 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.aux_attestation_unseal (&attestation, NULL, &seed, seed_length, &hmac,
		&ciphertext, cipher_length, &sealing, key, sizeof (key), 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.aux_attestation_unseal (&attestation, &aux_hash.base, &seed, seed_length,
		&hmac, &ciphertext, cipher_length, &sealing, NULL, sizeof (key), 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = attestation.aux_attestation_unseal (&attestation, &aux_hash.base, &seed, seed_length,
		&hmac, &ciphertext, cipher_length, &sealing, key, 0, 0);
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	status = hash_mock_validate_and_release (&aux_hash);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_decrypt (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_decrypt (&attestation, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_decrypt_with_label (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN),
		MOCK_ARG (RSA_ENCRYPT_LABEL_LEN), MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_decrypt (&attestation, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, decrypted,
		sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_decrypt_sha256 (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);
	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);
	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_decrypt (&attestation, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA256, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_decrypt_no_aux (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	uint8_t decrypted[4224];

	TEST_START;

	setup_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng, &riot,
		&store, &keystore);

	status = attestation.aux_decrypt (&attestation, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, ATTESTATION_UNSUPPORTED_OPERATION, status);

	complete_attestation_slave_no_aux_mock_test (test, &attestation, &hash, &ecc, &x509, &rng,
		&store, &keystore, &riot);
}

static void attestation_slave_test_aux_decrypt_fail (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_LOAD_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = attestation.aux_decrypt (&attestation, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

static void attestation_slave_test_aux_decrypt_null (CuTest *test)
{
	int status;
	struct attestation_slave attestation;
	struct hash_engine_mock hash;
	struct ecc_engine_mock ecc;
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct riot_key_manager riot;
	struct pcr_store store;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];

	TEST_START;

	setup_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng,
		&riot, &store, &keystore, &aux);

	status = attestation.aux_decrypt (NULL, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, ATTESTATION_INVALID_ARGUMENT, status);

	complete_attestation_slave_mock_test (test, &attestation, &hash, &ecc, &rsa, &x509, &rng, &store,
		&keystore, &aux, &riot);
}

CuSuite* get_attestation_slave_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, attestation_slave_test_init);
	SUITE_ADD_TEST (suite, attestation_slave_test_init_init_keypair_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_init_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_init_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_init_no_aux_init_keypair_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_init_no_aux_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_release_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_buf_too_small);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_no_int_ca);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_no_int_ca_buf_too_small);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_devid_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_alias_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_int_ca_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_digests_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_dev_id_certificate);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_dev_id_certificate_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_alias_certificate);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_alias_certificate_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_int_ca_certificate);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_int_ca_certificate_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_aux_certificate);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_aux_certificate_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_dev_id_certificate_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_alias_certificate_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_int_ca_certificate_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_aux_certificate_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_certificate_invalid_slot_num);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_certificate_invalid_cert_num);
	SUITE_ADD_TEST (suite, attestation_slave_test_get_certificate_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_invalid_slot_num);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_compute_fail);
	SUITE_ADD_TEST (suite,
		attestation_slave_test_pa_rot_challenge_response_buf_smaller_than_response);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_start_hash_fail);
	SUITE_ADD_TEST (suite,
		attestation_slave_test_pa_rot_challenge_response_update_challenge_hash_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_rng_fail);
	SUITE_ADD_TEST (suite,
		attestation_slave_test_pa_rot_challenge_response_update_response_hash_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_finish_hash_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_sign_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_buf_too_small);
	SUITE_ADD_TEST (suite, attestation_slave_test_pa_rot_challenge_response_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_attestation_unseal);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_attestation_unseal_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_attestation_unseal_fail);
	SUITE_ADD_TEST (suite,
		attestation_slave_test_aux_attestation_unseal_get_measurement_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_attestation_unseal_invalid_key_len);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_attestation_unseal_null);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_decrypt);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_decrypt_with_label);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_decrypt_sha256);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_decrypt_no_aux);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_decrypt_fail);
	SUITE_ADD_TEST (suite, attestation_slave_test_aux_decrypt_null);

	return suite;
}
