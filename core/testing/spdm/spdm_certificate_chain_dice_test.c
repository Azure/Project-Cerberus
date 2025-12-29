// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/ecdsa.h"
#include "spdm/spdm_certificate_chain_dice.h"
#include "spdm/spdm_certificate_chain_dice_static.h"
#include "testing/asn1/x509_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("spdm_certificate_chain_dice");


/**
 * SHA-256 digest of RIOT_CORE_DEVID_CERT.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_SHA256[] = {
	0xab, 0xeb, 0xfc, 0x2b, 0xd0, 0x66, 0x4a, 0xea, 0x29, 0xe0, 0x19, 0xdd, 0xf5, 0xf1, 0x42, 0x3a,
	0x99, 0x54, 0xf2, 0x05, 0x3d, 0xe4, 0x19, 0xe8, 0x83, 0x45, 0x0e, 0xd4, 0x09, 0x49, 0x4a, 0xb4
};

/**
 * SHA-256 digest of the cert chain rooted with RIOT_CORE_DEVID_CERT.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_CHAIN_SHA256[] = {
	0xbd, 0x9f, 0x5c, 0x6d, 0xf5, 0xa2, 0x95, 0x9d, 0xda, 0xf9, 0x6e, 0x4b, 0x41, 0x1d, 0xc7, 0x9b,
	0xe1, 0x9e, 0xa1, 0x88, 0x5a, 0x1d, 0x28, 0xbe, 0xf1, 0x8c, 0x14, 0xb8, 0xbe, 0x84, 0xf0, 0x6c
};

/**
 * SHA-384 digest of RIOT_CORE_DEVID_CERT.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_SHA384[] = {
	0x7e, 0xf2, 0x92, 0xa2, 0xc6, 0x81, 0x9a, 0x83, 0x57, 0xf9, 0xae, 0x3d, 0x7f, 0x35, 0xc9, 0x2a,
	0xd9, 0xf4, 0xd4, 0xd3, 0xf0, 0x08, 0x32, 0x9b, 0x83, 0xb2, 0x7d, 0x55, 0xb0, 0x28, 0x67, 0xea,
	0x45, 0xf2, 0x18, 0x64, 0xfb, 0x44, 0x79, 0xf4, 0xb2, 0x92, 0x26, 0xe8, 0xe4, 0x93, 0xd9, 0xe7
};

/**
 * SHA-384 digest of the cert chain rooted with RIOT_CORE_DEVID_CERT.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_CHAIN_SHA384[] = {
	0xe5, 0xbf, 0x01, 0x70, 0x94, 0x21, 0xff, 0x4f, 0x4e, 0x22, 0xb9, 0x0f, 0xc4, 0x95, 0x63, 0x72,
	0x18, 0xcd, 0x71, 0x99, 0xbf, 0x79, 0x73, 0xec, 0x53, 0xa9, 0x60, 0x2a, 0x9c, 0x4b, 0xc0, 0xc2,
	0xe2, 0xae, 0xf9, 0xd9, 0xd4, 0x31, 0xd5, 0x14, 0xe0, 0x3e, 0xac, 0xdd, 0x56, 0x13, 0x0e, 0xb6
};

/**
 * SHA-512 digest of RIOT_CORE_DEVID_CERT.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_SHA512[] = {
	0x7d, 0xbc, 0xab, 0x76, 0x80, 0x6d, 0xf3, 0x4f, 0xe5, 0x68, 0x84, 0xfd, 0xb3, 0x5f, 0x84, 0xb1,
	0x8c, 0xd4, 0x37, 0x59, 0xd8, 0x0d, 0x85, 0x66, 0xe2, 0xb1, 0x8d, 0x88, 0xec, 0x55, 0xef, 0xfc,
	0x5f, 0x89, 0xe2, 0xc6, 0x7a, 0xa3, 0xad, 0xc1, 0x73, 0xcf, 0xef, 0x35, 0x94, 0x69, 0x1c, 0x8d,
	0xbd, 0x15, 0xae, 0x50, 0x27, 0x63, 0x75, 0x74, 0xc6, 0x2a, 0xbb, 0xc2, 0x1a, 0x0b, 0xfc, 0x64
};

/**
 * SHA-512 digest of the cert chain rooted with RIOT_CORE_DEVID_CERT.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_CHAIN_SHA512[] = {
	0x7e, 0x25, 0x53, 0xa8, 0x08, 0x81, 0x5d, 0x76, 0xa8, 0xf1, 0xa9, 0x9e, 0xb0, 0x19, 0xcc, 0x27,
	0xae, 0xd1, 0x4f, 0x90, 0x6a, 0xad, 0x44, 0x6e, 0xe5, 0x29, 0xe8, 0xff, 0x88, 0xdc, 0x7c, 0x3f,
	0xdd, 0x53, 0x49, 0x65, 0x01, 0xbb, 0xa8, 0x83, 0x28, 0x79, 0x7c, 0xb0, 0x90, 0x65, 0xe4, 0x82,
	0xd0, 0xc3, 0xab, 0x4b, 0xbd, 0xa8, 0x46, 0xdb, 0x16, 0xf5, 0xde, 0xc2, 0xd1, 0xd3, 0x44, 0xf1
};

/**
 * SHA-256 digest of X509_CERTSS_RSA_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256[] = {
	0x17, 0x5e, 0xd3, 0x23, 0x2c, 0xb6, 0x11, 0x2b, 0xf2, 0x30, 0xa9, 0xc4, 0xac, 0xa3, 0xc3, 0x29,
	0x81, 0xfa, 0xd9, 0xe4, 0xd1, 0x79, 0xab, 0x9c, 0x5c, 0x50, 0x50, 0xeb, 0x46, 0xca, 0x01, 0x5d
};

/**
 * SHA-256 digest of the cert chain rooted with X509_CERTSS_RSA_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA256[] = {
	0x95, 0x7e, 0x2e, 0xca, 0xec, 0x01, 0xbb, 0xfa, 0x5e, 0x7c, 0x17, 0xd1, 0x41, 0x5d, 0xc8, 0x03,
	0x92, 0xf7, 0xfa, 0xba, 0x96, 0x10, 0x79, 0x1e, 0xfc, 0x46, 0xcd, 0x69, 0x0a, 0x1b, 0xb2, 0xc5
};

/**
 * SHA-384 digest of X509_CERTSS_RSA_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384[] = {
	0x24, 0x82, 0x0a, 0xd2, 0xd3, 0x58, 0xcd, 0x9b, 0x67, 0xe6, 0x07, 0x42, 0xe5, 0xd2, 0x41, 0x0a,
	0xc6, 0x94, 0x2e, 0xfc, 0x15, 0x52, 0x53, 0x0c, 0x87, 0x4a, 0xd0, 0x66, 0xff, 0xcc, 0x18, 0xb5,
	0x64, 0x56, 0x20, 0x86, 0x5b, 0x7c, 0x0d, 0xea, 0x18, 0x72, 0x8f, 0x55, 0xb7, 0xc7, 0x02, 0x31
};

/**
 * SHA-384 digest of the cert chain rooted with X509_CERTSS_RSA_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA384[] = {
	0xd1, 0x2a, 0xa8, 0x9b, 0x5a, 0xda, 0xd3, 0x92, 0x22, 0x94, 0x01, 0x82, 0xd4, 0x77, 0x06, 0x5a,
	0x37, 0xa2, 0x10, 0xf4, 0x27, 0xf7, 0x0e, 0x3e, 0x4c, 0x79, 0x07, 0x81, 0xe2, 0x9d, 0xd9, 0x8d,
	0x69, 0x22, 0xf9, 0xb6, 0x1c, 0x42, 0x42, 0xaa, 0xe1, 0x99, 0x29, 0xa2, 0xf9, 0x99, 0xa8, 0x37
};

/**
 * SHA-512 digest of X509_CERTSS_RSA_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512[] = {
	0x57, 0xe6, 0xd6, 0x15, 0x66, 0x80, 0x4f, 0xa6, 0x4b, 0xa1, 0xbb, 0x8d, 0x9b, 0x47, 0xa2, 0x38,
	0x17, 0x08, 0x98, 0x11, 0xbc, 0x88, 0x81, 0xb7, 0x72, 0x42, 0x90, 0x09, 0x4c, 0xdc, 0x0d, 0x29,
	0x76, 0xba, 0xce, 0xa1, 0x34, 0x7a, 0x5b, 0x1c, 0xb8, 0x0f, 0x07, 0x1c, 0x43, 0x80, 0xe4, 0xd5,
	0x46, 0x3c, 0xc8, 0x73, 0x91, 0x43, 0x5c, 0xde, 0xc7, 0xee, 0xd8, 0x1c, 0x62, 0x29, 0x9e, 0x05
};

/**
 * SHA-512 digest of the cert chain rooted with X509_CERTSS_RSA_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA512[] = {
	0x48, 0x5a, 0xd0, 0x6e, 0x9b, 0x79, 0x3d, 0x30, 0xa6, 0x2e, 0x4e, 0xf0, 0xf9, 0x98, 0x53, 0xea,
	0x6a, 0xc3, 0xa8, 0xf2, 0xe8, 0xd0, 0xdf, 0x13, 0xb5, 0x24, 0xeb, 0x9a, 0x83, 0x85, 0x67, 0x38,
	0xc3, 0x95, 0x24, 0x85, 0xc1, 0x68, 0x76, 0x61, 0x0c, 0x29, 0x9c, 0xda, 0xc5, 0xa6, 0xf9, 0x9b,
	0xcc, 0x85, 0x49, 0x29, 0x51, 0x22, 0x55, 0x24, 0x07, 0xba, 0xd7, 0xd3, 0xab, 0x10, 0xd9, 0x16
};

/**
 * SHA-256 digest of X509_CERTSS_ECC_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_SHA256[] = {
	0x1b, 0xf0, 0x25, 0x3e, 0x8c, 0x17, 0x91, 0xf1, 0x04, 0x41, 0x64, 0x98, 0xbd, 0x50, 0x6c, 0x1a,
	0x05, 0x0d, 0x49, 0x4f, 0xe4, 0xb1, 0xeb, 0x72, 0x3b, 0x00, 0x07, 0x52, 0x34, 0xd2, 0x43, 0x1b
};

/**
 * SHA-256 digest of the cert chain rooted with X509_CERTSS_ECC_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_CHAIN_SHA256[] = {
	0x2b, 0xa4, 0xbc, 0xa7, 0x73, 0x4a, 0x60, 0xe4, 0x92, 0x1d, 0x71, 0x32, 0xfd, 0x65, 0xef, 0xe7,
	0x98, 0xf5, 0x4e, 0x93, 0x51, 0x66, 0xc9, 0xc9, 0x43, 0xad, 0x91, 0xdd, 0x84, 0x48, 0x07, 0x73
};

/**
 * SHA-384 digest of X509_CERTSS_ECC_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_SHA384[] = {
	0x66, 0x3d, 0x52, 0xe3, 0x73, 0xe2, 0x9e, 0xf4, 0x34, 0x7f, 0x17, 0xc2, 0x2c, 0x69, 0x1e, 0x22,
	0xef, 0xf2, 0x9a, 0x30, 0x6a, 0x5f, 0x99, 0x0c, 0xcc, 0xb4, 0xe4, 0x89, 0x79, 0xc4, 0xc8, 0xb0,
	0xa4, 0xb6, 0xb5, 0x11, 0x88, 0x04, 0xd0, 0x01, 0xe5, 0xee, 0xaf, 0x2c, 0xf0, 0x61, 0xc1, 0x09
};

/**
 * SHA-384 digest of the cert chain rooted with X509_CERTSS_ECC_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_CHAIN_SHA384[] = {
	0x6d, 0xd3, 0xa5, 0xdc, 0x7a, 0x95, 0xe1, 0x1c, 0x2c, 0x06, 0x5f, 0x18, 0xe7, 0x87, 0x56, 0xb2,
	0xa2, 0x5d, 0xcb, 0x95, 0xde, 0x3d, 0xd4, 0xfa, 0x4d, 0x36, 0x02, 0xf7, 0x65, 0x49, 0x5d, 0x0f,
	0x23, 0x30, 0xa2, 0x57, 0xc3, 0x1a, 0xba, 0xd4, 0x0e, 0xf6, 0xa8, 0xd9, 0x2f, 0x87, 0xd4, 0x7b
};

/**
 * SHA-512 digest of X509_CERTSS_ECC_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_SHA512[] = {
	0xc1, 0xa1, 0x33, 0x16, 0xee, 0x36, 0xe2, 0x3f, 0x85, 0xa0, 0x1c, 0xba, 0x4d, 0x58, 0x10, 0xb1,
	0x3d, 0x83, 0x8f, 0x7b, 0x88, 0xe7, 0xa7, 0xcd, 0x33, 0xbf, 0x91, 0xb6, 0xa1, 0xcb, 0x84, 0xf6,
	0x61, 0x3a, 0x93, 0xd7, 0x81, 0x30, 0x60, 0x50, 0xa3, 0x63, 0xe4, 0x06, 0xaf, 0x46, 0x9c, 0x4a,
	0xda, 0x63, 0x70, 0xe2, 0x68, 0x30, 0xce, 0xe6, 0x65, 0x51, 0xd3, 0xfe, 0x75, 0x86, 0x02, 0x42
};

/**
 * SHA-512 digest of the cert chain rooted with X509_CERTSS_ECC_CA_NOPL_DER.
 */
const uint8_t SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_CHAIN_SHA512[] = {
	0x7f, 0xb2, 0x71, 0x50, 0xfa, 0x46, 0x2d, 0x6b, 0x06, 0xd2, 0x02, 0x6c, 0xfd, 0xb9, 0x13, 0x02,
	0x77, 0x47, 0x1f, 0xe0, 0x9c, 0x32, 0x6d, 0x4c, 0x4a, 0x4e, 0x56, 0x6b, 0x5f, 0xd2, 0x2b, 0x14,
	0x87, 0x57, 0x10, 0xdd, 0x54, 0x8f, 0x26, 0x01, 0xfb, 0x10, 0xab, 0x1d, 0x66, 0xc0, 0x5e, 0x8f,
	0xcb, 0xe1, 0x51, 0xe4, 0x55, 0x1b, 0x92, 0xb8, 0x38, 0x76, 0x62, 0x2e, 0xdb, 0x58, 0x40, 0xa0
};


/**
 * Dependencies for testing SPDM handling for the DICE certificate chain..
 */
struct spdm_certificate_chain_dice_testing {
	HASH_TESTING_ENGINE (hash);					/**< Hash engine for testing. */
	ECC_TESTING_ENGINE (ecc);					/**< ECC engine for testing. */
	X509_TESTING_ENGINE (x509);					/**< X.509 engine for testing. */
	struct ecc_engine_mock ecc_mock;			/**< Mock for ECC operations. */
	struct hash_engine_mock hash_mock;			/**< Mock for hash operations. */
	struct keystore_mock keystore;				/**< Mock for the keystore containing stored certs. */
	struct riot_keys keys;						/**< DICE keys to manage. */
	struct riot_key_manager_state dice_state;	/**< Variable context for the DICE key manager. */
	struct riot_key_manager dice;				/**< Device DICE key manager. */
	struct spdm_certificate_chain_dice test;	/**< SPDM certificate chain under test. */
};


/**
 * Initialize testing dependencies.
 *
 * @param test The test framework.
 * @param chain The testing dependencies.
 * @param root_ca Flag indicating if the DICE certs should be signed with a root CA.
 * @param intermediate_ca Flag indicating if the DICE certs are signed through an intermediate CA.
 */
static void spdm_certificate_chain_dice_testing_init_dependencies (CuTest *test,
	struct spdm_certificate_chain_dice_testing *chain, bool root_ca, bool intermediate_ca)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&chain->hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&chain->ecc);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&chain->x509);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&chain->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&chain->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&chain->keystore);
	CuAssertIntEquals (test, 0, status);

	chain->keys.devid_csr = RIOT_CORE_DEVID_CSR;
	chain->keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;

	chain->keys.devid_cert = RIOT_CORE_DEVID_CERT;
	chain->keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;

	chain->keys.alias_key = RIOT_CORE_ALIAS_KEY;
	chain->keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;

	chain->keys.alias_cert = RIOT_CORE_ALIAS_CERT;
	chain->keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

	if (root_ca && intermediate_ca) {
		uint8_t *dev_id_der;
		uint8_t *ca_der;
		uint8_t *int_der;

		dev_id_der = platform_malloc (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
		CuAssertPtrNotNull (test, dev_id_der);

		ca_der = platform_malloc (X509_CERTSS_RSA_CA_NOPL_DER_LEN);
		CuAssertPtrNotNull (test, ca_der);

		int_der = platform_malloc (X509_CERTCA_ECC_CA_NOPL_DER_LEN);
		CuAssertPtrNotNull (test, int_der);

		memcpy (dev_id_der, RIOT_CORE_DEVID_INTR_SIGNED_CERT, RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
		memcpy (ca_der, X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);
		memcpy (int_der, X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

		status = mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &dev_id_der,
			sizeof (dev_id_der), -1);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 2,
			&RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN, sizeof (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN),
			-1);

		status |= mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &ca_der, sizeof (ca_der), -1);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 2,
			&X509_CERTSS_RSA_CA_NOPL_DER_LEN, sizeof (X509_CERTSS_RSA_CA_NOPL_DER_LEN), -1);

		status |= mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, 0, MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &int_der, sizeof (int_der), -1);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 2,
			&X509_CERTCA_ECC_CA_NOPL_DER_LEN, sizeof (X509_CERTCA_ECC_CA_NOPL_DER_LEN), -1);

		CuAssertIntEquals (test, 0, status);
	}
	else if (root_ca) {
		uint8_t *dev_id_der;
		uint8_t *ca_der;
		uint8_t *int_der = NULL;

		dev_id_der = platform_malloc (RIOT_CORE_DEVID_SIGNED_CERT_LEN);
		CuAssertPtrNotNull (test, dev_id_der);

		ca_der = platform_malloc (X509_CERTSS_ECC_CA_NOPL_DER_LEN);
		CuAssertPtrNotNull (test, ca_der);

		memcpy (dev_id_der, RIOT_CORE_DEVID_SIGNED_CERT, RIOT_CORE_DEVID_SIGNED_CERT_LEN);
		memcpy (ca_der, X509_CERTSS_ECC_CA_NOPL_DER, X509_CERTSS_ECC_CA_NOPL_DER_LEN);

		status = mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, 0, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &dev_id_der,
			sizeof (dev_id_der), -1);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 2,
			&RIOT_CORE_DEVID_SIGNED_CERT_LEN, sizeof (RIOT_CORE_DEVID_SIGNED_CERT_LEN), -1);

		status |= mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, 0, MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &ca_der, sizeof (ca_der), -1);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 2,
			&X509_CERTSS_ECC_CA_NOPL_DER_LEN, sizeof (X509_CERTSS_ECC_CA_NOPL_DER_LEN), -1);

		status |= mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, KEYSTORE_NO_KEY, MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &int_der, sizeof (int_der), -1);

		CuAssertIntEquals (test, 0, status);
	}
	else {
		uint8_t *dev_id_der = NULL;

		status = mock_expect (&chain->keystore.mock, chain->keystore.base.load_key,
			&chain->keystore, KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
		status |= mock_expect_output_tmp (&chain->keystore.mock, 1, &dev_id_der,
			sizeof (dev_id_der), -1);

		CuAssertIntEquals (test, 0, status);
	}

	status = riot_key_manager_init_static_keys (&chain->dice, &chain->dice_state,
		&chain->keystore.base, &chain->keys, &chain->x509.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release testing dependencies and validate all mocks.
 *
 * @param test The test framework.
 * @param chain The testing dependencies.
 */
static void spdm_certificate_chain_dice_testing_release_dependencies (CuTest *test,
	struct spdm_certificate_chain_dice_testing *chain)
{
	int status;

	riot_key_manager_release (&chain->dice);
	HASH_TESTING_ENGINE_RELEASE (&chain->hash);
	ECC_TESTING_ENGINE_RELEASE (&chain->ecc);
	X509_TESTING_ENGINE_RELEASE (&chain->x509);

	status = hash_mock_validate_and_release (&chain->hash_mock);
	status |= ecc_mock_validate_and_release (&chain->ecc_mock);
	status |= keystore_mock_validate_and_release (&chain->keystore);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a SPDM DICE certificate chain handler for testing.
 *
 * @param test The test framework.
 * @param chain The testing dependencies.
 * @param root_ca Flag indicating if the DICE certs should be signed with a root CA.
 * @param intermediate_ca Flag indicating if the DICE certs are signed through an intermediate CA.
 */
static void spdm_certificate_chain_dice_testing_init (CuTest *test,
	struct spdm_certificate_chain_dice_testing *chain, bool root_ca, bool intermediate_ca)
{
	int status;

	spdm_certificate_chain_dice_testing_init_dependencies (test, chain, root_ca, intermediate_ca);

	status = spdm_certificate_chain_dice_init (&chain->test, &chain->dice);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release a test SPDM certificate chain and all dependencies
 *
 * @param test The test framework.
 * @param chain The testing components to release.
 */
static void spdm_certificate_chain_dice_testing_release (CuTest *test,
	struct spdm_certificate_chain_dice_testing *chain)
{
	spdm_certificate_chain_dice_release (&chain->test);

	spdm_certificate_chain_dice_testing_release_dependencies (test, chain);
}


/*******************
 * Test cases
 *******************/

static void spdm_certificate_chain_dice_test_init (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;

	TEST_START;

	spdm_certificate_chain_dice_testing_init_dependencies (test, &chain, false, false);

	status = spdm_certificate_chain_dice_init (&chain.test, &chain.dice);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, chain.test.base.get_digest);
	CuAssertPtrNotNull (test, chain.test.base.get_certificate_chain);
	CuAssertPtrNotNull (test, chain.test.base.sign_message);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_init_null (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;

	TEST_START;

	spdm_certificate_chain_dice_testing_init_dependencies (test, &chain, false, false);

	status = spdm_certificate_chain_dice_init (NULL, &chain.dice);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = spdm_certificate_chain_dice_init (&chain.test, NULL);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	spdm_certificate_chain_dice_testing_release_dependencies (test, &chain);
}

static void spdm_certificate_chain_dice_test_static_init (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain = {
		.test = spdm_certificate_chain_dice_static_init (&chain.dice)
	};

	TEST_START;

	CuAssertPtrNotNull (test, chain.test.base.get_digest);
	CuAssertPtrNotNull (test, chain.test.base.get_certificate_chain);
	CuAssertPtrNotNull (test, chain.test.base.sign_message);

	spdm_certificate_chain_dice_testing_init_dependencies (test, &chain, false, false);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_release_null (CuTest *test)
{
	TEST_START;

	spdm_certificate_chain_dice_release (NULL);
}

static void spdm_certificate_chain_dice_test_get_digest_no_root_ca_sha256 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_CHAIN_SHA256, digest,
		SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_with_root_ca_sha256 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA256,
		digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_no_intermediate_ca_sha256 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, false);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_CHAIN_SHA256,
		digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

#ifdef HASH_ENABLE_SHA384
static void spdm_certificate_chain_dice_test_get_digest_no_root_ca_sha384 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA384_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA384,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_CHAIN_SHA384, digest,
		SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_with_root_ca_sha384 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA384_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA384,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA384,
		digest, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_no_intermediate_ca_sha384 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA384_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, false);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA384,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_CHAIN_SHA384,
		digest, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void spdm_certificate_chain_dice_test_get_digest_no_root_ca_sha512 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA512,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_CHAIN_SHA512, digest,
		SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_with_root_ca_sha512 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA512,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA512,
		digest, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_no_intermediate_ca_sha512 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA512_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, false);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA512,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_CHAIN_SHA512,
		digest, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

static void spdm_certificate_chain_dice_test_get_digest_static_init (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain = {
		.test = spdm_certificate_chain_dice_static_init (&chain.dice)
	};
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init_dependencies (test, &chain, true, true);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_CHAIN_SHA256,
		digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_null (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_digest (NULL, &chain.hash.base, HASH_TYPE_SHA256, digest,
		sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.get_digest (&chain.test.base, NULL, HASH_TYPE_SHA256, digest,
		sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256, NULL,
		sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_missing_device_id (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Modify the internal DICE key state to remove the Device ID.  The APIs don't allow this
	 * condition to normally happen. */
	chain.dice_state.keys.devid_cert = NULL;

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	/* Now modify the length of the cert. */
	chain.dice_state.keys.devid_cert = RIOT_CORE_DEVID_CERT;
	chain.dice_state.keys.devid_cert_length = 0;

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_missing_alias (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Modify the internal DICE key state to remove the Alias cert.  The APIs don't allow this
	 * condition to normally happen. */
	chain.dice_state.keys.alias_cert = NULL;

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	/* Now modify the length of the cert. */
	chain.dice_state.keys.alias_cert = RIOT_CORE_ALIAS_CERT;
	chain.dice_state.keys.alias_cert_length = 0;

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_no_root_ca_hash_error (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_with_root_ca_hash_error (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_start_hash_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_hash_header_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, 0);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_certificate_chain_min_header) + SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.cancel, &chain.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_hash_root_ca_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, 0);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_certificate_chain_min_header) + SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.cancel, &chain.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_hash_intermediate_ca_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, 0);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_certificate_chain_min_header) + SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.cancel, &chain.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_hash_device_id_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, 0);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_certificate_chain_min_header) + SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.cancel, &chain.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_hash_alias_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, 0);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_certificate_chain_min_header) + SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.cancel, &chain.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_digest_hash_finish_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, 0,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&chain.hash_mock.mock, 2,
		SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.start_sha256,
		&chain.hash_mock, 0);

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (struct spdm_certificate_chain_min_header) + SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (X509_CERTCA_ECC_CA_NOPL_DER_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.update, &chain.hash_mock, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (RIOT_CORE_ALIAS_CERT_LEN));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.finish, &chain.hash_mock,
		HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.cancel, &chain.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_digest (&chain.test.base, &chain.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_sha256 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_SHA256,
		header->root_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RIOT_CORE_DEVID_CERT, &out[next_cert],
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_sha256 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		header->root_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_INTR_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_no_intermediate_ca_sha256 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_ECC_CA_NOPL_DER_LEN + RIOT_CORE_DEVID_SIGNED_CERT_LEN +
		RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_SHA256,
		header->root_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

#ifdef HASH_ENABLE_SHA384
static void spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_sha384 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_SHA384,
		header->root_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RIOT_CORE_DEVID_CERT, &out[next_cert],
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_sha384 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384,
		header->root_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_INTR_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_no_intermediate_ca_sha384 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_ECC_CA_NOPL_DER_LEN + RIOT_CORE_DEVID_SIGNED_CERT_LEN +
		RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_SHA384,
		header->root_hash, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_sha512 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_DEVID_SHA512,
		header->root_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (RIOT_CORE_DEVID_CERT, &out[next_cert],
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_sha512 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512,
		header->root_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_INTR_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_no_intermediate_ca_sha512 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_ECC_CA_NOPL_DER_LEN + RIOT_CORE_DEVID_SIGNED_CERT_LEN +
		RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_ECC_CA_SHA512,
		header->root_hash, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_min_header (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = sizeof (struct spdm_certificate_chain_min_header) - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_min_header (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = sizeof (struct spdm_certificate_chain_min_header);
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_ca_digest_sha256
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_ca_digest_sha256 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

#ifdef HASH_ENABLE_SHA384
static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_ca_digest_sha384
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384,
		SHA384_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_ca_digest_sha384 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384,
		SHA384_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_ca_digest_sha512
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512,
		SHA512_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_ca_digest_sha512 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512,
		SHA512_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_root_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_root_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_intermediate_ca
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_intermediate_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_device_id (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN + RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_device_id (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN + RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_alias (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 0;
	size_t req_length = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN +
		X509_CERTCA_ECC_CA_NOPL_DER_LEN + RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN +
		RIOT_CORE_ALIAS_CERT_LEN - 1;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_min_header (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = sizeof (struct spdm_certificate_chain_min_header) - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_min_header (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = sizeof (struct spdm_certificate_chain_min_header);
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_ca_digest_sha256
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_ca_digest_sha256 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

#ifdef HASH_ENABLE_SHA384
static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_ca_digest_sha384
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384,
		SHA384_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_ca_digest_sha384 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384,
		SHA384_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_ca_digest_sha512
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512,
		SHA512_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_ca_digest_sha512 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512,
		SHA512_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_root_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_root_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_intermediate_ca
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN -
		1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_intermediate_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_device_id (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_device_id (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_alias (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN - 1;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_alias (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = exp_length;
	size_t req_length = exp_length - offset;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_more_than_total_length (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = exp_length + 1;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_min_header
	(CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = 1;
	size_t req_length = sizeof (struct spdm_certificate_chain_min_header) - 2;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void
spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_ca_digest_sha256 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = sizeof (struct spdm_certificate_chain_min_header) + 2;
	size_t req_length = SHA256_HASH_LENGTH - 4;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

#ifdef HASH_ENABLE_SHA384
static void
spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_ca_digest_sha384 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA384_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = sizeof (struct spdm_certificate_chain_min_header) + 2;
	size_t req_length = SHA384_HASH_LENGTH - 4;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA384,
		SHA384_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA384, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void
spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_ca_digest_sha512 (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA512_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = sizeof (struct spdm_certificate_chain_min_header) + 2;
	size_t req_length = SHA512_HASH_LENGTH - 4;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA512,
		SHA512_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA512, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_root_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + 4;
	size_t req_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN - 8;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void
spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_intermediate_ca (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + 4;
	size_t req_length = X509_CERTCA_ECC_CA_NOPL_DER_LEN - 8;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_device_id (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		4;
	size_t req_length = RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN - 8;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_alias (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	uint8_t exp_chain[buf_length];
	struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;
	int status;
	size_t offset = hdr_length + X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + 4;
	size_t req_length = RIOT_CORE_ALIAS_CERT_LEN - 8;
	uint8_t out[buf_length];
	size_t out_length = req_length;
	size_t total_length;

	TEST_START;

	header = (struct spdm_certificate_chain_header*) exp_chain;
	header->min_hdr.length = exp_length;
	header->min_hdr.reserved = 0;
	memcpy (header->root_hash, SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		SHA256_HASH_LENGTH);

	next_cert = hdr_length;
	memcpy (&exp_chain[next_cert], X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], X509_CERTCA_ECC_CA_NOPL_DER, X509_CERTCA_ECC_CA_NOPL_DER_LEN);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_DEVID_INTR_SIGNED_CERT,
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;
	memcpy (&exp_chain[next_cert], RIOT_CORE_ALIAS_CERT, RIOT_CORE_ALIAS_CERT_LEN);

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, offset, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, req_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	status = testing_validate_array (&exp_chain[offset], out, req_length);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_static_init (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain = {
		.test = spdm_certificate_chain_dice_static_init (&chain.dice)
	};
	const size_t hdr_length = sizeof (struct spdm_certificate_chain_min_header) +
		SHA256_HASH_LENGTH;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t exp_length = hdr_length + cert_length;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;
	const struct spdm_certificate_chain_header *header;
	size_t next_cert = hdr_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init_dependencies (test, &chain, true, true);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, exp_length, out_length);
	CuAssertIntEquals (test, hdr_length + cert_length, total_length);

	header = (const struct spdm_certificate_chain_header*) out;
	CuAssertIntEquals (test, exp_length, header->min_hdr.length);
	CuAssertIntEquals (test, 0, header->min_hdr.reserved);

	status = testing_validate_array (SPDM_CERTIFICATE_CHAIN_DICE_TESTING_RSA_CA_SHA256,
		header->root_hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (X509_CERTSS_RSA_CA_NOPL_DER, &out[next_cert],
		X509_CERTSS_RSA_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTSS_RSA_CA_NOPL_DER_LEN;

	status = testing_validate_array (X509_CERTCA_ECC_CA_NOPL_DER, &out[next_cert],
		X509_CERTCA_ECC_CA_NOPL_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += X509_CERTCA_ECC_CA_NOPL_DER_LEN;

	status = testing_validate_array (RIOT_CORE_DEVID_INTR_SIGNED_CERT, &out[next_cert],
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	next_cert += RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN;

	status = testing_validate_array (RIOT_CORE_ALIAS_CERT, &out[next_cert],
		RIOT_CORE_ALIAS_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_null (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_certificate_chain (NULL, &chain.hash.base, HASH_TYPE_SHA256, 0,
		out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.get_certificate_chain (&chain.test.base, NULL, HASH_TYPE_SHA256, 0,
		out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, NULL, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, NULL, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, NULL);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_zero_length (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = 0;
	size_t total_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_missing_device_id (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Modify the internal DICE key state to remove the Device ID.  The APIs don't allow this
	 * condition to normally happen. */
	chain.dice_state.keys.devid_cert = NULL;

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	/* Now modify the length of the cert. */
	chain.dice_state.keys.devid_cert = RIOT_CORE_DEVID_CERT;
	chain.dice_state.keys.devid_cert_length = 0;

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_missing_alias (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Modify the internal DICE key state to remove the Alias cert.  The APIs don't allow this
	 * condition to normally happen. */
	chain.dice_state.keys.alias_cert = NULL;

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	/* Now modify the length of the cert. */
	chain.dice_state.keys.alias_cert = RIOT_CORE_ALIAS_CERT;
	chain.dice_state.keys.alias_cert_length = 0;

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_MISSING_CERT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_hash_error (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t cert_length = RIOT_CORE_DEVID_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash_mock.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_hash_error (
	CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	const size_t cert_length = X509_CERTSS_RSA_CA_NOPL_DER_LEN + X509_CERTCA_ECC_CA_NOPL_DER_LEN +
		RIOT_CORE_DEVID_INTR_SIGNED_CERT_LEN + RIOT_CORE_ALIAS_CERT_LEN;
	const size_t buf_length = sizeof (struct spdm_certificate_chain_header) + cert_length;
	int status;
	uint8_t out[buf_length];
	size_t out_length = buf_length;
	size_t total_length;

	TEST_START;

	memset (out, 0x55, sizeof (out));

	spdm_certificate_chain_dice_testing_init (test, &chain, true, true);

	status = mock_expect (&chain.hash_mock.mock, chain.hash_mock.base.calculate_sha256,
		&chain.hash_mock, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (X509_CERTSS_RSA_CA_NOPL_DER, X509_CERTSS_RSA_CA_NOPL_DER_LEN),
		MOCK_ARG (X509_CERTSS_RSA_CA_NOPL_DER_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.get_certificate_chain (&chain.test.base, &chain.hash_mock.base,
		HASH_TYPE_SHA256, 0, out, &out_length, &total_length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_sign_message_sha256 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t signature[ECC_DER_P256_ECDSA_MAX_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Use a mock ECC engine to get easily verifiable execution and deterministic signature output.
	 * This follows the same pattern used for ECDSA testing.  The signature is not actually correct
	 * for the data, but the flow is being verified as correct. */
	status = mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.init_key_pair, &chain.ecc_mock,
		0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&chain.ecc_mock.mock, 2, 0);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.sign, &chain.ecc_mock,
		ECC_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&chain.ecc_mock.mock, 4, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, 5);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.release_key_pair,
		&chain.ecc_mock, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc_mock.base, &chain.hash.base,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST, signature, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

#ifdef HASH_ENABLE_SHA384
static void spdm_certificate_chain_dice_test_sign_message_sha384 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t signature[ECC_DER_P256_ECDSA_MAX_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Use a mock ECC engine to get easily verifiable execution and deterministic signature output.
	 * This follows the same pattern used for ECDSA testing.  The signature is not actually correct
	 * for the data, but the flow is being verified as correct. */
	status = mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.init_key_pair, &chain.ecc_mock,
		0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&chain.ecc_mock.mock, 2, 0);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.sign, &chain.ecc_mock,
		ECC_SIG_TEST2_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (SHA384_FULL_BLOCK_1024_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&chain.ecc_mock.mock, 4, ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN,
		5);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.release_key_pair,
		&chain.ecc_mock, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc_mock.base, &chain.hash.base,
		HASH_TYPE_SHA384, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECC_SIG_TEST2_LEN, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST2, signature, ECC_SIG_TEST2_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void spdm_certificate_chain_dice_test_sign_message_sha512 (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t signature[ECC_DER_P256_ECDSA_MAX_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	/* Use a mock ECC engine to get easily verifiable execution and deterministic signature output.
	 * This follows the same pattern used for ECDSA testing.  The signature is not actually correct
	 * for the data, but the flow is being verified as correct. */
	status = mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.init_key_pair, &chain.ecc_mock,
		0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&chain.ecc_mock.mock, 2, 0);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.sign, &chain.ecc_mock,
		ECC_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (SHA512_FULL_BLOCK_1024_HASH, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH), MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&chain.ecc_mock.mock, 4, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, 5);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.release_key_pair,
		&chain.ecc_mock, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc_mock.base, &chain.hash.base,
		HASH_TYPE_SHA512, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST, signature, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}
#endif

static void spdm_certificate_chain_dice_test_sign_message_static_init (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain = {
		.test = spdm_certificate_chain_dice_static_init (&chain.dice)
	};
	int status;
	uint8_t signature[ECC_DER_P256_ECDSA_MAX_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init_dependencies (test, &chain, false, false);

	/* Use a mock ECC engine to get easily verifiable execution and deterministic signature output.
	 * This follows the same pattern used for ECDSA testing.  The signature is not actually correct
	 * for the data, but the flow is being verified as correct. */
	status = mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.init_key_pair, &chain.ecc_mock,
		0, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&chain.ecc_mock.mock, 2, 0);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.sign, &chain.ecc_mock,
		ECC_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&chain.ecc_mock.mock, 4, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, 5);

	status |= mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.release_key_pair,
		&chain.ecc_mock, 0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc_mock.base, &chain.hash.base,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECC_SIG_TEST_LEN, status);

	status = testing_validate_array (ECC_SIGNATURE_TEST, signature, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_sign_message_null (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t signature[ECC_DER_P256_ECDSA_MAX_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = chain.test.base.sign_message (NULL, &chain.ecc.base, &chain.hash.base,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, SPDM_CERT_CHAIN_INVALID_ARGUMENT, status);

	status = chain.test.base.sign_message (&chain.test.base, NULL, &chain.hash.base,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc.base, NULL,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc.base, &chain.hash.base,
		HASH_TYPE_SHA256, NULL, HASH_TESTING_FULL_BLOCK_1024_LEN, signature, sizeof (signature));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc.base, &chain.hash.base,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, NULL,
		sizeof (signature));
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}

static void spdm_certificate_chain_dice_test_sign_message_ecc_error (CuTest *test)
{
	struct spdm_certificate_chain_dice_testing chain;
	int status;
	uint8_t signature[ECC_DER_P256_ECDSA_MAX_LENGTH];

	TEST_START;

	spdm_certificate_chain_dice_testing_init (test, &chain, false, false);

	status = mock_expect (&chain.ecc_mock.mock, chain.ecc_mock.base.init_key_pair, &chain.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&chain.ecc_mock.mock, 2, 0);

	CuAssertIntEquals (test, 0, status);

	status = chain.test.base.sign_message (&chain.test.base, &chain.ecc_mock.base, &chain.hash.base,
		HASH_TYPE_SHA256, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN, signature,
		sizeof (signature));
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	spdm_certificate_chain_dice_testing_release (test, &chain);
}


// *INDENT-OFF*
TEST_SUITE_START (spdm_certificate_chain_dice);

TEST (spdm_certificate_chain_dice_test_init);
TEST (spdm_certificate_chain_dice_test_init_null);
TEST (spdm_certificate_chain_dice_test_static_init);
TEST (spdm_certificate_chain_dice_test_release_null);
TEST (spdm_certificate_chain_dice_test_get_digest_no_root_ca_sha256);
TEST (spdm_certificate_chain_dice_test_get_digest_with_root_ca_sha256);
TEST (spdm_certificate_chain_dice_test_get_digest_no_intermediate_ca_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (spdm_certificate_chain_dice_test_get_digest_no_root_ca_sha384);
TEST (spdm_certificate_chain_dice_test_get_digest_with_root_ca_sha384);
TEST (spdm_certificate_chain_dice_test_get_digest_no_intermediate_ca_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (spdm_certificate_chain_dice_test_get_digest_no_root_ca_sha512);
TEST (spdm_certificate_chain_dice_test_get_digest_with_root_ca_sha512);
TEST (spdm_certificate_chain_dice_test_get_digest_no_intermediate_ca_sha512);
#endif
TEST (spdm_certificate_chain_dice_test_get_digest_static_init);
TEST (spdm_certificate_chain_dice_test_get_digest_null);
TEST (spdm_certificate_chain_dice_test_get_digest_missing_device_id);
TEST (spdm_certificate_chain_dice_test_get_digest_missing_alias);
TEST (spdm_certificate_chain_dice_test_get_digest_no_root_ca_hash_error);
TEST (spdm_certificate_chain_dice_test_get_digest_with_root_ca_hash_error);
TEST (spdm_certificate_chain_dice_test_get_digest_start_hash_error);
TEST (spdm_certificate_chain_dice_test_get_digest_hash_header_error);
TEST (spdm_certificate_chain_dice_test_get_digest_hash_root_ca_error);
TEST (spdm_certificate_chain_dice_test_get_digest_hash_intermediate_ca_error);
TEST (spdm_certificate_chain_dice_test_get_digest_hash_device_id_error);
TEST (spdm_certificate_chain_dice_test_get_digest_hash_alias_error);
TEST (spdm_certificate_chain_dice_test_get_digest_hash_finish_error);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_sha256);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_sha256);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_intermediate_ca_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_sha384);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_sha384);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_intermediate_ca_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_sha512);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_sha512);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_intermediate_ca_sha512);
#endif
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_min_header);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_min_header);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_ca_digest_sha256);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_ca_digest_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_ca_digest_sha384);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_ca_digest_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_ca_digest_sha512);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_ca_digest_sha512);
#endif
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_root_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_root_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_intermediate_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_intermediate_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_device_id);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_up_to_device_id);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_length_less_than_alias);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_min_header);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_min_header);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_ca_digest_sha256);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_ca_digest_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_ca_digest_sha384);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_ca_digest_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_ca_digest_sha512);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_ca_digest_sha512);
#endif
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_root_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_root_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_intermediate_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_intermediate_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_device_id);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_device_id);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_less_than_alias);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_skip_alias);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_more_than_total_length);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_min_header);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_ca_digest_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_ca_digest_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_ca_digest_sha512);
#endif
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_root_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_intermediate_ca);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_device_id);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_offset_length_partial_alias);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_static_init);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_null);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_zero_length);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_missing_device_id);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_missing_alias);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_no_root_ca_hash_error);
TEST (spdm_certificate_chain_dice_test_get_certificate_chain_with_root_ca_hash_error);
TEST (spdm_certificate_chain_dice_test_sign_message_sha256);
#ifdef HASH_ENABLE_SHA384
TEST (spdm_certificate_chain_dice_test_sign_message_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (spdm_certificate_chain_dice_test_sign_message_sha512);
#endif
TEST (spdm_certificate_chain_dice_test_sign_message_static_init);
TEST (spdm_certificate_chain_dice_test_sign_message_null);
TEST (spdm_certificate_chain_dice_test_sign_message_ecc_error);

TEST_SUITE_END;
// *INDENT-ON*
