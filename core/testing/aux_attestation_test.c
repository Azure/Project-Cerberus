// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "attestation/aux_attestation.h"
#include "mock/keystore_mock.h"
#include "mock/rsa_mock.h"
#include "mock/hash_mock.h"
#include "mock/x509_mock.h"
#include "mock/rng_mock.h"
#include "engines/rsa_testing_engine.h"
#include "engines/hash_testing_engine.h"
#include "engines/x509_testing_engine.h"
#include "engines/rng_testing_engine.h"
#include "rsa_testing.h"
#include "riot_core_testing.h"
#include "x509_testing.h"


static const char *SUITE = "aux_attestation";


/**
 * The random seed for key derivation.
 */
const uint8_t KEY_SEED[] = {
	0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef
};

const size_t KEY_SEED_LEN = sizeof (KEY_SEED);

/**
 * The random seed encrypted with the RSA public key using OAEP padding.
 */
const uint8_t KEY_SEED_ENCRYPT_OAEP[] = {
	0x91,0x78,0x45,0xa6,0xc0,0x00,0x39,0x05,0x9a,0xfe,0xc2,0xeb,0x0c,0xfb,0xe7,0x43,
	0xae,0x52,0xd3,0x6a,0xce,0x0e,0xac,0xb7,0x0b,0xc1,0x51,0xb3,0x9c,0xbd,0xce,0xd9,
	0x41,0x87,0x79,0x45,0x30,0xe9,0x63,0x7d,0xfd,0xc6,0x83,0xcb,0x50,0x95,0x1e,0xab,
	0x6d,0xdf,0x76,0x29,0x5c,0x62,0xb9,0x20,0x30,0x4f,0xf2,0x90,0x61,0x1e,0x38,0x9a,
	0x37,0x9a,0x8e,0x75,0xcd,0x77,0x99,0x6a,0x3f,0x63,0x5c,0xac,0xa7,0xfb,0x25,0xf6,
	0xf9,0xeb,0x9e,0x1e,0x8b,0xd6,0xde,0x9d,0xc4,0x90,0x46,0xe7,0xe9,0x90,0x65,0x1b,
	0xbe,0x18,0x63,0xe8,0xfa,0x9f,0x1c,0x20,0x06,0x4d,0xb4,0xab,0x7d,0x7e,0x83,0xaf,
	0x4a,0xa2,0xb6,0x7d,0x61,0xfe,0x01,0x20,0xce,0xe2,0xf7,0x46,0x0d,0x52,0x68,0x0c,
	0x03,0x96,0x3e,0x64,0x9b,0x12,0x4b,0x13,0xc4,0xf1,0x90,0x6d,0x6c,0x80,0xac,0xcd,
	0xb3,0x07,0xbb,0xee,0xdf,0x67,0x5c,0xfa,0xd0,0x79,0xe9,0x75,0x28,0x82,0x2f,0x9a,
	0x4c,0x8b,0xc5,0x31,0xf4,0x14,0x93,0xcb,0xf0,0xd8,0xd7,0x77,0x38,0x58,0x98,0xf1,
	0x99,0x51,0x1b,0xe2,0x1b,0x5f,0xd3,0xcb,0x0c,0x1d,0x36,0x6d,0x4b,0xe3,0x6f,0xa8,
	0xff,0x0f,0xc5,0x97,0x49,0xb2,0xce,0xf9,0xce,0x94,0x17,0xb0,0xe5,0x66,0x7e,0x6b,
	0x52,0x8c,0xeb,0x1d,0x22,0x08,0x58,0x1b,0x83,0xb7,0x61,0x1c,0x97,0x04,0x92,0x52,
	0xca,0x9d,0x35,0x71,0xf4,0x88,0x95,0x96,0xc8,0xee,0xb0,0xfe,0xba,0xb0,0xc3,0x09,
	0x75,0x81,0x14,0xe1,0x22,0xa1,0x2a,0xc1,0x3a,0xa6,0xdb,0xe0,0xe9,0x34,0x07,0x5a
};

const size_t KEY_SEED_ENCRYPT_OAEP_LEN = sizeof (KEY_SEED_ENCRYPT_OAEP);

/**
 * The value of i in the NIST SP800-108 KDF algorithm.
 */
const uint8_t NIST_KEY_DERIVE_I[] = {
	0x00,0x00,0x00,0x01
};

const size_t NIST_KEY_DERIVE_I_LEN = sizeof (NIST_KEY_DERIVE_I);

/**
 * The label for deriving the encryption key.
 */
const char ENCRYPTION_KEY_LABEL[] = "encryption key";

const size_t ENCRYPTION_KEY_LABEL_LEN = sizeof (ENCRYPTION_KEY_LABEL);

/**
 * The label for deriving the signing key.
 */
const char SIGNING_KEY_LABEL[] = "signing key";

const size_t SIGNING_KEY_LABEL_LEN = sizeof (SIGNING_KEY_LABEL);

/**
 * The value of L in the NIST SP800-108 KDF algorithm.
 */
const uint8_t NIST_KEY_DERIVE_L[] = {
	0x00,0x00,0x01,0x00
};

const size_t NIST_KEY_DERIVE_L_LEN = sizeof (NIST_KEY_DERIVE_L);

/**
 * The encryption key derived from the seed.  (Label=encryption key, Context=empty).
 */
const uint8_t ENCRYPTION_KEY[] = {
	0x4d,0xb6,0x71,0x95,0x44,0xa8,0x43,0x26,0x6f,0x0e,0xeb,0x3b,0xff,0xc7,0xfd,0xe3,
	0x08,0xe3,0x7f,0x80,0xb7,0xf0,0x0e,0x40,0x46,0xa0,0x3e,0x71,0x3b,0xc1,0x8d,0x95
};

const size_t ENCRYPTION_KEY_LEN = sizeof (ENCRYPTION_KEY);

/**
 * The signing key derived from the seed.  (Label=signing key, Context=empty).
 */
const uint8_t SIGNING_KEY[] = {
	0x84,0x89,0xf7,0x68,0x6e,0xa3,0xcc,0xb3,0x9c,0xef,0x4c,0x21,0x8b,0x84,0xfa,0xdd,
	0x48,0x85,0xc4,0x66,0x8b,0xda,0xe9,0x6f,0xcb,0xbe,0xa5,0x7b,0x14,0x40,0xcc,0x24
};

const size_t SIGNING_KEY_LEN = sizeof (SIGNING_KEY);

/**
 * Data provided as the cipher text, though not actually encrypted with the key.
 */
const uint8_t CIPHER_TEXT[] = {
	0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};

const size_t CIPHER_TEXT_LEN = sizeof (CIPHER_TEXT);

/**
 * 64-byte Sealing policy value.
 */
const uint8_t SEALING_POLICY[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
	0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
};

const size_t SEALING_POLICY_LEN = sizeof (SEALING_POLICY);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY).
 */
const uint8_t PAYLOAD_HMAC[] = {
	0x42,0xce,0xa2,0xdf,0x4c,0xf0,0x7a,0x66,0xf1,0x46,0x82,0xef,0xd9,0x75,0x0b,0xb8,
	0x35,0x00,0x8c,0x4f,0xae,0x36,0x53,0xe4,0x89,0x4d,0xaa,0xc8,0x2a,0xa0,0x16,0x72
};

const size_t PAYLOAD_HMAC_LEN = sizeof (PAYLOAD_HMAC);

/**
 * Sealing policy that bypasses PCR checks.
 */
static const uint8_t SEALING_POLICY_BYPASS[] = {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const size_t SEALING_POLICY_BYPASS_LEN = sizeof (SEALING_POLICY_BYPASS);

/**
 * HMAC (SIGNING_KEY, CIPHER_TEXT || SEALING_POLICY_BYPASS).
 */
static const uint8_t PAYLOAD_BYPASS_HMAC[] = {
	0x5a,0xfa,0xb0,0x2c,0xe2,0x3f,0x24,0x8d,0x50,0x44,0x77,0xde,0x82,0x40,0x1a,0xe4,
	0x8a,0x45,0x81,0xee,0xe5,0x15,0x82,0x82,0x68,0x51,0x37,0xb4,0x0b,0x87,0x5f,0xb8
};

static const size_t PAYLOAD_BYPASS_HMAC_LEN = sizeof (PAYLOAD_BYPASS_HMAC);

/**
 * The local PCR0 value.
 */
const uint8_t PCR0_VALUE[] = {
	0xf7,0x0e,0x27,0xc8,0xf0,0x0d,0x40,0x34,0xad,0xab,0x82,0x40,0x17,0x3e,0xd7,0x74,
	0xe4,0x4a,0xcb,0xd7,0x4d,0x0b,0x24,0xad,0x3d,0x4b,0x75,0x29,0x11,0x57,0x98,0x1e
};

const size_t PCR0_VALUE_LEN = sizeof (PCR0_VALUE);


/*******************
 * Test cases
 *******************/

static void aux_attestation_test_init (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void aux_attestation_test_init_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (NULL, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_init (&aux, NULL, &rsa.base);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_init (&aux, &keystore.base, NULL);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void aux_attestation_test_release_null (CuTest *test)
{
	TEST_START;

	aux_attestation_release (NULL);
}

static void aux_attestation_test_generate_key (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der = NULL;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&rsa.mock, rsa.base.generate_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.get_private_key_der, &rsa, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rsa.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&rsa.mock, 2, &RSA_PRIVKEY_DER_LEN, sizeof (RSA_PRIVKEY_DER_LEN),
		-1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_generate_key_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (NULL);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_generate_key_generation_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&rsa.mock, rsa.base.generate_key, &rsa, RSA_ENGINE_GENERATE_KEY_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (3072));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux);
	CuAssertIntEquals (test, RSA_ENGINE_GENERATE_KEY_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_generate_key_der_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&rsa.mock, rsa.base.generate_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.get_private_key_der, &rsa,
		RSA_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux);
	CuAssertIntEquals (test, RSA_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_generate_key_save_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der = NULL;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&rsa.mock, rsa.base.generate_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (3072));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.get_private_key_der, &rsa, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rsa.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&rsa.mock, 2, &RSA_PRIVKEY_DER_LEN, sizeof (RSA_PRIVKEY_DER_LEN),
		-1);

	status |= mock_expect (&keystore.mock, keystore.base.save_key, &keystore, KEYSTORE_SAVE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_generate_key (&aux);
	CuAssertIntEquals (test, KEYSTORE_SAVE_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	status |= mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_authenticate (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	X509_TESTING_ENGINE x509;
	RNG_TESTING_ENGINE rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	size_t key_length;
	struct x509_certificate aux_cert;
	struct x509_ca_certs ca_certs;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);

	status = x509.base.load_certificate (&x509.base, &aux_cert, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.init_ca_cert_store (&x509.base, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.add_root_ca (&x509.base, &ca_certs, RIOT_CORE_DEVID_CERT,
		RIOT_CORE_DEVID_CERT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.authenticate (&x509.base, &aux_cert, &ca_certs);
	CuAssertIntEquals (test, 0, status);

	status = x509.base.get_public_key (&x509.base, &aux_cert, &key_der, &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PUBKEY_DER_LEN, key_length);

	status = testing_validate_array (RSA_PUBKEY_DER, key_der, key_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (key_der);
	x509.base.release_certificate (&x509.base, &aux_cert);
	x509.base.release_ca_cert_store (&x509.base, &ca_certs);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	X509_TESTING_ENGINE_RELEASE (&x509);
	RNG_TESTING_ENGINE_RELEASE (&rng);
}

static void aux_attestation_test_create_certificate_twice (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	X509_TESTING_ENGINE x509;
	RNG_TESTING_ENGINE rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = X509_TESTING_ENGINE_INIT (&x509);
	CuAssertIntEquals (test, 0, status);

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);

	status = mock_validate (&keystore.mock);
	CuAssertIntEquals (test, 0, status);

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	X509_TESTING_ENGINE_RELEASE (&x509);
	RNG_TESTING_ENGINE_RELEASE (&rng);
}

static void aux_attestation_test_create_certificate_zero_serial_number (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t zero[8] = {0};

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, zero, sizeof (zero), 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_zero_serial_number_twice (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t zero[8] = {0};

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, zero, sizeof (zero), 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, zero, sizeof (zero), 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (NULL, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux, NULL, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, NULL,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		NULL, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, 0, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, NULL,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		0);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_no_private_key (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *null = NULL;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_NO_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &null, sizeof (null), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, KEYSTORE_NO_KEY, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_bad_private_key (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *null = NULL;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_BAD_KEY,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &null, sizeof (null), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, KEYSTORE_BAD_KEY, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_load_key_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der = NULL;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_LOAD_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_load_ca_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, X509_ENGINE_LOAD_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_LOAD_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_serial_number_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (8), MOCK_ARG_NOT_NULL);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_create_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509,
		X509_ENGINE_CA_SIGNED_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CA_SIGNED_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_create_certificate_cert_der_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der = NULL;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	status |= mock_expect (&x509.mock, x509.base.get_certificate_der, &x509,
		X509_ENGINE_CERT_DER_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&x509.mock, 1, &cert_der, sizeof (cert_der), -1);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, X509_ENGINE_CERT_DER_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_certificate (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertPtrEquals (test, cert_der, (void*) cert->cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_certificate_before_create (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	status |= mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_certificate_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (NULL, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_certificate (&aux, NULL, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_certificate (&aux, cert_der, 0);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_certificate_twice (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert_der = platform_malloc (X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (cert_der != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_certificate_after_create (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	status |= mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert_der = platform_malloc (X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_ECC_EE_DER, X509_CERTCA_ECC_EE_DER_LEN);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (cert_der != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	platform_free (cert_der);
}

static void aux_attestation_test_set_static_certificate (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertPtrEquals (test, (void*) X509_CERTCA_RSA_EE_DER, (void*) cert->cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_static_certificate_before_create (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	status |= mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_static_certificate_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (NULL, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_static_certificate (&aux, NULL,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_RSA_EE_DER,
		0);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_static_certificate_twice (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (X509_CERTCA_ECC_EE_DER != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_set_static_certificate_after_create (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct rng_engine_mock rng;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *key_der;
	uint8_t *cert_der;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.load_certificate, &x509, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN),
		MOCK_ARG (RIOT_CORE_DEVID_CERT_LEN));
	status |= mock_expect_save_arg (&x509.mock, 0, 0);

	status |= mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0, MOCK_ARG (8),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN, 0);

	status |= mock_expect (&x509.mock, x509.base.create_ca_signed_certificate, &x509, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN),
		MOCK_ARG_PTR_CONTAINS (X509_CA2_SERIAL_NUM, X509_CA2_SERIAL_NUM_LEN), MOCK_ARG (8),
		MOCK_ARG_PTR_CONTAINS ("AUX", 3), MOCK_ARG (X509_CERT_END_ENTITY),
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_DEVICE_ID, RIOT_CORE_DEVICE_ID_LEN),
		MOCK_ARG (RIOT_CORE_DEVICE_ID_LEN), MOCK_ARG_SAVED_ARG (0), MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&x509.mock, 0, 1);

	status |= mock_expect (&x509.mock, x509.base.get_certificate_der, &x509, 0,
		MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&x509.mock, 1, &cert_der, sizeof (cert_der), -1);
	status |= mock_expect_output (&x509.mock, 2, &X509_CERTCA_RSA_EE_DER_LEN,
		sizeof (X509_CERTCA_RSA_EE_DER_LEN), -1);

	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (1));
	status |= mock_expect (&x509.mock, x509.base.release_certificate, &x509, 0,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_create_certificate (&aux, &x509.base, &rng.base,
		RIOT_CORE_DEVID_CERT, RIOT_CORE_DEVID_CERT_LEN, RIOT_CORE_DEVICE_ID,
		RIOT_CORE_DEVICE_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_ECC_EE_DER,
		X509_CERTCA_ECC_EE_DER_LEN);
	CuAssertIntEquals (test, AUX_ATTESTATION_HAS_CERTIFICATE, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrNotNull (test, cert);
	CuAssertTrue (test, (X509_CERTCA_ECC_EE_DER != cert->cert));
	CuAssertIntEquals (test, X509_CERTCA_RSA_EE_DER_LEN, cert->length);

	status = testing_validate_array (X509_CERTCA_RSA_EE_DER, cert->cert, cert->length);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_get_certificate_null (CuTest *test)
{
	const struct der_cert *cert;

	TEST_START;

	cert = aux_attestation_get_certificate (NULL);
	CuAssertPtrEquals (test, NULL, (void*) cert);

}

static void aux_attestation_test_unseal (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, attestation_key);
	CuAssertIntEquals (test, ENCRYPTION_KEY_LEN, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, key_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_pcr_mismatch (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;
	uint8_t bad_pcr[PCR0_VALUE_LEN];

	TEST_START;

	memcpy (bad_pcr, PCR0_VALUE, PCR0_VALUE_LEN);
	bad_pcr[0] ^= 0x55;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		bad_pcr, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_PCR_MISMATCH, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_bypass_pcr_check (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY_BYPASS, SEALING_POLICY_BYPASS_LEN),
		MOCK_ARG (SEALING_POLICY_BYPASS_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_BYPASS_HMAC, PAYLOAD_BYPASS_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		ENCRYPTION_KEY, ENCRYPTION_KEY_LEN);

	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_BYPASS_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY_BYPASS, PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, attestation_key);
	CuAssertIntEquals (test, ENCRYPTION_KEY_LEN, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, key_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_bad_hmac (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_BYPASS_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN,
		SEALING_POLICY, PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_HMAC_MISMATCH, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_no_mock (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	HASH_TESTING_ENGINE hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, attestation_key);
	CuAssertIntEquals (test, ENCRYPTION_KEY_LEN, key_length);

	status = testing_validate_array (ENCRYPTION_KEY, attestation_key, key_length);
	CuAssertIntEquals (test, 0, status);

	platform_free (attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void aux_attestation_test_unseal_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (NULL, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, NULL, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, NULL,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		0, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, NULL, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, NULL, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, 0, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, NULL,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		NULL, &attestation_key, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, NULL, &key_length);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, NULL);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_load_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der = NULL;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_LOAD_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_init_key_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, RSA_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, RSA_ENGINE_KEY_PAIR_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_decrypt_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, RSA_ENGINE_DECRYPT_FAILED,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, RSA_ENGINE_DECRYPT_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_signing_key_init_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_signing_key_hash_i_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_signing_key_hash_label_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_signing_key_hash_L_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_signing_key_finish_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_validate_init_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_validate_hash_cipher_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_validate_hash_policy_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_validate_finish_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_encryption_key_init_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_encryption_key_hash_i_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_encryption_key_hash_label_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_encryption_key_hash_L_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_unseal_encryption_key_finish_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct hash_engine_mock hash;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	uint8_t *key_der;
	uint8_t *attestation_key;
	size_t key_length;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	/* Decrypt seed */
	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (3072 / 8));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	/* Derive signing key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) SIGNING_KEY_LABEL, SIGNING_KEY_LABEL_LEN),
		MOCK_ARG (SIGNING_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, KEY_SEED, KEY_SEED_LEN, NULL, SHA256_HASH_LENGTH,
		SIGNING_KEY, SIGNING_KEY_LEN);

	/* Validate cipher text and sealing policy */
	status |= hash_mock_expect_hmac_init (&hash, SIGNING_KEY, SIGNING_KEY_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (CIPHER_TEXT, CIPHER_TEXT_LEN),
		MOCK_ARG (CIPHER_TEXT_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (SEALING_POLICY, SEALING_POLICY_LEN),
		MOCK_ARG (SEALING_POLICY_LEN));
	status |= hash_mock_expect_hmac_finish (&hash, SIGNING_KEY, SIGNING_KEY_LEN, NULL,
		SHA256_HASH_LENGTH, PAYLOAD_HMAC, PAYLOAD_HMAC_LEN);

	/* Derive encryption key */
	status |= hash_mock_expect_hmac_init (&hash, KEY_SEED, KEY_SEED_LEN);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_I, NIST_KEY_DERIVE_I_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_I_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS ((uint8_t*) ENCRYPTION_KEY_LABEL, ENCRYPTION_KEY_LABEL_LEN),
		MOCK_ARG (ENCRYPTION_KEY_LABEL_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (NIST_KEY_DERIVE_L, NIST_KEY_DERIVE_L_LEN),
		MOCK_ARG (NIST_KEY_DERIVE_L_LEN));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	attestation_key = (uint8_t*) &status;
	status = aux_attestation_unseal (&aux, &hash.base, KEY_SEED_ENCRYPT_OAEP,
		KEY_SEED_ENCRYPT_OAEP_LEN, PAYLOAD_HMAC, CIPHER_TEXT, CIPHER_TEXT_LEN, SEALING_POLICY,
		PCR0_VALUE, &attestation_key, &key_length);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);
	CuAssertPtrEquals (test, NULL, attestation_key);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_erase_key (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.erase_key, &keystore, 0, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_erase_key_with_certificate (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.erase_key, &keystore, 0, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_erase_key_with_static_certificate (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_static_certificate (&aux, X509_CERTCA_RSA_EE_DER,
		X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.erase_key, &keystore, 0, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux);
	CuAssertIntEquals (test, 0, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_erase_key_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (NULL);
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_erase_key_erase_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct x509_engine_mock x509;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	int status;
	const struct der_cert *cert;
	uint8_t *cert_der;

	TEST_START;

	cert_der = platform_malloc (X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertPtrNotNull (test, cert_der);

	memcpy (cert_der, X509_CERTCA_RSA_EE_DER, X509_CERTCA_RSA_EE_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_init (&x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_set_certificate (&aux, cert_der, X509_CERTCA_RSA_EE_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.erase_key, &keystore, KEYSTORE_ERASE_FAILED,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_erase_key (&aux);
	CuAssertIntEquals (test, KEYSTORE_ERASE_FAILED, status);

	cert = aux_attestation_get_certificate (&aux);
	CuAssertPtrEquals (test, NULL, (void*) cert);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = x509_mock_validate_and_release (&x509);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt_with_label (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
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

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, decrypted,
		sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt_sha256 (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, KEY_SEED_LEN, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA256), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));
	status |= mock_expect_output (&rsa.mock, 6, KEY_SEED, KEY_SEED_LEN, 7);

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA256, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEY_SEED_LEN, status);

	status = testing_validate_array (KEY_SEED, decrypted, KEY_SEED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt_null (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	int status;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (NULL, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_decrypt (&aux, NULL, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, NULL, sizeof (decrypted));
	CuAssertIntEquals (test, AUX_ATTESTATION_INVALID_ARGUMENT, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt_load_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	int status;

	TEST_START;

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, KEYSTORE_LOAD_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, KEYSTORE_LOAD_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt_init_key_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, RSA_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, RSA_ENGINE_KEY_PAIR_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}

static void aux_attestation_test_decrypt_error (CuTest *test)
{
	struct rsa_engine_mock rsa;
	struct keystore_mock keystore;
	struct aux_attestation aux;
	uint8_t decrypted[4224];
	uint8_t *key_der;
	int status;

	TEST_START;

	key_der = platform_malloc (RSA_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key_der);

	memcpy (key_der, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);

	status = rsa_mock_init (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_init (&aux, &keystore.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&keystore.mock, keystore.base.load_key, &keystore, 0, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&keystore.mock, 1, &key_der, sizeof (key_der), -1);
	status |= mock_expect_output (&keystore.mock, 2, &RSA_PRIVKEY_DER_LEN,
		sizeof (RSA_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&rsa.mock, rsa.base.init_private_key, &rsa, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN),
		MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	status |= mock_expect_save_arg (&rsa.mock, 0, 0);

	status |= mock_expect (&rsa.mock, rsa.base.decrypt, &rsa, RSA_ENGINE_DECRYPT_FAILED,
		MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG_PTR_CONTAINS (KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN),
		MOCK_ARG (KEY_SEED_ENCRYPT_OAEP_LEN), MOCK_ARG (NULL), MOCK_ARG (0),
		MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (decrypted)));

	status |= mock_expect (&rsa.mock, rsa.base.release_key, &rsa, 0, MOCK_ARG_SAVED_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = aux_attestation_decrypt (&aux, KEY_SEED_ENCRYPT_OAEP, KEY_SEED_ENCRYPT_OAEP_LEN,
		NULL, 0, HASH_TYPE_SHA1, decrypted, sizeof (decrypted));
	CuAssertIntEquals (test, RSA_ENGINE_DECRYPT_FAILED, status);

	status = keystore_mock_validate_and_release (&keystore);
	CuAssertIntEquals (test, 0, status);

	status = rsa_mock_validate_and_release (&rsa);
	CuAssertIntEquals (test, 0, status);

	aux_attestation_release (&aux);
}


CuSuite* get_aux_attestation_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, aux_attestation_test_init);
	SUITE_ADD_TEST (suite, aux_attestation_test_init_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_release_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_generate_key);
	SUITE_ADD_TEST (suite, aux_attestation_test_generate_key_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_generate_key_generation_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_generate_key_der_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_generate_key_save_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_authenticate);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_twice);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_zero_serial_number);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_zero_serial_number_twice);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_no_private_key);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_bad_private_key);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_load_key_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_load_ca_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_serial_number_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_create_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_create_certificate_cert_der_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_certificate);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_certificate_before_create);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_certificate_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_certificate_twice);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_certificate_after_create);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_static_certificate);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_static_certificate_before_create);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_static_certificate_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_static_certificate_twice);
	SUITE_ADD_TEST (suite, aux_attestation_test_set_static_certificate_after_create);
	SUITE_ADD_TEST (suite, aux_attestation_test_get_certificate_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_pcr_mismatch);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_bypass_pcr_check);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_bad_hmac);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_no_mock);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_load_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_init_key_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_decrypt_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_signing_key_init_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_signing_key_hash_i_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_signing_key_hash_label_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_signing_key_hash_L_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_signing_key_finish_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_validate_init_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_validate_hash_cipher_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_validate_hash_policy_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_validate_finish_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_encryption_key_init_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_encryption_key_hash_i_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_encryption_key_hash_label_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_encryption_key_hash_L_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_unseal_encryption_key_finish_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_erase_key);
	SUITE_ADD_TEST (suite, aux_attestation_test_erase_key_with_certificate);
	SUITE_ADD_TEST (suite, aux_attestation_test_erase_key_with_static_certificate);
	SUITE_ADD_TEST (suite, aux_attestation_test_erase_key_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_erase_key_erase_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt_with_label);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt_sha256);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt_null);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt_load_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt_init_key_error);
	SUITE_ADD_TEST (suite, aux_attestation_test_decrypt_error);

	return suite;
}
