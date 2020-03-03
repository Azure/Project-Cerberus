// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "testing/ecc_testing.h"
#include "testing/signature_testing.h"
#include "testing/rsa_testing.h"
#include "crypto/ecc_mbedtls.h"


static const char *SUITE = "ecc_mbedtls";


#define	ECC_DSA_MAX_LENGTH			73


/*******************
 * Test cases
 *******************/

static void ecc_mbedtls_test_init (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.init_key_pair);
	CuAssertPtrNotNull (test, engine.base.init_public_key);
	CuAssertPtrNotNull (test, engine.base.generate_derived_key_pair);
	CuAssertPtrNotNull (test, engine.base.generate_key_pair);
	CuAssertPtrNotNull (test, engine.base.release_key_pair);
	CuAssertPtrNotNull (test, engine.base.get_signature_max_length);
	CuAssertPtrNotNull (test, engine.base.get_private_key_der);
	CuAssertPtrNotNull (test, engine.base.get_public_key_der);
	CuAssertPtrNotNull (test, engine.base.sign);
	CuAssertPtrNotNull (test, engine.base.verify);
	CuAssertPtrNotNull (test, engine.base.get_shared_secret_max_length);
	CuAssertPtrNotNull (test, engine.base.compute_shared_secret);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecc_mbedtls_init (NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
}

static void ecc_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	ecc_mbedtls_release (NULL);
}

static void ecc_mbedtls_test_public_key_init_key_pair_and_verify (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_init_key_pair_and_verify_bad_sig (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_private_key_init_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, (status > 0));

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);
	CuAssertPtrEquals (test, NULL, priv_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_init_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, (out_len > 0));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_key_pair_no_keys (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_key_pair_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (NULL, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_key_pair (&engine.base, NULL,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		0, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_key_pair_with_public_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, NULL, &pub_key);
	CuAssertTrue (test, (status < 0));
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_key_pair_with_rsa_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_public_key_and_verify (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_public_key_and_verify_bad_sig (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_public_key_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (NULL, (const uint8_t*) ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, NULL,
		ECC_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) ECC_PUBKEY_DER,
		0, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_public_key_with_private_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &pub_key);
	CuAssertTrue (test, (status < 0));
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_init_public_key_with_rsa_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_generate_derived_key_pair_and_verify (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_generate_derived_key_pair_and_verify_bad_sig (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_private_key_generate_derived_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, (status > 0));

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_generate_derived_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_derived_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, (out_len > 0));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_derived_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_derived_key_pair_no_keys (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_derived_key_pair_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (NULL, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_derived_key_pair (&engine.base, NULL, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, 0,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_generate_key_pair (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_private_key_generate_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, (status > 0));

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_public_key_generate_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, (out_len > 0));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_key_pair_no_keys (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_generate_key_pair_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (NULL, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_sign_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (NULL, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, NULL, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, &priv_key, NULL, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, 0, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, NULL,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_sign_small_buffer (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		ECC_DSA_MAX_LENGTH - 1);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_BUFFER_TOO_SMALL, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_verify_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (NULL, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, NULL, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, NULL, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, 0,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		NULL, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_verify_corrupt_signature (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t bad_sig[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (bad_sig, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	bad_sig[0] ^= 0x55;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		bad_sig, sizeof (bad_sig));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_signature_max_length (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_signature_max_length_derived_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_signature_max_length_random_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_signature_max_length_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (NULL, &priv_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_signature_max_length (&engine.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_shared_secret_max_length (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_DH_SECRET_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_shared_secret_max_length_derived_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_DH_SECRET_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_shared_secret_max_length_random_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_DH_SECRET_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_shared_secret_max_length_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (NULL, &priv_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_compute_shared_secret (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_compute_shared_secret_derived_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_compute_shared_secret_different_keys (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key1;
	struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key1;
	struct ecc_public_key pub_key2;
	int status;
	int out_len1;
	int out_len2;
	uint8_t out1[ECC_DH_SECRET_MAX_LENGTH * 2];
	uint8_t out2[ECC_DH_SECRET_MAX_LENGTH * 2];
	uint8_t sign[ECC_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key1, &pub_key1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key2, &pub_key2);
	CuAssertIntEquals (test, 0, status);

	/* Prove the two keys are different. */
	out_len1 = engine.base.sign (&engine.base, &priv_key1, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		sizeof (sign));
	CuAssertTrue (test, (out_len1 > 0));

	status = engine.base.verify (&engine.base, &pub_key2, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		out_len1);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	out_len2 = engine.base.sign (&engine.base, &priv_key2, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		sizeof (sign));
	CuAssertTrue (test, (out_len2 > 0));

	status = engine.base.verify (&engine.base, &pub_key1, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		out_len2);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	/* Prove the shared secret is the same for both keys. */
	out_len1 = engine.base.compute_shared_secret (&engine.base, &priv_key1, &pub_key2, out1,
		sizeof (out1));
	out_len2 = engine.base.compute_shared_secret (&engine.base, &priv_key2, &pub_key1, out2,
		sizeof (out2));

	CuAssertIntEquals (test, out_len1, out_len2);
	status = testing_validate_array (out1, out2, out_len1);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key1, &pub_key1);
	engine.base.release_key_pair (&engine.base, &priv_key2, &pub_key2);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_compute_shared_secret_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.compute_shared_secret (NULL, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.compute_shared_secret (&engine.base, NULL, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.compute_shared_secret (&engine.base, &priv_key, NULL, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, NULL,
		sizeof (out));
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_compute_shared_secret_small_buffer (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		ECC_DH_SECRET_LEN - 1);
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_BUFFER_TOO_SMALL, out_len);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_private_key_der (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PRIVKEY_DER, der, ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_private_key_der_derived_key_pair (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PRIVKEY_DER, der, ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_private_key_der_generated_key_pair (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	if ((length > ECC_PRIVKEY_DER_LEN + 1) || (length < ECC_PRIVKEY_DER_LEN - 1)) {
		CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);
	}

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_private_key_der_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (NULL, &priv_key, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, NULL, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_private_key_der_public_key_from_private (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, (struct ecc_private_key*) &pub_key,
		&der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_private_key_der_public_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, (const uint8_t*) ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, (struct ecc_private_key*) &pub_key,
		&der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_public_key_der (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_public_key_der_derived_key_pair (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_public_key_der_generated_key_pair (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_public_key_der_null (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (NULL, &pub_key, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, NULL, &length);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_mbedtls_release (&engine);
}

static void ecc_mbedtls_test_get_public_key_der_private_key (CuTest *test)
{
	struct ecc_engine_mbedtls engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = (uint8_t*) &status;;
	size_t length;

	TEST_START;

	status = ecc_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, (const uint8_t*) ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, (struct ecc_public_key*) &priv_key, &der,
		&length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PUBLIC_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_mbedtls_release (&engine);
}


CuSuite* get_ecc_mbedtls_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_release_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_init_key_pair_and_verify);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_init_key_pair_and_verify_bad_sig);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_private_key_init_key_pair_and_sign);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_init_key_pair_and_sign);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_key_pair_and_sign_and_verify);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_key_pair_and_sign_with_public_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_key_pair_no_keys);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_key_pair_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_key_pair_with_public_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_key_pair_with_rsa_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_public_key_and_verify);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_public_key_and_verify_bad_sig);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_public_key_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_public_key_with_private_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_init_public_key_with_rsa_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_generate_derived_key_pair_and_verify);
	SUITE_ADD_TEST (suite,
		ecc_mbedtls_test_public_key_generate_derived_key_pair_and_verify_bad_sig);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_private_key_generate_derived_key_pair_and_sign);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_generate_derived_key_pair_and_sign);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_derived_key_pair_and_sign_and_verify);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_derived_key_pair_and_sign_with_public_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_derived_key_pair_no_keys);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_derived_key_pair_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_generate_key_pair);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_private_key_generate_key_pair_and_sign);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_public_key_generate_key_pair_and_sign);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_key_pair_and_sign_and_verify);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_key_pair_and_sign_with_public_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_key_pair_no_keys);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_generate_key_pair_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_sign_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_sign_small_buffer);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_verify_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_verify_corrupt_signature);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_signature_max_length);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_signature_max_length_derived_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_signature_max_length_random_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_signature_max_length_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_shared_secret_max_length);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_shared_secret_max_length_derived_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_shared_secret_max_length_random_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_shared_secret_max_length_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_compute_shared_secret);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_compute_shared_secret_derived_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_compute_shared_secret_different_keys);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_compute_shared_secret_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_compute_shared_secret_small_buffer);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_private_key_der);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_private_key_der_derived_key_pair);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_private_key_der_generated_key_pair);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_private_key_der_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_private_key_der_public_key_from_private);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_private_key_der_public_key);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_public_key_der);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_public_key_der_derived_key_pair);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_public_key_der_generated_key_pair);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_public_key_der_null);
	SUITE_ADD_TEST (suite, ecc_mbedtls_test_get_public_key_der_private_key);

	return suite;
}
