// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "crypto/ecc_openssl.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("ecc_openssl");


/* Maximum lengths of DER-encoded ECDSA signatures.
 * Sequence -> 2 bytes overhead (3 for ECC521)
 *	BIT STRING (r) -> 2 bytes overhead (3 if MSB is 1)
 *	BIT STRING (s) -> 2 bytes overhead (3 if MSB is 1) */
#define	ECC256_DSA_MAX_LENGTH		72
#define	ECC384_DSA_MAX_LENGTH		104
#define	ECC521_DSA_MAX_LENGTH		141


/*******************
 * Test cases
 *******************/

static void ecc_openssl_test_init (CuTest *test)
{
	struct ecc_engine_openssl engine;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecc_openssl_init (NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);
}

static void ecc_openssl_test_release_null (CuTest *test)
{
	TEST_START;

	ecc_openssl_release (NULL);
}

static void ecc_openssl_test_public_key_init_key_pair_and_verify (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_public_key_init_key_pair_and_verify_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_public_key_init_key_pair_and_verify_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_public_key_init_key_pair_and_verify_bad_sig (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_private_key_init_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (status));

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);
	CuAssertPtrEquals (test, NULL, priv_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_init_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_and_sign_and_verify_no_pubkey (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_NO_PUBKEY_DER,
		ECC_PRIVKEY_NO_PUBKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_init_key_pair_and_sign_and_verify_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC384_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_and_sign_and_verify_no_pubkey_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC384_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_NO_PUBKEY_DER,
		ECC384_PRIVKEY_NO_PUBKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_init_key_pair_and_sign_and_verify_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC521_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_and_sign_and_verify_no_pubkey_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC521_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_NO_PUBKEY_DER,
		ECC521_PRIVKEY_NO_PUBKEY_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_and_sign_and_verify_no_leading_zero_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC521_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER_NO_LEADING_ZERO,
		ECC521_PRIVKEY_DER_NO_LEADING_ZERO_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_init_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
	CuAssertPtrEquals (test, NULL, priv_key.context);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_no_keys (CuTest *test)
{
	struct ecc_engine_openssl engine;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		NULL);
	CuAssertIntEquals (test, 0, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (NULL, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key,  &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_key_pair (&engine.base, NULL, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, 0,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_with_public_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);	// We can't distinguish this case from the RSA case.
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_key_pair_with_rsa_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_public_key_and_verify (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_init_public_key_and_verify_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_init_public_key_and_verify_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_init_public_key_and_verify_bad_sig (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_public_key_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, NULL, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, 0,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_public_key_with_private_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&pub_key);
	CuAssertTrue (test, (status < 0));
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_init_public_key_with_rsa_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_derived_key_pair_and_verify (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_derived_key_pair_and_verify_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC384_PRIVKEY,
		ECC384_PRIVKEY_LEN, NULL, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH,
		ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_derived_key_pair_and_verify_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC521_PRIVKEY,
		ECC521_PRIVKEY_LEN, NULL, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH,
		ECC521_SIGNATURE_TEST, ECC521_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_derived_key_pair_and_verify_bad_sig (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_private_key_generate_derived_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (status));

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_derived_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_and_sign_and_verify_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC384_PRIVKEY,
		ECC384_PRIVKEY_LEN, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_and_sign_and_verify_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC521_PRIVKEY,
		ECC521_PRIVKEY_LEN, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_no_keys (CuTest *test)
{
	struct ecc_engine_openssl engine;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_derived_key_pair_unsupported_key_length (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, 16, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_key_pair (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_private_key_generate_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (status));

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_public_key_generate_key_pair_and_sign (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_and_sign_and_verify (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_and_sign_and_verify_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_384, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA384_TEST_HASH, SHA384_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_and_sign_and_verify_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	int out_len;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];
#endif

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	out_len = engine.base.sign (&engine.base, &priv_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		sizeof (out));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len));

	status = engine.base.verify (&engine.base, &pub_key, SHA512_TEST_HASH, SHA512_HASH_LENGTH, out,
		out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_and_sign_with_public_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.sign (&engine.base, (struct ecc_private_key*) &pub_key, SIG_HASH_TEST,
		SIG_HASH_LEN, out, sizeof (out));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_no_keys (CuTest *test)
{
	struct ecc_engine_openssl engine;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, NULL);
	CuAssertIntEquals (test, 0, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (NULL, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_generate_key_pair_unsupported_key_length (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, 16, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_sign_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_sign_small_buffer (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sign (&engine.base, &priv_key, SIG_HASH_TEST, SIG_HASH_LEN, out,
		ECC256_DSA_MAX_LENGTH - 1);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_BUFFER_TOO_SMALL, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_verify_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_verify_corrupt_signature (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t bad_sig[ECC_SIG_TEST_LEN];

	TEST_START;

	memcpy (bad_sig, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	bad_sig[0] ^= 0x55;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, pub_key.context);

	status = engine.base.verify (&engine.base, &pub_key, SIG_HASH_TEST, SIG_HASH_LEN,
		bad_sig, sizeof (bad_sig));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);
	CuAssertPtrEquals (test, NULL, pub_key.context);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_signature_max_length (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_get_signature_max_length_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC384_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_get_signature_max_length_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC521_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_get_signature_max_length_derived_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_signature_max_length_random_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC256_DSA_MAX_LENGTH, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_signature_max_length_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_signature_max_length (NULL, &priv_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_signature_max_length (&engine.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_shared_secret_max_length (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_get_shared_secret_max_length_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_384, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_get_shared_secret_max_length_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_521, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_get_shared_secret_max_length_derived_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_derived_key_pair (&engine.base, ECC_PRIVKEY, ECC_PRIVKEY_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_shared_secret_max_length_random_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, &priv_key);
	CuAssertIntEquals (test, ECC_KEY_LENGTH_256, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_shared_secret_max_length_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_shared_secret_max_length (NULL, &priv_key);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_shared_secret_max_length (&engine.base, NULL);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_compute_shared_secret (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_compute_shared_secret_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC384_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC384_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC384_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_compute_shared_secret_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC521_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC521_DH_SECRET_LEN, out_len);

	status = testing_validate_array (ECC521_DH_SECRET, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_compute_shared_secret_leading_zero (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_LEADING_ZERO_DER,
		ECC_PRIVKEY_LEADING_ZERO_DER_LEN, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		sizeof (out));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEADING_ZERO_LEN, out_len);

	status = testing_validate_array (ECC_DH_SECRET_LEADING_ZERO, out, out_len);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_compute_shared_secret_derived_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_compute_shared_secret_different_keys (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key1;
	struct ecc_private_key priv_key2;
	struct ecc_public_key pub_key1;
	struct ecc_public_key pub_key2;
	int status;
	int out_len1;
	int out_len2;
	uint8_t out1[ECC_KEY_LENGTH_256 * 2];
	uint8_t out2[ECC_KEY_LENGTH_256 * 2];
	uint8_t sign[ECC256_DSA_MAX_LENGTH * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key1,
		&pub_key1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key2,
		&pub_key2);
	CuAssertIntEquals (test, 0, status);

	/* Prove the two keys are different. */
	out_len1 = engine.base.sign (&engine.base, &priv_key1, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		sizeof (sign));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len1));

	status = engine.base.verify (&engine.base, &pub_key2, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		out_len1);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	out_len2 = engine.base.sign (&engine.base, &priv_key2, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		sizeof (sign));
	CuAssertTrue (test, !ROT_IS_ERROR (out_len2));

	status = engine.base.verify (&engine.base, &pub_key1, SIG_HASH_TEST, SIG_HASH_LEN, sign,
		out_len2);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	/* Prove the shared secret is the same for both keys. */
	out_len1 = engine.base.compute_shared_secret (&engine.base, &priv_key1, &pub_key2, out1,
		sizeof (out1));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len1);

	out_len2 = engine.base.compute_shared_secret (&engine.base, &priv_key2, &pub_key1, out2,
		sizeof (out2));
	CuAssertIntEquals (test, ECC_DH_SECRET_LEN, out_len2);

	status = testing_validate_array (out1, out2, out_len1);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key_pair (&engine.base, &priv_key1, &pub_key1);
	engine.base.release_key_pair (&engine.base, &priv_key2, &pub_key2);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_compute_shared_secret_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_compute_shared_secret_small_buffer (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	int out_len;
	uint8_t out[ECC_DH_SECRET_LEN * 2];

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	out_len = engine.base.compute_shared_secret (&engine.base, &priv_key, &pub_key, out,
		ECC_DH_SECRET_LEN - 1);
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_BUFFER_TOO_SMALL, out_len);

	engine.base.release_key_pair (&engine.base, &priv_key, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_private_key_der (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
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

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_get_private_key_der_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC384_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC384_PRIVKEY_DER, der, ECC384_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_get_private_key_der_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC521_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (ECC521_PRIVKEY_DER, der, ECC521_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_get_private_key_der_derived_key_pair (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_private_key_der_generated_key_pair (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &priv_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	if ((length > ECC_PRIVKEY_DER_LEN + 1) || (length < ECC_PRIVKEY_DER_LEN - 1)) {
		CuAssertIntEquals (test, ECC_PRIVKEY_DER_LEN, length);
	}

	platform_free (der);
	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_private_key_der_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_private_key_der_public_key_from_private (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, (struct ecc_private_key*) &pub_key,
		&der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_private_key_der_public_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = (uint8_t*) &status;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, (struct ecc_private_key*) &pub_key,
		&der, &length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PRIVATE_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_public_key_der (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC_PUBKEY_DER, der, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecc_openssl_test_get_public_key_der_p384 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC384_PRIVKEY_DER, ECC384_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC384_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC384_PUBKEY_DER, der, ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecc_openssl_test_get_public_key_der_p521 (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC521_PRIVKEY_DER, ECC521_PRIVKEY_DER_LEN,
		NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC521_PUBKEY_DER_LEN, length);

	status = testing_validate_array (ECC521_PUBKEY_DER, der, ECC521_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}
#endif

static void ecc_openssl_test_get_public_key_der_derived_key_pair (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_public_key_der_generated_key_pair (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der = NULL;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key_pair (&engine.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &pub_key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, der);
	CuAssertIntEquals (test, ECC_PUBKEY_DER_LEN, length);

	platform_free (der);
	engine.base.release_key_pair (&engine.base, NULL, &pub_key);

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_public_key_der_null (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_public_key pub_key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&pub_key);
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

	ecc_openssl_release (&engine);
}

static void ecc_openssl_test_get_public_key_der_private_key (CuTest *test)
{
	struct ecc_engine_openssl engine;
	struct ecc_private_key priv_key;
	int status;
	uint8_t *der = (uint8_t*) &status;;
	size_t length;

	TEST_START;

	status = ecc_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_key_pair (&engine.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN,
		&priv_key, NULL);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, (struct ecc_public_key*) &priv_key, &der,
		&length);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_PUBLIC_KEY, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key_pair (&engine.base, &priv_key, NULL);

	ecc_openssl_release (&engine);
}


TEST_SUITE_START (ecc_openssl);

TEST (ecc_openssl_test_init);
TEST (ecc_openssl_test_init_null);
TEST (ecc_openssl_test_release_null);
TEST (ecc_openssl_test_public_key_init_key_pair_and_verify);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_public_key_init_key_pair_and_verify_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_public_key_init_key_pair_and_verify_p521);
#endif
TEST (ecc_openssl_test_public_key_init_key_pair_and_verify_bad_sig);
TEST (ecc_openssl_test_private_key_init_key_pair_and_sign);
TEST (ecc_openssl_test_public_key_init_key_pair_and_sign);
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify);
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify_no_pubkey);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify_p384);
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify_no_pubkey_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify_p521);
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify_no_pubkey_p521);
TEST (ecc_openssl_test_init_key_pair_and_sign_and_verify_no_leading_zero_p521);
#endif
TEST (ecc_openssl_test_init_key_pair_and_sign_with_public_key);
TEST (ecc_openssl_test_init_key_pair_no_keys);
TEST (ecc_openssl_test_init_key_pair_null);
TEST (ecc_openssl_test_init_key_pair_with_public_key);
TEST (ecc_openssl_test_init_key_pair_with_rsa_key);
TEST (ecc_openssl_test_init_public_key_and_verify);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_init_public_key_and_verify_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_init_public_key_and_verify_p521);
#endif
TEST (ecc_openssl_test_init_public_key_and_verify_bad_sig);
TEST (ecc_openssl_test_init_public_key_null);
TEST (ecc_openssl_test_init_public_key_with_private_key);
TEST (ecc_openssl_test_init_public_key_with_rsa_key);
TEST (ecc_openssl_test_public_key_generate_derived_key_pair_and_verify);
TEST (ecc_openssl_test_public_key_generate_derived_key_pair_and_verify_p384);
TEST (ecc_openssl_test_public_key_generate_derived_key_pair_and_verify_p521);
TEST (ecc_openssl_test_public_key_generate_derived_key_pair_and_verify_bad_sig);
TEST (ecc_openssl_test_private_key_generate_derived_key_pair_and_sign);
TEST (ecc_openssl_test_public_key_generate_derived_key_pair_and_sign);
TEST (ecc_openssl_test_generate_derived_key_pair_and_sign_and_verify);
TEST (ecc_openssl_test_generate_derived_key_pair_and_sign_and_verify_p384);
TEST (ecc_openssl_test_generate_derived_key_pair_and_sign_and_verify_p521);
TEST (ecc_openssl_test_generate_derived_key_pair_and_sign_with_public_key);
TEST (ecc_openssl_test_generate_derived_key_pair_no_keys);
TEST (ecc_openssl_test_generate_derived_key_pair_null);
TEST (ecc_openssl_test_generate_derived_key_pair_unsupported_key_length);
TEST (ecc_openssl_test_public_key_generate_key_pair);
TEST (ecc_openssl_test_private_key_generate_key_pair_and_sign);
TEST (ecc_openssl_test_public_key_generate_key_pair_and_sign);
TEST (ecc_openssl_test_generate_key_pair_and_sign_and_verify);
TEST (ecc_openssl_test_generate_key_pair_and_sign_and_verify_p384);
TEST (ecc_openssl_test_generate_key_pair_and_sign_and_verify_p521);
TEST (ecc_openssl_test_generate_key_pair_and_sign_with_public_key);
TEST (ecc_openssl_test_generate_key_pair_no_keys);
TEST (ecc_openssl_test_generate_key_pair_null);
TEST (ecc_openssl_test_generate_key_pair_unsupported_key_length);
TEST (ecc_openssl_test_sign_null);
TEST (ecc_openssl_test_sign_small_buffer);
TEST (ecc_openssl_test_verify_null);
TEST (ecc_openssl_test_verify_corrupt_signature);
TEST (ecc_openssl_test_get_signature_max_length);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_get_signature_max_length_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_get_signature_max_length_p521);
#endif
TEST (ecc_openssl_test_get_signature_max_length_derived_key);
TEST (ecc_openssl_test_get_signature_max_length_random_key);
TEST (ecc_openssl_test_get_signature_max_length_null);
TEST (ecc_openssl_test_get_shared_secret_max_length);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_get_shared_secret_max_length_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_get_shared_secret_max_length_p521);
#endif
TEST (ecc_openssl_test_get_shared_secret_max_length_derived_key);
TEST (ecc_openssl_test_get_shared_secret_max_length_random_key);
TEST (ecc_openssl_test_get_shared_secret_max_length_null);
TEST (ecc_openssl_test_compute_shared_secret);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_compute_shared_secret_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_compute_shared_secret_p521);
#endif
TEST (ecc_openssl_test_compute_shared_secret_leading_zero);
TEST (ecc_openssl_test_compute_shared_secret_derived_key);
TEST (ecc_openssl_test_compute_shared_secret_different_keys);
TEST (ecc_openssl_test_compute_shared_secret_null);
TEST (ecc_openssl_test_compute_shared_secret_small_buffer);
TEST (ecc_openssl_test_get_private_key_der);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_get_private_key_der_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_get_private_key_der_p521);
#endif
TEST (ecc_openssl_test_get_private_key_der_derived_key_pair);
TEST (ecc_openssl_test_get_private_key_der_generated_key_pair);
TEST (ecc_openssl_test_get_private_key_der_null);
TEST (ecc_openssl_test_get_private_key_der_public_key_from_private);
TEST (ecc_openssl_test_get_private_key_der_public_key);
TEST (ecc_openssl_test_get_public_key_der);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecc_openssl_test_get_public_key_der_p384);
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecc_openssl_test_get_public_key_der_p521);
#endif
TEST (ecc_openssl_test_get_public_key_der_derived_key_pair);
TEST (ecc_openssl_test_get_public_key_der_generated_key_pair);
TEST (ecc_openssl_test_get_public_key_der_null);
TEST (ecc_openssl_test_get_public_key_der_private_key);

TEST_SUITE_END;
