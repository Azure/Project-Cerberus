// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "crypto/rsa_openssl.h"
#include "crypto/rsa_openssl_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"


TEST_SUITE_LABEL ("rsa_openssl");


/**
 * Encrypt a message with an RSA public key.
 *
 * @param test The test framework.
 * @param engine The RSA engine being used.
 * @param key The RSA key pair to use for the encryption.
 * @param message A string to encrypt.
 * @param out The buffer for the encrypted output.  This must be at least the size of the RSA key.
 * @param out_len Input the size of the output buffer, output the length of the data.
 */
static void rsa_openssl_testing_encrypt_data (CuTest *test, struct rsa_engine_openssl *engine,
	struct rsa_private_key *key, const char *message, uint8_t *out, size_t *out_len)
{
	EVP_PKEY_CTX *ctx;
	int status;

	ctx = EVP_PKEY_CTX_new ((EVP_PKEY*) key->context, NULL);
	CuAssertPtrNotNull (test, ctx);

	status = EVP_PKEY_encrypt_init (ctx);
	CuAssertIntEquals (test, 1, status);

	status = EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_OAEP_PADDING);
	CuAssertIntEquals (test, 1, status);

	status = EVP_PKEY_encrypt (ctx, out, out_len, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 1, status);

	EVP_PKEY_CTX_free (ctx);
}

/**
 * Sign a set of data with an RSA private key.
 *
 * @param data The data to sign.
 * @param length The length of the data.
 * @param key The private key to use to sign the data.
 * @param key_length The length of the key.
 * @param signature Output buffer for the signature.
 * @param sig_length The length of the signature buffer.
 *
 * @return 0 if the signature was successfully generated or an error code.
 */
int rsa_openssl_testing_sign_data (const uint8_t *data, size_t length, const uint8_t *key,
	size_t key_length, uint8_t *signature, size_t sig_length)
{
	EVP_PKEY *rsa;
	EVP_PKEY_CTX *ctx;
	uint8_t hash[SHA256_HASH_LENGTH];
	int status;

	rsa = d2i_PrivateKey (EVP_PKEY_RSA, NULL, &key, key_length);
	if (rsa == NULL) {
		return -ERR_get_error ();
	}

	ctx = EVP_PKEY_CTX_new (rsa, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING);
	if (status == 1) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_CTX_set_signature_md (ctx, EVP_sha256 ());
	if (status != 1) {
		return -ERR_get_error ();
	}

	SHA256 (data, length, hash);

	status = EVP_PKEY_sign (ctx, signature, &sig_length, hash, sizeof (hash));
	EVP_PKEY_CTX_free (ctx);
	if (status != 1) {
		return -ERR_get_error ();
	}

	EVP_PKEY_free (rsa);

	return 0;
}


/*******************
 * Test cases
 *******************/

static void rsa_openssl_test_init (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_key);
	CuAssertPtrNotNull (test, engine.base.init_private_key);
	CuAssertPtrNotNull (test, engine.base.init_public_key);
	CuAssertPtrNotNull (test, engine.base.release_key);
	CuAssertPtrNotNull (test, engine.base.get_private_key_der);
	CuAssertPtrNotNull (test, engine.base.get_public_key_der);
	CuAssertPtrNotNull (test, engine.base.decrypt);
	CuAssertPtrNotNull (test, engine.base.sig_verify);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = rsa_openssl_init (NULL);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
}

static void rsa_openssl_test_static_init (CuTest *test)
{
	struct rsa_engine_openssl engine = rsa_openssl_static_init;

	TEST_START;

	CuAssertPtrNotNull (test, engine.base.generate_key);
	CuAssertPtrNotNull (test, engine.base.init_private_key);
	CuAssertPtrNotNull (test, engine.base.init_public_key);
	CuAssertPtrNotNull (test, engine.base.release_key);
	CuAssertPtrNotNull (test, engine.base.get_private_key_der);
	CuAssertPtrNotNull (test, engine.base.get_public_key_der);
	CuAssertPtrNotNull (test, engine.base.decrypt);
	CuAssertPtrNotNull (test, engine.base.sig_verify);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_release_null (CuTest *test)
{
	TEST_START;

	rsa_openssl_release (NULL);
}

static void rsa_openssl_test_sig_verify (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_sha384 (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SHA384_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA384, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_sha512 (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SHA512_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA512, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_static_init (CuTest *test)
{
	struct rsa_engine_openssl engine = rsa_openssl_static_init;
	int status;

	TEST_START;

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (NULL, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,	RSA_ENCRYPT_LEN,
		HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sig_verify (&engine.base, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, NULL, RSA_ENCRYPT_LEN,
		HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,	0,
		HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA256, NULL, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA256, SIG_HASH_TEST, 0);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_unsupported_sig_type (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA1, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_UNSUPPORTED_SIG_TYPE, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, (enum hash_type) 10, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_UNSUPPORTED_SIG_TYPE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_no_match (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_NOPE,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_no_match_sha384 (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SHA384_SIGNATURE_NOPE,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA384, SHA384_TEST_HASH, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_no_match_sha512 (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SHA512_SIGNATURE_NOPE,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA512, SHA512_TEST_HASH, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_wrong_length (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN - 1, HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_bad_signature (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_ENCRYPT_BAD,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA256, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_sig_verify_bad_signature_wrong_hash (CuTest *test)
{
	struct rsa_engine_openssl engine;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_BAD,
		RSA_ENCRYPT_LEN, HASH_TYPE_SHA384, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_private_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key.context);

	status = engine.base.get_private_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (RSA_PRIVKEY_DER, der, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	status = engine.base.get_public_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PUBKEY_DER_LEN, length);

	status = testing_validate_array (RSA_PUBKEY_DER, der, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_private_key_static_init (CuTest *test)
{
	struct rsa_engine_openssl engine = rsa_openssl_static_init;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key.context);

	status = engine.base.get_private_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (RSA_PRIVKEY_DER, der, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);

	status = engine.base.get_public_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PUBKEY_DER_LEN, length);

	status = testing_validate_array (RSA_PUBKEY_DER, der, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	platform_free (der);
	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_private_key_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (NULL, &key, RSA_PRIVKEY_DER,	RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_private_key (&engine.base, NULL, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_private_key (&engine.base, &key, NULL, RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,	0);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_private_key_with_public_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertTrue (test, (status != 0));

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_private_key_with_ecc_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_NOT_RSA_KEY, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_public_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PUBLIC_KEY.mod_length, key.mod_length);
	CuAssertIntEquals (test, RSA_PUBLIC_KEY.exponent, key.exponent);

	status = testing_validate_array (RSA_PUBLIC_KEY.modulus, key.modulus,
		RSA_PUBLIC_KEY.mod_length);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}

#if (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
static void rsa_openssl_test_init_public_key_4k (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA4K_PUBKEY_DER,
		RSA4K_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA4K_PUBLIC_KEY.mod_length, key.mod_length);
	CuAssertIntEquals (test, RSA4K_PUBLIC_KEY.exponent, key.exponent);

	status = testing_validate_array (RSA4K_PUBLIC_KEY.modulus, key.modulus,
		RSA4K_PUBLIC_KEY.mod_length);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}
#endif

static void rsa_openssl_test_init_public_key_static_init (CuTest *test)
{
	struct rsa_engine_openssl engine = rsa_openssl_static_init;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_PUBLIC_KEY.mod_length, key.mod_length);
	CuAssertIntEquals (test, RSA_PUBLIC_KEY.exponent, key.exponent);

	status = testing_validate_array (RSA_PUBLIC_KEY.modulus, key.modulus,
		RSA_PUBLIC_KEY.mod_length);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_public_key_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (NULL, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, NULL, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, &key, NULL, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, 0);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_public_key_with_private_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA_PRIVKEY_DER, RSA_PRIVKEY_DER_LEN);
	CuAssertTrue (test, (status != 0));

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_public_key_with_ecc_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_NOT_RSA_KEY, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_init_public_key_too_large (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA5K_PUBKEY_DER,
		RSA5K_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_get_private_key_der_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (NULL, &key, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_private_key_der (&engine.base, &key, NULL, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_private_key_der (&engine.base, &key, &der, NULL);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_get_public_key_der_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (NULL, &key, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (&engine.base, NULL, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	status = engine.base.get_public_key_der (&engine.base, &key, NULL, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	der = (uint8_t*) &status;
	status = engine.base.get_public_key_der (&engine.base, &key, &der, NULL);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, der);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_release_key_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key (NULL, &key);
	engine.base.release_key (&engine.base, NULL);
	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_generate_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (&engine.base, &key, 2048);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key.context);

	status = engine.base.get_private_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		((length >= (RSA_PRIVKEY_DER_LEN - 3)) && (length <= (RSA_PRIVKEY_DER_LEN + 3))));

	platform_free (der);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_generate_key_static_init (CuTest *test)
{
	struct rsa_engine_openssl engine = rsa_openssl_static_init;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = engine.base.generate_key (&engine.base, &key, 2048);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key.context);

	status = engine.base.get_private_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		((length >= (RSA_PRIVKEY_DER_LEN - 3)) && (length <= (RSA_PRIVKEY_DER_LEN + 3))));

	platform_free (der);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_generate_key_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (NULL, &key, 2048);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_key (&engine.base, NULL, 2048);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_with_label (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_LABEL_ENCRYPT_TEST, RSA_ENCRYPT_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, (uint8_t*) message,
		sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_sha256 (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_SHA256_ENCRYPT_TEST, RSA_ENCRYPT_LEN,
		NULL, 0, HASH_TYPE_SHA256, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_sha256_with_label (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_SHA256_LABEL_ENCRYPT_TEST,
		RSA_ENCRYPT_LEN, (uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA256,
		(uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_random_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	const int bits = 2048;
	uint8_t out[bits / 8];
	size_t length = sizeof (out);
	char message[sizeof (out)];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (&engine.base, &key, bits);
	CuAssertIntEquals (test, 0, status);

	rsa_openssl_testing_encrypt_data (test, &engine, &key, expected, out, &length);

	status = engine.base.decrypt (&engine.base, &key, out, length, NULL, 0, HASH_TYPE_SHA1,
		(uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_differest_hashes (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	const char *expected2 = "Test2";
	const char *expected3 = "Bad";
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	status = engine.base.decrypt (&engine.base, &key, RSA_SHA256_ENCRYPT_TEST2, RSA_ENCRYPT_LEN,
		NULL, 0, HASH_TYPE_SHA256, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected2), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected2, message);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected3), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected3, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_static_init (CuTest *test)
{
	struct rsa_engine_openssl engine = rsa_openssl_static_init;
	struct rsa_private_key key;
	int status;
	const char *expected = "Test";
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, strlen (expected), status);

	message[status] = '\0';
	CuAssertStrEquals (test, expected, message);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_null (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (NULL, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt (&engine.base, NULL, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt (&engine.base, &key, NULL, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, 0, NULL, 0,	HASH_TYPE_SHA1,
		(uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, NULL, sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_unknown_hash_type (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		(enum hash_type) 10, (uint8_t*) message, sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_UNSUPPORTED_HASH_TYPE, status);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_small_buffer (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, strlen ("Test") - 1);
	CuAssertIntEquals (test, RSA_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_wrong_key (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (&engine.base, &key, 2048);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_with_wrong_label (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_LABEL_ENCRYPT_TEST, RSA_ENCRYPT_LEN,
		(uint8_t*) "Bad", 3, HASH_TYPE_SHA1, (uint8_t*) message, sizeof (message));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}

static void rsa_openssl_test_decrypt_wrong_hash (CuTest *test)
{
	struct rsa_engine_openssl engine;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, NULL, 0,
		HASH_TYPE_SHA256, (uint8_t*) message, sizeof (message));
	CuAssertTrue (test, (status < 0));

	engine.base.release_key (&engine.base, &key);

	rsa_openssl_release (&engine);
}


TEST_SUITE_START (rsa_openssl);

TEST (rsa_openssl_test_init);
TEST (rsa_openssl_test_init_null);
TEST (rsa_openssl_test_static_init);
TEST (rsa_openssl_test_release_null);
TEST (rsa_openssl_test_sig_verify);
TEST (rsa_openssl_test_sig_verify_sha384);
TEST (rsa_openssl_test_sig_verify_sha512);
TEST (rsa_openssl_test_sig_verify_static_init);
TEST (rsa_openssl_test_sig_verify_null);
TEST (rsa_openssl_test_sig_verify_unsupported_sig_type);
TEST (rsa_openssl_test_sig_verify_no_match);
TEST (rsa_openssl_test_sig_verify_no_match_sha384);
TEST (rsa_openssl_test_sig_verify_no_match_sha512);
TEST (rsa_openssl_test_sig_verify_wrong_length);
TEST (rsa_openssl_test_sig_verify_bad_signature);
TEST (rsa_openssl_test_sig_verify_bad_signature_wrong_hash);
TEST (rsa_openssl_test_init_private_key);
TEST (rsa_openssl_test_init_private_key_static_init);
TEST (rsa_openssl_test_init_private_key_null);
TEST (rsa_openssl_test_init_private_key_with_public_key);
TEST (rsa_openssl_test_init_private_key_with_ecc_key);
TEST (rsa_openssl_test_init_public_key);
#if (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
TEST (rsa_openssl_test_init_public_key_4k);
#endif
TEST (rsa_openssl_test_init_public_key_static_init);
TEST (rsa_openssl_test_init_public_key_null);
TEST (rsa_openssl_test_init_public_key_with_private_key);
TEST (rsa_openssl_test_init_public_key_with_ecc_key);
TEST (rsa_openssl_test_init_public_key_too_large);
TEST (rsa_openssl_test_get_private_key_der_null);
TEST (rsa_openssl_test_get_public_key_der_null);
TEST (rsa_openssl_test_release_key_null);
TEST (rsa_openssl_test_generate_key);
TEST (rsa_openssl_test_generate_key_static_init);
TEST (rsa_openssl_test_generate_key_null);
TEST (rsa_openssl_test_decrypt);
TEST (rsa_openssl_test_decrypt_with_label);
TEST (rsa_openssl_test_decrypt_sha256);
TEST (rsa_openssl_test_decrypt_sha256_with_label);
TEST (rsa_openssl_test_decrypt_random_key);
TEST (rsa_openssl_test_decrypt_differest_hashes);
TEST (rsa_openssl_test_decrypt_static_init);
TEST (rsa_openssl_test_decrypt_null);
TEST (rsa_openssl_test_decrypt_unknown_hash_type);
TEST (rsa_openssl_test_decrypt_small_buffer);
TEST (rsa_openssl_test_decrypt_wrong_key);
TEST (rsa_openssl_test_decrypt_with_wrong_label);
TEST (rsa_openssl_test_decrypt_wrong_hash);

TEST_SUITE_END;
