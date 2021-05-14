// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include "rsa_openssl.h"
#include "platform.h"


#ifdef RSA_ENABLE_PRIVATE_KEY
static int rsa_openssl_generate_key (struct rsa_engine *engine, struct rsa_private_key *key,
	int bits)
{
	RSA *rsa;
	BIGNUM *exponent;
	uint8_t exp[] = {0x01, 0x00, 0x01};
	int status;

	if ((engine == NULL) || (key == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	rsa = RSA_new ();
	if (rsa == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	exponent = BN_bin2bn (exp, sizeof (exp), NULL);
	if (exponent == NULL) {
		status = RSA_ENGINE_NO_MEMORY;
		goto err_free_rsa;
	}

	ERR_clear_error ();

	status = RSA_generate_key_ex (rsa, bits, exponent, NULL);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_free_bn;
	}

	key->context = rsa;

	BN_free (exponent);
	return 0;

err_free_bn:
	BN_free (exponent);
err_free_rsa:
	RSA_free (rsa);
	return status;
}

static int rsa_openssl_init_private_key (struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
	RSA *rsa;
	int status;

	if ((engine == NULL) || (key == NULL) || (der == NULL) || (length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	rsa = d2i_RSAPrivateKey (NULL, &der, length);
	if (rsa == NULL) {
		status = ERR_get_error ();
		if (status == 0xd0680a8) {
			status = RSA_ENGINE_NOT_RSA_KEY;
		}
		else {
			status = -status;
		}
		goto exit;
	}

	key->context = rsa;
	status = 0;

exit:
	return status;
}

static void rsa_openssl_release_key (struct rsa_engine *engine, struct rsa_private_key *key)
{
	if (engine && key) {
		RSA_free ((RSA*) key->context);
		memset (key, 0, sizeof (struct rsa_private_key));
	}
}

static int rsa_openssl_get_private_key_der (struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	int status;

	if (der == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = i2d_RSAPrivateKey ((RSA*) key->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return status;
}

static int rsa_openssl_decrypt (struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	int status;
	uint8_t *padded;
	const EVP_MD *md = NULL;

	if ((engine == NULL) || (key == NULL) || (encrypted == NULL) || (in_length == 0) ||
		(decrypted == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	if (pad_hash > HASH_TYPE_SHA256) {
		return RSA_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	if ((int) out_length < RSA_size ((RSA*) key->context)) {
		return RSA_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	padded = platform_malloc (RSA_size ((RSA*) key->context));
	if (padded == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	ERR_clear_error ();

	status = RSA_private_decrypt (in_length, encrypted, padded, (RSA*) key->context,
		RSA_NO_PADDING);
	if (status == -1) {
		status = -ERR_get_error ();
		goto exit;
	}

	if (pad_hash == HASH_TYPE_SHA256) {
		md = EVP_sha256 ();
	}

	status = RSA_padding_check_PKCS1_OAEP_mgf1 (decrypted, out_length, padded, status,
		RSA_size ((RSA*) key->context), label, label_length, md, NULL);
	if (status == -1) {
		status = -ERR_get_error ();
	}

exit:
	platform_free (padded);
	return status;
}
#endif

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
static int rsa_openssl_init_public_key (struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length)
{
	RSA *rsa;
	uint8_t exp[4];
	int status = 0;

	if ((engine == NULL) || (key == NULL) || (der == NULL) || (length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	rsa = d2i_RSA_PUBKEY (NULL, &der, length);
	if (rsa == NULL) {
		status = ERR_get_error ();

		if ((status == 0xd0680a8) || (status == 0x607907f)) {
			return RSA_ENGINE_NOT_RSA_KEY;
		}
		else {
			return -status;
		}
	}

	key->mod_length = BN_num_bytes (RSA_get0_n (rsa));
	if (key->mod_length > sizeof (key->modulus)) {
		status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
		goto exit;
	}

	BN_bn2bin (RSA_get0_n (rsa), key->modulus);

	if (BN_num_bytes (RSA_get0_e (rsa)) > (int) sizeof (exp)) {
		status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
		goto exit;
	}

	memset (exp, 0, sizeof (exp));
	BN_bn2bin (RSA_get0_e (rsa), exp);

	key->exponent = (exp[3] << 24) | (exp[2] << 16) | (exp[1] << 8) | exp[0];

exit:
	RSA_free (rsa);

	return status;
}

static int rsa_openssl_get_public_key_der (struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length)
{
	int status;

	if (der == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = i2d_RSA_PUBKEY ((RSA*) key->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return status;
}
#endif

/**
 * Allocate an RSA context and load it with a public key.
 *
 * @param rsa The pointer for the new RSA context.
 * @param key The public key to load.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int rsa_openssl_load_pubkey (RSA **rsa, const struct rsa_public_key *key)
{
	uint8_t exp[4];
	BIGNUM *n;
	BIGNUM *e;
	int status;

	*rsa = RSA_new ();
	if (*rsa == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	exp[0] = key->exponent >> 24;
	exp[1] = key->exponent >> 16;
	exp[2] = key->exponent >> 8;
	exp[3] = key->exponent;

	n = BN_bin2bn (key->modulus, key->mod_length, NULL);
	e = BN_bin2bn (exp, sizeof (exp), NULL);

	if ((n == NULL) || (e == NULL)) {
		status = RSA_ENGINE_NO_MEMORY;
		goto err_key;
	}

	status = RSA_set0_key (*rsa, n, e, NULL);
	if (status == 0) {
		status = -ERR_get_error ();
		goto err_key;
	}

	return 0;

err_key:
	BN_free (n);
	BN_free (e);
	RSA_free (*rsa);
	return status;
}

static int rsa_openssl_sig_verify (struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, const uint8_t *match, size_t match_length)
{
	RSA *rsa;
	int status;

	if ((engine == NULL) || (key == NULL) || (signature == NULL) || (match == NULL) ||
		(sig_length == 0) || (match_length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	status = rsa_openssl_load_pubkey (&rsa, key);
	if (status != 0) {
		return status;
	}

	status = RSA_verify (NID_sha256, match, match_length, signature, sig_length, rsa);

	RSA_free (rsa);
	return (status == 1) ? 0 : RSA_ENGINE_BAD_SIGNATURE;
}

/**
 * Initialize an openssl RSA engine.
 *
 * @param engine The RSA engine to initialize.
 *
 * @return 0 if the RSA engine was successfully initialize or an error code.
 */
int rsa_openssl_init (struct rsa_engine_openssl *engine)
{
	if (engine == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rsa_engine_openssl));

#ifdef RSA_ENABLE_PRIVATE_KEY
	engine->base.generate_key = rsa_openssl_generate_key;
	engine->base.init_private_key = rsa_openssl_init_private_key;
	engine->base.release_key = rsa_openssl_release_key;
	engine->base.get_private_key_der = rsa_openssl_get_private_key_der;
	engine->base.decrypt = rsa_openssl_decrypt;
#endif
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	engine->base.init_public_key = rsa_openssl_init_public_key;
	engine->base.get_public_key_der = rsa_openssl_get_public_key_der;
#endif
	engine->base.sig_verify = rsa_openssl_sig_verify;

	return 0;
}

/**
 * Release the resources used by an openssl RSA engine.
 *
 * @param engine The RSA engine to release.
 */
void rsa_openssl_release (struct rsa_engine_openssl *engine)
{

}
