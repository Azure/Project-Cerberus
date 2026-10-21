// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include "openssl_check.h"
#include "platform_api.h"
#include "rsa_openssl.h"
#include "common/unused.h"

#if OPENSSL_IS_VERSION_3
#include <openssl/param_build.h>
#endif


#ifdef RSA_ENABLE_PRIVATE_KEY
int rsa_openssl_generate_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	int bits)
{
	EVP_PKEY *rsa = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int status;

	if ((engine == NULL) || (key == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_RSA, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_keygen_init (ctx);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	status = EVP_PKEY_CTX_set_rsa_keygen_bits (ctx, bits);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	status = EVP_PKEY_keygen (ctx, &rsa);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	key->context = rsa;
	status = 0;

exit:
	EVP_PKEY_CTX_free (ctx);

	return status;
}

int rsa_openssl_init_private_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
	EVP_PKEY *rsa = NULL;
	int status;

#if OPENSSL_IS_VERSION_3
	const int ERROR_NOT_RSA = 0x1e08010c;
#else
	const int ERROR_NOT_RSA = 0xd0680a8;
#endif

	if ((engine == NULL) || (key == NULL) || (der == NULL) || (length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	rsa = d2i_PrivateKey (EVP_PKEY_RSA, NULL, &der, length);
	if (rsa == NULL) {
		status = ERR_get_error ();
		if (status == ERROR_NOT_RSA) {
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

void rsa_openssl_release_key (const struct rsa_engine *engine, struct rsa_private_key *key)
{
	if (engine && key) {
		EVP_PKEY_free ((EVP_PKEY*) key->context);
		memset (key, 0, sizeof (struct rsa_private_key));
	}
}

int rsa_openssl_get_private_key_der (const struct rsa_engine *engine,
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

	status = i2d_PrivateKey ((EVP_PKEY*) key->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return status;
}

#ifndef RSA_DISABLE_DECRYPT
int rsa_openssl_decrypt (const struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	EVP_PKEY_CTX *ctx = NULL;
	uint8_t *label_copy = NULL;
	int status;

	if ((engine == NULL) || (key == NULL) || (encrypted == NULL) || (in_length == 0) ||
		(decrypted == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	if (pad_hash > HASH_TYPE_SHA256) {
		return RSA_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	if ((int) out_length < EVP_PKEY_size ((EVP_PKEY*) key->context)) {
		return RSA_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	ERR_clear_error ();

	ctx = EVP_PKEY_CTX_new ((EVP_PKEY*) key->context, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_decrypt_init (ctx);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	status = EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_OAEP_PADDING);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	if (pad_hash == HASH_TYPE_SHA256) {
		status = EVP_PKEY_CTX_set_rsa_oaep_md (ctx, EVP_sha256 ());
		if (status != 1) {
			status = -ERR_get_error ();
			goto exit;
		}
	}

	/* A copy of the label needs to be made since context takes ownership of the label memory. */
	if ((label != NULL) && (label_length != 0)) {
		label_copy = platform_malloc (label_length);
		if (label_copy == NULL) {
			status = RSA_ENGINE_NO_MEMORY;
			goto exit;
		}

		memcpy (label_copy, label, label_length);
	}

#if (OPENSSL_IS_VERSION_3 && (OPENSSL_VERSION_MINOR == 0) && (OPENSSL_VERSION_PATCH <= 7))
		/* There is a bug up to at least version 3.0.7 that reports a failure when calling
		 * EVP_PKEY_CTX_set0_rsa_oaep_label with a null label.
		 * https://github.com/openssl/openssl/issues/21288 */
	if (label_copy != NULL)
#endif
	{
		/* Always set the label, since null pointers or 0 length will clear it. */
		status = EVP_PKEY_CTX_set0_rsa_oaep_label (ctx, label_copy, label_length);
		if (status != 1) {
			if (label_copy != NULL) {
				platform_free (label_copy);
			}

			status = -ERR_get_error ();
			goto exit;
		}
	}

	status = EVP_PKEY_decrypt (ctx, decrypted, &out_length, encrypted, in_length);
	if (status == 1) {
		status = out_length;
	}
	else {
		status = -ERR_get_error ();
	}

exit:
	EVP_PKEY_CTX_free (ctx);

	return status;
}
#endif	// RSA_DISABLE_DECRYPT
#endif	// RSA_ENABLE_PRIVATE_KEY

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
int rsa_openssl_init_public_key (const struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length)
{
	EVP_PKEY *rsa = NULL;
	int status = 0;

	if ((engine == NULL) || (key == NULL) || (der == NULL) || (length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (key, 0, sizeof (*key));

	ERR_clear_error ();

	rsa = d2i_PUBKEY (NULL, &der, length);
	if (rsa == NULL) {
		return ERR_get_error ();
	}

	if (EVP_PKEY_base_id (rsa) != EVP_PKEY_RSA) {
		status = RSA_ENGINE_NOT_RSA_KEY;
		goto exit;
	}

#if OPENSSL_IS_VERSION_3
	{
		OSSL_PARAM *rsa_params = NULL;
		int i = 0;

		status = EVP_PKEY_todata (rsa, EVP_PKEY_PUBLIC_KEY, &rsa_params);
		if (status != 1) {
			status = -ERR_get_error ();
			goto exit;
		}

		while (rsa_params[i].key != NULL) {
			if (strcmp (rsa_params[i].key, "n") == 0) {
				BIGNUM *n = NULL;

				status = OSSL_PARAM_get_BN (&rsa_params[i], &n);
				if (status != 1) {
					status = -ERR_get_error ();
					goto exit_params;
				}

				key->mod_length = BN_num_bytes (n);
				if (key->mod_length > sizeof (key->modulus)) {
					status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
					BN_free (n);

					goto exit_params;
				}

				BN_bn2bin (n, key->modulus);
				BN_free (n);
			}
			else if (strcmp (rsa_params[i].key, "e") == 0) {
				BIGNUM *e = NULL;

				status = OSSL_PARAM_get_BN (&rsa_params[i], &e);
				if (status != 1) {
					status = -ERR_get_error ();
					goto exit_params;
				}

				if ((size_t) BN_num_bytes (e) > sizeof (key->exponent)) {
					status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
					BN_free (e);

					goto exit_params;
				}

				BN_bn2bin (e, (uint8_t*) &key->exponent);
				BN_free (e);
			}

			i++;
		}

		if ((key->mod_length == 0) || (key->exponent == 0)) {
			/* Missing some key data. */
			status = RSA_ENGINE_PUBLIC_KEY_FAILED;
		}
		else {
			status = 0;
		}

exit_params:
		OSSL_PARAM_free (rsa_params);
	}
#else
	{
		RSA *rsa_key = EVP_PKEY_get0_RSA (rsa);
		uint8_t exp[4];

		key->mod_length = BN_num_bytes (RSA_get0_n (rsa_key));
		if (key->mod_length > sizeof (key->modulus)) {
			status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
			goto exit;
		}

		BN_bn2bin (RSA_get0_n (rsa_key), key->modulus);

		if (BN_num_bytes (RSA_get0_e (rsa_key)) > (int) sizeof (exp)) {
			status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
			goto exit;
		}

		memset (exp, 0, sizeof (exp));
		BN_bn2bin (RSA_get0_e (rsa_key), exp);

		key->exponent = (exp[3] << 24) | (exp[2] << 16) | (exp[1] << 8) | exp[0];
	}
#endif

exit:
	EVP_PKEY_free (rsa);

	return status;
}

int rsa_openssl_get_public_key_der (const struct rsa_engine *engine,
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

	status = i2d_PUBKEY ((EVP_PKEY*) key->context, der);
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
static int rsa_openssl_load_pubkey (EVP_PKEY **rsa, const struct rsa_public_key *key)
{
	uint8_t exp[4];
	BIGNUM *n = NULL;
	BIGNUM *e = NULL;
	int status;

	ERR_clear_error ();

	n = BN_bin2bn (key->modulus, key->mod_length, NULL);
	if (n == NULL) {
		return -ERR_get_error ();
	}

	exp[0] = key->exponent >> 24;
	exp[1] = key->exponent >> 16;
	exp[2] = key->exponent >> 8;
	exp[3] = key->exponent;

	e = BN_bin2bn (exp, sizeof (exp), NULL);
	if (e == NULL) {
		status = -ERR_get_error ();
		goto err_e;
	}

#if OPENSSL_IS_VERSION_3
	{
		OSSL_PARAM_BLD *param_list = NULL;
		OSSL_PARAM *rsa_params = NULL;
		EVP_PKEY_CTX *ctx = NULL;

		param_list = OSSL_PARAM_BLD_new ();
		if (param_list == NULL) {
			status = -ERR_get_error ();
			goto err_list;
		}

		status = OSSL_PARAM_BLD_push_BN (param_list, "n", n);
		if (status != 1) {
			status = -ERR_get_error ();
			goto err_push;
		}

		status = OSSL_PARAM_BLD_push_BN (param_list, "e", e);
		if (status != 1) {
			status = -ERR_get_error ();
			goto err_push;
		}

		rsa_params = OSSL_PARAM_BLD_to_param (param_list);
		if (rsa_params == NULL) {
			status = -ERR_get_error ();
			goto err_push;
		}

		ctx = EVP_PKEY_CTX_new_from_name (NULL, "RSA", NULL);
		if (ctx == NULL) {
			status = -ERR_get_error ();
			goto err_ctx;
		}

		status = EVP_PKEY_fromdata_init (ctx);
		if (status != 1) {
			status = -ERR_get_error ();
			goto err_key;
		}

		status = EVP_PKEY_fromdata (ctx, rsa, EVP_PKEY_PUBLIC_KEY, rsa_params);
		if (status != 1) {
			status = -ERR_get_error ();
			goto err_key;
		}

		status = 0;

err_key:
		EVP_PKEY_CTX_free (ctx);
err_ctx:
		OSSL_PARAM_free (rsa_params);
err_push:
		OSSL_PARAM_BLD_free (param_list);
	}
#else
	{
		RSA *rsa_key;

		rsa_key = RSA_new ();
		if (rsa_key == NULL) {
			status = -ERR_get_error ();
			goto err_list;
		}

		status = RSA_set0_key (rsa_key, n, e, NULL);
		if (status == 0) {
			status = -ERR_get_error ();
			goto err_rsa;
		}

		*rsa = EVP_PKEY_new ();
		if (*rsa == NULL) {
			status = -ERR_get_error ();
			goto err_rsa;
		}

		status = EVP_PKEY_assign_RSA (*rsa, rsa_key);
		if (status != 1) {
			status = -ERR_get_error ();
			goto err_rsa;
		}

		/* Don't free anything that was created. */
		return 0;

err_rsa:
		RSA_free (rsa_key);
	}
#endif

err_list:
	BN_free (e);
err_e:
	BN_free (n);

	return status;
}

int rsa_openssl_sig_verify (const struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match,
	size_t match_length)
{
	EVP_PKEY *rsa = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	const EVP_MD *sig_algo;
	int status;

	if ((engine == NULL) || (key == NULL) || (signature == NULL) || (match == NULL) ||
		(sig_length == 0) || (match_length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			sig_algo = EVP_sha256 ();
			break;

		case HASH_TYPE_SHA384:
			sig_algo = EVP_sha384 ();
			break;

		case HASH_TYPE_SHA512:
			sig_algo = EVP_sha512 ();
			break;

		default:
			return RSA_ENGINE_UNSUPPORTED_SIG_TYPE;
	}

	status = rsa_openssl_load_pubkey (&rsa, key);
	if (status != 0) {
		return status;
	}

	ctx = EVP_PKEY_CTX_new (rsa, NULL);
	if (ctx == NULL) {
		status = -ERR_get_error ();
		goto err_ctx;
	}

	status = EVP_PKEY_verify_init (ctx);
	if (status != 1) {
		status = -ERR_get_error ();
		goto err_params;
	}

	status = EVP_PKEY_CTX_set_rsa_padding (ctx, RSA_PKCS1_PADDING);
	if (status != 1) {
		status = -ERR_get_error ();
		goto err_params;
	}

	status = EVP_PKEY_CTX_set_signature_md (ctx, sig_algo);
	if (status != 1) {
		status = -ERR_get_error ();
		goto err_params;
	}

	if (EVP_PKEY_verify (ctx, signature, sig_length, match, match_length) == 1) {
		status = 0;
	}
	else {
		status = RSA_ENGINE_BAD_SIGNATURE;
	}

err_params:
	EVP_PKEY_CTX_free (ctx);
err_ctx:
	EVP_PKEY_free (rsa);

	return status;
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
#ifndef RSA_DISABLE_DECRYPT
	engine->base.decrypt = rsa_openssl_decrypt;
#endif
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
void rsa_openssl_release (const struct rsa_engine_openssl *engine)
{
	UNUSED (engine);
}
