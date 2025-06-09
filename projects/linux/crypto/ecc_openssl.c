// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ecc_openssl.h"
#include "openssl_check.h"
#include "asn1/ecc_der_util.h"
#include "common/unused.h"
#include "crypto/hash.h"


/**
 * Initialize a public key instance from a private key.
 *
 * @param key The private key instance to covert to a public key.
 * @param dup Flag indicating if a new key instance should be created for the public key.
 *
 * @return The public key instance or null if there was an error.
 */
static EVP_PKEY* ecc_openssl_convert_private_to_public (EVP_PKEY *key, bool dup)
{
	EVP_PKEY *ec_pub = NULL;
	uint8_t *pub_key = NULL;
	const uint8_t *parse_key;
	int key_length;

	/* Create a key context that only contains the public key by encoding just the public key from
	 * the parsed key pair then decoding that into a new key context. */
	key_length = i2d_PUBKEY (key, &pub_key);
	if (key_length < 0) {
		return NULL;
	}

	parse_key = pub_key;
	ec_pub = d2i_PUBKEY (NULL, &parse_key, key_length);

	if (ec_pub && !dup) {
		EVP_PKEY_free (key);
	}

	OPENSSL_free (pub_key);

	return ec_pub;
}

int ecc_openssl_init_key_pair (const struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	EVP_PKEY *ec_priv = NULL;
	int status;

#if OPENSSL_IS_VERSION_3
	const int ERROR_NOT_EC = 0x1e08010c;
#else
	const int ERROR_NOT_EC = 0xd0680a8;
#endif

	if ((engine == NULL) || (key == NULL) || (key_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	ERR_clear_error ();

	ec_priv = d2i_PrivateKey (EVP_PKEY_EC, NULL, &key, key_length);
	if (ec_priv == NULL) {
		status = ERR_get_error ();
		if (status == ERROR_NOT_EC) {
			status = ECC_ENGINE_NOT_EC_KEY;
		}
#if (OPENSSL_IS_VERSION_3 && (OPENSSL_VERSION_MINOR == 0) && (OPENSSL_VERSION_PATCH <= 2))
		else if (status == 0x68000a8) {
			status = ECC_ENGINE_NOT_PRIVATE_KEY;
		}
#endif
		else {
			status = -status;
		}

		goto err_load;
	}

	if (pub_key) {
		pub_key->context = ecc_openssl_convert_private_to_public (ec_priv, (priv_key));
		if (pub_key->context == NULL) {
			status = -ERR_get_error ();
			goto err_pubkey;
		}
	}

	if (priv_key) {
		priv_key->context = ec_priv;
	}

	return 0;

err_pubkey:
	EVP_PKEY_free (ec_priv);

err_load:

	return status;
}

int ecc_openssl_init_public_key (const struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key)
{
	EVP_PKEY *ec_pub = NULL;
	EVP_PKEY_CTX *ctx;
	int status;

	if ((engine == NULL) || (key == NULL) || (key_length == 0) || (pub_key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (pub_key, 0, sizeof (struct ecc_public_key));

	ERR_clear_error ();

	ec_pub = d2i_PUBKEY (NULL, &key, key_length);
	if (ec_pub == NULL) {
		return -ERR_get_error ();
	}

	if (EVP_PKEY_base_id (ec_pub) != EVP_PKEY_EC) {
		EVP_PKEY_free (ec_pub);

		return ECC_ENGINE_NOT_EC_KEY;
	}

	ctx = EVP_PKEY_CTX_new (ec_pub, NULL);
	if (ctx == NULL) {
		EVP_PKEY_free (ec_pub);

		return -ERR_get_error ();
	}

	status = EVP_PKEY_public_check (ctx);
	EVP_PKEY_CTX_free (ctx);
	if (status != 1) {
		EVP_PKEY_free (ec_pub);

		return ECC_ENGINE_INVALID_PUBLIC_KEY;
	}

	pub_key->context = ec_pub;
	status = 0;

	return status;
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
int ecc_openssl_generate_derived_key_pair (const struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	uint8_t der[ECC_DER_MAX_PRIVATE_NO_PUB_LENGTH];
	int der_length;

	if ((engine == NULL) || (priv == NULL) || (key_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	/* It seems possible to use EVP_PKEY_fromdata (introduced in version 3.0) to generate a specific
	 * private key context, but that path requires the caller to also have the public key.  Encoding
	 * the private key as DER and parsing it causes OpenSSL to calculate the public key on it's own,
	 * which makes this code much simpler.  This approach also works equally well for any version of
	 * OpenSSL. */
	der_length = ecc_der_encode_private_key (priv, NULL, NULL, key_length, der, sizeof (der));
	if (ROT_IS_ERROR (der_length)) {
		return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}

	return ecc_openssl_init_key_pair (engine, der, der_length, priv_key, pub_key);
}

int ecc_openssl_generate_key_pair (const struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	EVP_PKEY *ec_priv = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	ERR_clear_error ();

	ctx = EVP_PKEY_CTX_new_id (EVP_PKEY_EC, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_keygen_init (ctx);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			status = EVP_PKEY_CTX_set_ec_paramgen_curve_nid (ctx, NID_X9_62_prime256v1);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			status = EVP_PKEY_CTX_set_ec_paramgen_curve_nid (ctx, NID_secp384r1);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			status = EVP_PKEY_CTX_set_ec_paramgen_curve_nid (ctx, NID_secp521r1);
			break;
#endif
#endif

		default:
			status = ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
			goto exit;
	}
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	status = EVP_PKEY_keygen (ctx, &ec_priv);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	if (pub_key) {
		pub_key->context = ecc_openssl_convert_private_to_public (ec_priv, (priv_key));
		if (pub_key->context == NULL) {
			status = -ERR_get_error ();
			EVP_PKEY_free (ec_priv);

			return status;
		}
	}

	if (priv_key) {
		priv_key->context = ec_priv;
	}

	status = 0;

exit:
	EVP_PKEY_CTX_free (ctx);

	return status;
}
#endif

void ecc_openssl_release_key_pair (const struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	UNUSED (engine);

	if (priv_key) {
		EVP_PKEY_free ((EVP_PKEY*) priv_key->context);
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}

	if (pub_key) {
		EVP_PKEY_free ((EVP_PKEY*) pub_key->context);
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}
}

int ecc_openssl_get_signature_max_length (const struct ecc_engine *engine,
	const struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	return EVP_PKEY_size ((EVP_PKEY*) key->context);
}

/**
 * Check an EC key context to see if contains a private key.
 *
 * @param key The key to check.
 *
 * @return 1 if it contains a private key, 0 if not, or an error code.
 */
static int ecc_openssl_has_private_key (EVP_PKEY *key)
{
#if OPENSSL_IS_VERSION_3
	EVP_PKEY_CTX *ctx = NULL;
	int status;

	ctx = EVP_PKEY_CTX_new (key, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_private_check (ctx);
	EVP_PKEY_CTX_free (ctx);
	if (status != 1) {
		return 0;
	}

	return 1;
#else
	EC_KEY *ec = EVP_PKEY_get0_EC_KEY (key);

	return (EC_KEY_get0_private_key (ec) != NULL);
#endif
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
int ecc_openssl_get_private_key_der (const struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length)
{
	int status;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = ecc_openssl_has_private_key ((EVP_PKEY*) key->context);
	if (status != 1) {
		if (status == 0) {
			return ECC_ENGINE_NOT_PRIVATE_KEY;
		}
		else {
			return status;
		}
	}

#if OPENSSL_IS_VERSION_3
	status = EVP_PKEY_set_int_param ((EVP_PKEY*) key->context, "include-public", 1);
	if (status != 1) {
		return -ERR_get_error ();
	}
#else
	{
		EC_KEY *ec = EVP_PKEY_get0_EC_KEY ((EVP_PKEY*) key->context);

		status = EC_KEY_get_enc_flags (ec);
		EC_KEY_set_enc_flags (ec, (status & ~EC_PKEY_NO_PUBKEY));
	}
#endif

	status = i2d_PrivateKey ((EVP_PKEY*) key->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return 0;
}

int ecc_openssl_get_public_key_der (const struct ecc_engine *engine,
	const struct ecc_public_key *key, uint8_t **der, size_t *length)
{
	int status;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = ecc_openssl_has_private_key ((EVP_PKEY*) key->context);
	if (status != 0) {
		if (status == 1) {
			return ECC_ENGINE_NOT_PUBLIC_KEY;
		}
		else {
			return status;
		}
	}

	status = i2d_PUBKEY ((EVP_PKEY*) key->context, der);
	if (status >= 0) {
		*length = status;
		status = 0;
	}
	else {
		status = -ERR_get_error ();
	}

	return 0;
}
#endif

int ecc_openssl_sign (const struct ecc_engine *engine, const struct ecc_private_key *key,
	const uint8_t *digest, size_t length, const struct rng_engine *rng, uint8_t *signature,
	size_t sig_length)
{
	EVP_PKEY_CTX *ctx = NULL;
	const EVP_MD *sig_algo;
	size_t out_len = sig_length;
	int status;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if ((int) sig_length < ecc_openssl_get_signature_max_length (engine, key)) {
		return ECC_ENGINE_SIG_BUFFER_TOO_SMALL;
	}

	switch (length) {
		case SHA256_HASH_LENGTH:
			sig_algo = EVP_sha256 ();
			break;

		case SHA384_HASH_LENGTH:
			sig_algo = EVP_sha384 ();
			break;

		case SHA512_HASH_LENGTH:
			sig_algo = EVP_sha512 ();
			break;

		default:
			return ECC_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	ERR_clear_error ();

	ctx = EVP_PKEY_CTX_new ((EVP_PKEY*) key->context, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_sign_init (ctx);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	status = EVP_PKEY_CTX_set_signature_md (ctx, sig_algo);
	if (status != 1) {
		status = -ERR_get_error ();
		goto exit;
	}

	if (rng == NULL) {
		status = EVP_PKEY_sign (ctx, signature, &out_len, digest, length);
		if (status != 1) {
			status = -ERR_get_error ();
		}
	}
	else {
		/* TODO:  It's not clear how to leverage the EVP API to control the random number generation
		 * for use in the signing operation.  This implementation isn't used in any scenario where
		 * it's necessary to use an external RNG.  Defer this work until it becomes more
		 * relevant. */
		status = ECC_ENGINE_UNSUPPORTED_OPERATION;
	}

exit:
	EVP_PKEY_CTX_free (ctx);

	return (status == 1) ? (int) out_len : status;
}

int ecc_openssl_verify (const struct ecc_engine *engine, const struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	EVP_PKEY_CTX *ctx = NULL;
	const EVP_MD *sig_algo;
	int status;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	switch (length) {
		case SHA256_HASH_LENGTH:
			sig_algo = EVP_sha256 ();
			break;

		case SHA384_HASH_LENGTH:
			sig_algo = EVP_sha384 ();
			break;

		case SHA512_HASH_LENGTH:
			sig_algo = EVP_sha512 ();
			break;

		default:
			return ECC_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	ERR_clear_error ();

	ctx = EVP_PKEY_CTX_new ((EVP_PKEY*) key->context, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_verify_init (ctx);
	if (status != 1) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_CTX_set_signature_md (ctx, sig_algo);
	if (status != 1) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_verify (ctx, signature,
		ecc_der_get_ecdsa_signature_length (signature, sig_length), digest, length);
	EVP_PKEY_CTX_free (ctx);

	return (status == 1) ? 0 : ECC_ENGINE_BAD_SIGNATURE;
}

#ifdef ECC_ENABLE_ECDH
int ecc_openssl_get_shared_secret_max_length (const struct ecc_engine *engine,
	const struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	return (EVP_PKEY_bits ((EVP_PKEY*) key->context) + 7) / 8;
}

int ecc_openssl_compute_shared_secret (const struct ecc_engine *engine,
	const struct ecc_private_key *priv_key, const struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length)
{
	EVP_PKEY_CTX *ctx = NULL;
	int status;

	if ((engine == NULL) || (priv_key == NULL) || (pub_key == NULL) || (secret == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if ((int) length < ecc_openssl_get_shared_secret_max_length (engine, priv_key)) {
		return ECC_ENGINE_SECRET_BUFFER_TOO_SMALL;
	}

	ERR_clear_error ();

	ctx = EVP_PKEY_CTX_new ((EVP_PKEY*) priv_key->context, NULL);
	if (ctx == NULL) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_derive_init (ctx);
	if (status != 1) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_derive_set_peer (ctx, (EVP_PKEY*) pub_key->context);
	if (status != 1) {
		return -ERR_get_error ();
	}

	status = EVP_PKEY_derive (ctx, secret, &length);
	EVP_PKEY_CTX_free (ctx);

	return (status == 1) ? length : -ERR_get_error ();
}
#endif

/**
 * Initialize an instance for running ECC operations using OpenSSL.
 *
 * @param engine The ECC engine to initialize.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int ecc_openssl_init (struct ecc_engine_openssl *engine)
{
	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct ecc_engine_openssl));

	engine->base.init_key_pair = ecc_openssl_init_key_pair;
	engine->base.init_public_key = ecc_openssl_init_public_key;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.generate_derived_key_pair = ecc_openssl_generate_derived_key_pair;
	engine->base.generate_key_pair = ecc_openssl_generate_key_pair;
#endif
	engine->base.release_key_pair = ecc_openssl_release_key_pair;
	engine->base.get_signature_max_length = ecc_openssl_get_signature_max_length;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.get_private_key_der = ecc_openssl_get_private_key_der;
	engine->base.get_public_key_der = ecc_openssl_get_public_key_der;
#endif
	engine->base.sign = ecc_openssl_sign;
	engine->base.verify = ecc_openssl_verify;
#ifdef ECC_ENABLE_ECDH
	engine->base.get_shared_secret_max_length = ecc_openssl_get_shared_secret_max_length;
	engine->base.compute_shared_secret = ecc_openssl_compute_shared_secret;
#endif

	return 0;
}

/**
 * Release an OpenSSL ECC engine.
 *
 * @param engine The ECC engine to release.
 */
void ecc_openssl_release (const struct ecc_engine_openssl *engine)
{
	UNUSED (engine);
}
