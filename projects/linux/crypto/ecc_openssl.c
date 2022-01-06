// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>
#include "crypto/ecc_openssl.h"
#include "common/unused.h"


/**
 * Initialize a public key instance from a private key.
 *
 * @param key The private key instance to covert to a public key.
 * @param dup Flag indicating if a new key instance should be created for the public key.
 *
 * @return The public key instance or null if there was an error.
 */
static EC_KEY* ecc_openssl_convert_private_to_public (EC_KEY *key, bool dup)
{
	EC_KEY *pub = key;

	if (dup) {
		pub = EC_KEY_dup (pub);
	}

	if (pub) {
		EC_KEY_set_private_key (pub, NULL);
	}

	return pub;
}

static int ecc_openssl_init_key_pair (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	EC_KEY *ec;
	int status;

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

	ec = d2i_ECPrivateKey (NULL, &key, key_length);
	if (ec == NULL) {
		status = ERR_get_error ();
		if (status == 0xd0680a8) {
			status = ECC_ENGINE_NOT_EC_KEY;
		}
		else {
			status = -status;
		}
		goto err_load;
	}

	if (pub_key) {
		pub_key->context = ecc_openssl_convert_private_to_public (ec, (priv_key));
		if (pub_key->context == NULL) {
			status = -ERR_get_error ();
			goto err_pubkey;
		}
	}

	if (priv_key) {
		priv_key->context = ec;
	}

	return 0;

err_pubkey:
	EC_KEY_free (ec);
err_load:
	return status;
}

static int ecc_openssl_init_public_key (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key)
{
	EC_KEY *ec;
	int status;

	if ((engine == NULL) || (key == NULL) || (key_length == 0) || (pub_key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (pub_key, 0, sizeof (struct ecc_public_key));

	ERR_clear_error ();

	ec = d2i_EC_PUBKEY (NULL, &key, key_length);
	if (ec == NULL) {
		status = ERR_get_error ();
		if (status == 0x608308e) {
			status = ECC_ENGINE_NOT_EC_KEY;
		}
		else {
			status = -status;
		}
		goto exit;
	}

	pub_key->context = ec;
	status = 0;

exit:
	return status;
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_openssl_generate_derived_key_pair (struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	EC_KEY *ec;
	const EC_GROUP *curve;
	BIGNUM *priv_val;
	EC_POINT *pub_val;
	BN_CTX *pub_ctx;
	int status;

	if ((engine == NULL) || (priv == NULL) || (key_length == 0)) {
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

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			ec = EC_KEY_new_by_curve_name (NID_secp384r1);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			ec = EC_KEY_new_by_curve_name (NID_secp521r1);
			break;
#endif
#endif

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}
	if (ec == NULL) {
		return -ERR_get_error ();
	}

	EC_KEY_set_asn1_flag (ec, OPENSSL_EC_NAMED_CURVE);

	curve = EC_KEY_get0_group (ec);
	if (curve == NULL) {
		status = ERR_get_error ();
		goto err_priv;
	}

	priv_val = BN_bin2bn (priv, key_length, NULL);
	if (priv_val == NULL) {
		status = ERR_get_error ();
		goto err_priv;
	}

	pub_ctx = BN_CTX_new ();
	if (pub_ctx == NULL) {
		status = ERR_get_error ();
		goto err_ctx;
	}

	pub_val = EC_POINT_new (curve);
	if (pub_val == NULL) {
		status = ERR_get_error ();
		goto err_point;
	}

	status = EC_POINT_mul (curve, pub_val, priv_val, NULL, NULL, pub_ctx);
	if (status != 1) {
		status = ERR_get_error ();
		goto err_mult;
	}

	if (EC_KEY_set_private_key (ec, priv_val) != 1) {
		status = ERR_get_error ();
		goto err_mult;
	}

	if (EC_KEY_set_public_key (ec, pub_val) != 1) {
		status = ERR_get_error ();
		goto err_mult;
	}

	EC_POINT_clear_free (pub_val);
	BN_CTX_free (pub_ctx);
	BN_clear_free (priv_val);

	if (pub_key) {
		pub_key->context = ecc_openssl_convert_private_to_public (ec, (priv_key));
		if (pub_key->context == NULL) {
			status = ERR_get_error ();
			goto err_priv;
		}
	}

	if (priv_key) {
		priv_key->context = ec;
	}

	return 0;

err_mult:
	EC_POINT_clear_free (pub_val);
err_point:
	BN_CTX_free (pub_ctx);
err_ctx:
	BN_clear_free (priv_val);
err_priv:
	EC_KEY_free (ec);
	return (!status) ? ECC_ENGINE_NO_MEMORY : -status;
}

static int ecc_openssl_generate_key_pair (struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	EC_KEY *ec;
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

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			ec = EC_KEY_new_by_curve_name (NID_X9_62_prime256v1);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			ec = EC_KEY_new_by_curve_name (NID_secp384r1);
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			ec = EC_KEY_new_by_curve_name (NID_secp521r1);
			break;
#endif
#endif

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}
	if (ec == NULL) {
		return -ERR_get_error ();
	}

	EC_KEY_set_asn1_flag (ec, OPENSSL_EC_NAMED_CURVE);

	status = EC_KEY_generate_key (ec);
	if (status != 1) {
		EC_KEY_free (ec);
		return -ERR_get_error ();
	}

	if (pub_key) {
		pub_key->context = ecc_openssl_convert_private_to_public (ec, (priv_key));
		if (pub_key->context == NULL) {
			status = -ERR_get_error ();
			EC_KEY_free (ec);
			return status;
		}
	}

	if (priv_key) {
		priv_key->context = ec;
	}

	return 0;
}
#endif

static void ecc_openssl_release_key_pair (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	UNUSED (engine);

	if (priv_key) {
		EC_KEY_free ((EC_KEY*) priv_key->context);
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}

	if (pub_key) {
		EC_KEY_free ((EC_KEY*) pub_key->context);
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}
}

static int ecc_openssl_get_signature_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	return ECDSA_size ((EC_KEY*) key->context);
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_openssl_get_private_key_der (struct ecc_engine *engine,
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

	status = i2d_ECPrivateKey ((EC_KEY*) key->context, der);
	if (status > 0) {
		*length = status;
		status = 0;
	}
	else if (status == 0) {
		status = ECC_ENGINE_NOT_PRIVATE_KEY;
	}
	else {
		status = -ERR_get_error ();
	}

	return status;
}

static int ecc_openssl_get_public_key_der (struct ecc_engine *engine,
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

	if (EC_KEY_get0_private_key ((EC_KEY*) key->context) != NULL) {
		return ECC_ENGINE_NOT_PUBLIC_KEY;
	}

	status = i2d_EC_PUBKEY ((EC_KEY*) key->context, der);
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

static int ecc_openssl_sign (struct ecc_engine *engine, struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t sig_length)
{
	unsigned int out_len;
	int status;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if ((int) sig_length < ecc_openssl_get_signature_max_length (engine, key)) {
		return ECC_ENGINE_SIG_BUFFER_TOO_SMALL;
	}

	ERR_clear_error ();

	status = ECDSA_sign (-1, digest, length, signature, &out_len, (EC_KEY*) key->context);

	return (status == 1) ? out_len : -ERR_get_error ();
}

static int ecc_openssl_verify (struct ecc_engine *engine, struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	int status;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	status = ECDSA_verify (-1, digest, length, signature, sig_length, (EC_KEY*) key->context);

	return (status == 1) ? 0 : ECC_ENGINE_BAD_SIGNATURE;
}

#ifdef ECC_ENABLE_ECDH
static int ecc_openssl_get_shared_secret_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	return (EC_GROUP_get_degree (EC_KEY_get0_group ((EC_KEY*) key->context)) + 7) / 8;
}

static int ecc_openssl_compute_shared_secret (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length)
{
	int status;

	if ((engine == NULL) || (priv_key == NULL) || (pub_key == NULL) || (secret == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if ((int) length < ecc_openssl_get_shared_secret_max_length (engine, priv_key)) {
		return ECC_ENGINE_SECRET_BUFFER_TOO_SMALL;
	}

	ERR_clear_error ();

	status = ECDH_compute_key (secret, length, EC_KEY_get0_public_key ((EC_KEY*) pub_key->context),
		(EC_KEY*) priv_key->context, NULL);
	if (status < 0) {
		return -ERR_get_error ();
	}

	return status;
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
void ecc_openssl_release (struct ecc_engine_openssl *engine)
{

}
