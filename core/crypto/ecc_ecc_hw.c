// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ecc_ecc_hw.h"
#include "platform_api.h"
#include "asn1/ecc_der_util.h"
#include "common/buffer_util.h"
#include "common/unused.h"
#include "crypto/crypto_logging.h"
#include "crypto/hash.h"


/**
 * Key context for managing ECC keys.
 */
struct ecc_ecc_hw_key_context {
	bool is_private;						/**< Indicates if the key context contains a private key. */
	union {
		struct ecc_raw_private_key priv;	/**< ECC private key data. */
		struct ecc_point_public_key pub;	/**< ECC public key data. */
	};
};

/**
 * Get the key context for an ECC key instance.
 *
 * @return The ECC key context.
 */
#define	ecc_ecc_hw_get_key_context(x)	((struct ecc_ecc_hw_key_context*) x->context)

/**
 * Get the raw public key for a public key instance.
 *
 * @return The raw public key.
 */
#define	ecc_ecc_hw_public_key(x)		((ecc_ecc_hw_get_key_context (x))->pub)

/**
 * Get the raw private key for a private key instance.
 *
 * @return The raw private key.
 */
#define	ecc_ecc_hw_private_key(x)		((ecc_ecc_hw_get_key_context (x))->priv)

/**
 * Determine if a key context contains a private key.
 */
#define	ecc_ecc_hw_is_private_key(x)	((ecc_ecc_hw_get_key_context (x))->is_private)


/**
 * Allocate and initialize a context for an ECC key.
 *
 * @return The initialized key context or null.
 */
static struct ecc_ecc_hw_key_context* ecc_ecc_hw_alloc_key_context ()
{
	struct ecc_ecc_hw_key_context *key = platform_malloc (sizeof (struct ecc_ecc_hw_key_context));

	if (key != NULL) {
		memset (key, 0, sizeof (struct ecc_ecc_hw_key_context));
	}

	return key;
}

/**
 * Zeroize an ECC key context and free the memory.
 *
 * @param context The context to free.
 */
static void ecc_ecc_hw_free_key_context (void *context)
{
	buffer_zeroize (context, sizeof (struct ecc_ecc_hw_key_context));
	platform_free (context);
}

/**
 * Initialize ECC key contexts for private and public keys.
 *
 * @param ecc The ECC engine initializing the keys.
 * @param priv The ECC private key data, not DER encoded.
 * @param key_length Length of the private key.
 * @param pub The ECC public key data, not DER encoded.  If this is not provided, the public key
 * will be calculated from the private key.
 * @param priv_key Output for the private key context.  Null to not initialize the private key.
 * @param pub_key Output for the public key context.  Null to not initialize the public key.
 *
 * @return 0 if the key contexts were successfully initialized or an error code.
 */
static int ecc_ecc_hw_init_key_contexts (const struct ecc_engine_ecc_hw *ecc, const uint8_t *priv,
	size_t key_length, const struct ecc_point_public_key *pub, struct ecc_private_key *priv_key,
	struct ecc_public_key *pub_key)
{
	int status;

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (priv_key) {
		priv_key->context = ecc_ecc_hw_alloc_key_context ();
		if (priv_key->context == NULL) {
			return ECC_ENGINE_NO_MEMORY;
		}

		ecc_ecc_hw_get_key_context (priv_key)->is_private = true;
		memcpy (ecc_ecc_hw_private_key (priv_key).d, priv, key_length);
		ecc_ecc_hw_private_key (priv_key).key_length = key_length;
	}

	if (pub_key) {
		pub_key->context = ecc_ecc_hw_alloc_key_context ();
		if (pub_key->context == NULL) {
			status = ECC_ENGINE_NO_MEMORY;
			goto pub_error;
		}

		if (!pub) {
			status = ecc->hw->get_ecc_public_key (ecc->hw, priv, key_length,
				&ecc_ecc_hw_public_key (pub_key));
			if (status != 0) {
				ecc_ecc_hw_free_key_context (pub_key->context);
				pub_key->context = NULL;
				goto pub_error;
			}
		}
		else {
			memcpy (&ecc_ecc_hw_public_key (pub_key), pub, sizeof (struct ecc_point_public_key));
		}
	}

	return 0;

pub_error:
	if (priv_key) {
		ecc_ecc_hw_free_key_context (priv_key->context);
		priv_key->context = NULL;
	}

	return status;
}

int ecc_ecc_hw_init_key_pair (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	uint8_t priv[ECC_MAX_KEY_LENGTH];
	int priv_key_length;

	if ((engine == NULL) || (key == NULL) || (key_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	priv_key_length = ecc_der_decode_private_key (key, key_length, priv, sizeof (priv));
	if (ROT_IS_ERROR (priv_key_length)) {
		if (priv_key_length == ECC_DER_UTIL_UNKNOWN_SEQUENCE) {
			/* If we don't understand the structure, it's probably not an ECC key. */
			priv_key_length = ECC_ENGINE_NOT_EC_KEY;
		}

		return priv_key_length;
	}

	return ecc_ecc_hw_init_key_contexts ((const struct ecc_engine_ecc_hw*) engine, priv,
		priv_key_length, NULL, priv_key, pub_key);
}

int ecc_ecc_hw_init_public_key (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
	struct ecc_public_key *pub_key)
{
	int pub_key_length;

	if ((engine == NULL) || (key == NULL) || (key_length == 0) || (pub_key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	pub_key->context = ecc_ecc_hw_alloc_key_context ();
	if (pub_key->context == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	pub_key_length = ecc_der_decode_public_key (key, key_length, ecc_ecc_hw_public_key (pub_key).x,
		ecc_ecc_hw_public_key (pub_key).y, ECC_MAX_KEY_LENGTH);
	if (ROT_IS_ERROR (pub_key_length)) {
		ecc_ecc_hw_free_key_context (pub_key->context);
		pub_key->context = NULL;

		if (pub_key_length == ECC_DER_UTIL_UNKNOWN_SEQUENCE) {
			/* If we don't understand the structure, it's probably not an ECC key. */
			pub_key_length = ECC_ENGINE_NOT_EC_KEY;
		}

		return pub_key_length;
	}

	ecc_ecc_hw_public_key (pub_key).key_length = pub_key_length;

	return 0;
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
int ecc_ecc_hw_generate_derived_key_pair (struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	if ((engine == NULL) || (priv == NULL) || (key_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
#endif
			break;

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}

	return ecc_ecc_hw_init_key_contexts ((const struct ecc_engine_ecc_hw*) engine, priv, key_length,
		NULL, priv_key, pub_key);
}

int ecc_ecc_hw_generate_key_pair (struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	const struct ecc_engine_ecc_hw *ecc = (const struct ecc_engine_ecc_hw*) engine;
	uint8_t priv[ECC_MAX_KEY_LENGTH];
	struct ecc_point_public_key pub;
	int status;

	if (ecc == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
#endif
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
#endif
			break;

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}

	status = ecc->hw->generate_ecc_key_pair (ecc->hw, key_length, priv, &pub);
	if (status != 0) {
		return status;
	}

	return ecc_ecc_hw_init_key_contexts (ecc, priv, key_length, &pub, priv_key, pub_key);
}
#endif

void ecc_ecc_hw_release_key_pair (struct ecc_engine *engine, struct ecc_private_key *priv_key,
	struct ecc_public_key *pub_key)
{
	UNUSED (engine);

	if (priv_key) {
		ecc_ecc_hw_free_key_context (priv_key->context);
		priv_key->context = NULL;
	}

	if (pub_key) {
		ecc_ecc_hw_free_key_context (pub_key->context);
		pub_key->context = NULL;
	}
}

int ecc_ecc_hw_get_signature_max_length (struct ecc_engine *engine,
	const struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	switch (ecc_ecc_hw_private_key (key).key_length) {
		case ECC_KEY_LENGTH_256:
			return ECC_DER_P256_ECDSA_MAX_LENGTH;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			return ECC_DER_P384_ECDSA_MAX_LENGTH;
#endif

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			return ECC_DER_P521_ECDSA_MAX_LENGTH;
#endif

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
int ecc_ecc_hw_get_private_key_der (struct ecc_engine *engine, const struct ecc_private_key *key,
	uint8_t **der, size_t *length)
{
	const struct ecc_engine_ecc_hw *ecc = (const struct ecc_engine_ecc_hw*) engine;
	struct ecc_point_public_key pub_key;
	int status;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((ecc == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!ecc_ecc_hw_is_private_key (key)) {
		return ECC_ENGINE_NOT_PRIVATE_KEY;
	}

	status = ecc->hw->get_ecc_public_key (ecc->hw, ecc_ecc_hw_private_key (key).d,
		ecc_ecc_hw_private_key (key).key_length, &pub_key);
	if (status != 0) {
		return status;
	}

	*der = platform_malloc (ECC_DER_MAX_PRIVATE_LENGTH);
	if (*der == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	/* This call won't fail since we have a valid key and the buffer is large enough for any key. */
	*length = ecc_der_encode_private_key (ecc_ecc_hw_private_key (key).d, pub_key.x, pub_key.y,
		ecc_ecc_hw_private_key (key).key_length, *der, ECC_DER_MAX_PRIVATE_LENGTH);

	return 0;
}

int ecc_ecc_hw_get_public_key_der (struct ecc_engine *engine, const struct ecc_public_key *key,
	uint8_t **der, size_t *length)
{
	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (ecc_ecc_hw_is_private_key (key)) {
		return ECC_ENGINE_NOT_PUBLIC_KEY;
	}

	*der = platform_malloc (ECC_DER_MAX_PUBLIC_LENGTH);
	if (*der == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	/* This call won't fail since we have a valid key and the buffer is large enough for any key. */
	*length = ecc_der_encode_public_key (ecc_ecc_hw_public_key (key).x,
		ecc_ecc_hw_public_key (key).y, ecc_ecc_hw_public_key (key).key_length, *der,
		ECC_DER_MAX_PUBLIC_LENGTH);

	return 0;
}
#endif

int ecc_ecc_hw_sign (struct ecc_engine *engine, const struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t sig_length)
{
	const struct ecc_engine_ecc_hw *ecc = (const struct ecc_engine_ecc_hw*) engine;
	struct ecc_ecdsa_signature raw_signature;
	int status;

	if ((ecc == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!ecc_ecc_hw_is_private_key (key)) {
		return ECC_ENGINE_NOT_PRIVATE_KEY;
	}

	switch (length) {
		case SHA256_HASH_LENGTH:
		case SHA384_HASH_LENGTH:
		case SHA512_HASH_LENGTH:
			break;

		default:
			return ECC_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	status = ecc->hw->ecdsa_sign (ecc->hw, ecc_ecc_hw_private_key (key).d,
		ecc_ecc_hw_private_key (key).key_length, digest, length, ecc->rng, &raw_signature);
	if (status != 0) {
		return status;
	}

	status = ecc_der_encode_ecdsa_signature (raw_signature.r, raw_signature.s, raw_signature.length,
		signature, sig_length);
	if (status == ECC_DER_UTIL_SMALL_DER_BUFFER) {
		status = ECC_ENGINE_SIG_BUFFER_TOO_SMALL;
	}

	return status;
}

int ecc_ecc_hw_verify (struct ecc_engine *engine, const struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	const struct ecc_engine_ecc_hw *ecc = (const struct ecc_engine_ecc_hw*) engine;
	struct ecc_ecdsa_signature raw_signature;
	int status;

	if ((ecc == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	raw_signature.length = ecc_ecc_hw_public_key (key).key_length;
	status = ecc_der_decode_ecdsa_signature (signature, sig_length, raw_signature.r,
		raw_signature.s, raw_signature.length);
	if (status != 0) {
		/* Re-use the mbedTLS logging message, since it is conveying the same information. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC, status, 0);

		return ECC_ENGINE_BAD_SIGNATURE;
	}

	status = ecc->hw->ecdsa_verify (ecc->hw, &ecc_ecc_hw_public_key (key), &raw_signature, digest,
		length);
	if (status == ECC_HW_ECDSA_BAD_SIGNATURE) {
		status = ECC_ENGINE_BAD_SIGNATURE;
	}

	return status;
}

#ifdef ECC_ENABLE_ECDH
int ecc_ecc_hw_get_shared_secret_max_length (struct ecc_engine *engine,
	const struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	return ecc_ecc_hw_private_key (key).key_length;
}

int ecc_ecc_hw_compute_shared_secret (struct ecc_engine *engine,
	const struct ecc_private_key *priv_key, const struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length)
{
	const struct ecc_engine_ecc_hw *ecc = (const struct ecc_engine_ecc_hw*) engine;
	int status;

	if ((ecc == NULL) || (priv_key == NULL) || (pub_key == NULL) || (secret == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (length < ecc_ecc_hw_private_key (priv_key).key_length) {
		return ECC_ENGINE_SECRET_BUFFER_TOO_SMALL;
	}

	status = ecc->hw->ecdh_compute (ecc->hw, ecc_ecc_hw_private_key (priv_key).d,
		ecc_ecc_hw_private_key (priv_key).key_length, &ecc_ecc_hw_public_key (pub_key), secret,
		length);
	if (status != 0) {
		return status;
	}

	return ecc_ecc_hw_private_key (priv_key).key_length;
}
#endif

/**
 * Initialize an instance for executing ECC operations using a hardware accelerator.
 *
 * @param engine The ECC context to initialize.
 * @param hw The hardware accelerator that should be used for ECC operations.
 * @param rng An optional random number generator to use during ECC signature generation.  If this
 * is not provided, the default RNG for the hardware accelerator will be used.
 *
 * @return 0 if initialization was successful or an error code.
 */
int ecc_ecc_hw_init (struct ecc_engine_ecc_hw *engine, const struct ecc_hw *hw,
	struct rng_engine *rng)
{
	if ((engine == NULL) || (hw == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct ecc_engine_ecc_hw));

	engine->base.init_key_pair = ecc_ecc_hw_init_key_pair;
	engine->base.init_public_key = ecc_ecc_hw_init_public_key;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.generate_derived_key_pair = ecc_ecc_hw_generate_derived_key_pair;
	engine->base.generate_key_pair = ecc_ecc_hw_generate_key_pair;
#endif
	engine->base.release_key_pair = ecc_ecc_hw_release_key_pair;
	engine->base.get_signature_max_length = ecc_ecc_hw_get_signature_max_length;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.get_private_key_der = ecc_ecc_hw_get_private_key_der;
	engine->base.get_public_key_der = ecc_ecc_hw_get_public_key_der;
#endif
	engine->base.sign = ecc_ecc_hw_sign;
	engine->base.verify = ecc_ecc_hw_verify;
#ifdef ECC_ENABLE_ECDH
	engine->base.get_shared_secret_max_length = ecc_ecc_hw_get_shared_secret_max_length;
	engine->base.compute_shared_secret = ecc_ecc_hw_compute_shared_secret;
#endif

	engine->hw = hw;
	engine->rng = rng;

	return 0;
}

/**
 * Release a hardware accelerated ECC instance.  The interface to the hardware will not be released.
 *
 * @param engine The ECC context to release.
 */
void ecc_ecc_hw_release (const struct ecc_engine_ecc_hw *engine)
{
	UNUSED (engine);
}
