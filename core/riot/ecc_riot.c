// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include "platform.h"
#include "ecc_riot.h"
#include "riot/riot_core.h"
#include "reference/include/RiotEcc.h"
#include "reference/include/RiotDerEnc.h"
#include "reference/include/RiotX509Bldr.h"
#include "reference/include/RiotDerDec.h"

/**
 * Get the riot ECC key pair instance for a public or private key instance.
 *
 * @return The riot ECC key pair.
 */
#define	ecc_riot_get_ec_key_pair(x)	((ecc_keypair*) x->context)


#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
/**
 * Allocate and initialize a context for an ECC key.
 *
 * @return The initialized key context or null.
 */

static ecc_keypair *ecc_riot_alloc_key_context ()
{
	ecc_keypair *key_ctx = platform_malloc (sizeof (ecc_keypair));

	if (key_ctx) {
		memset (key_ctx, 0, sizeof (ecc_keypair));
	}

	key_ctx->Q.infinity = true;

	return key_ctx;
}

/**
 * Zeroize an ECC key context and free the memory.
 *
 * @param context The context to free.
 */
static void ecc_riot_free_key_context (void *key_ctx)
{
	riot_core_clear (key_ctx, sizeof (ecc_keypair));
	platform_free (key_ctx);
}

static int ecc_riot_init_key_pair (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	ecc_keypair *public_key;
	ecc_keypair *private_key;
	uint8_t der_priv_key[RIOT_ECC_PRIVATE_BYTES];
	size_t der_priv_key_len;
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

	public_key = ecc_riot_alloc_key_context ();
	if (public_key == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	private_key = ecc_riot_alloc_key_context ();
	if (private_key == NULL) {
		ecc_riot_free_key_context (public_key);
		return ECC_ENGINE_NO_MEMORY;
	}

	status = DERDECGetPrivKey (der_priv_key, &der_priv_key_len, key, key_length);
	if (status != RIOT_SUCCESS) {
		status = (status == RIOT_INVALID_PARAMETER) ?
			ECC_ENGINE_UNSUPPORTED_KEY_LENGTH : ECC_ENGINE_NOT_PRIVATE_KEY;
		goto error;
	}

	status = RIOT_DeriveDsaKeyPair (&public_key->Q, &private_key->d, der_priv_key,
		der_priv_key_len);
	if (status != RIOT_SUCCESS) {
		status = ECC_ENGINE_KEY_PAIR_FAILED;
		goto error;
	}

	if (pub_key) {
		pub_key->context = public_key;
	}
	else {
		ecc_riot_free_key_context (public_key);
	}

	if (priv_key) {
		priv_key->context = private_key;
	}
	else {
		ecc_riot_free_key_context (private_key);
	}

	return 0;

error:
	ecc_riot_free_key_context (public_key);
	ecc_riot_free_key_context (private_key);

	return status;
}

static int ecc_riot_generate_derived_key_pair (struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_riot *riot = (struct ecc_engine_riot*) engine;
	ecc_keypair *public_key;
	ecc_keypair *private_key;
	int status;

	if ((riot == NULL) || (priv == NULL) || (key_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	if (key_length != ECC_KEY_LENGTH_256) {
		return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}

	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	public_key = ecc_riot_alloc_key_context ();
	if (public_key == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	private_key = ecc_riot_alloc_key_context ();
	if (private_key == NULL) {
		ecc_riot_free_key_context (public_key);
		return ECC_ENGINE_NO_MEMORY;
	}

	status = RIOT_DeriveDsaKeyPair (&public_key->Q, &private_key->d, priv, key_length);
	if (status != RIOT_SUCCESS) {
		goto error;
	}

	memcpy (&(private_key->Q), &(public_key->Q), sizeof (ecc_publickey));

	if (pub_key) {
		pub_key->context = public_key;
	}
	else {
		ecc_riot_free_key_context (public_key);
	}

	if (priv_key) {
		priv_key->context = private_key;
	}
	else {
		ecc_riot_free_key_context (private_key);
	}

	return 0;

error:
	ecc_riot_free_key_context (public_key);
	ecc_riot_free_key_context (private_key);

	return ECC_ENGINE_DERIVED_KEY_FAILED;
}

static void ecc_riot_release_key_pair (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	if (priv_key) {
		ecc_riot_free_key_context (priv_key->context);
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}

	if (pub_key) {
		ecc_riot_free_key_context (pub_key->context);
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}
}
#endif

static int ecc_riot_get_signature_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	return  (((RIOT_DSA_size ((ecc_keypair*) key->context) + 3) * 2) + 2);
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_riot_get_private_key_der (struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length)
{
	uint8_t tmp_der[25 + (4 * (RIOT_ECC_PRIVATE_BYTES))];
	int status;
	ecc_keypair *ec;
	DERBuilderContext derCtx;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	ec = ecc_riot_get_ec_key_pair (key);

	if (RIOT_DSA_check_privkey (&ec->d) != RIOT_SUCCESS) {
		return ECC_ENGINE_NOT_PRIVATE_KEY;
	}

	DERInitContext (&derCtx, tmp_der, sizeof (tmp_der));
	status = X509GetDEREcc (&derCtx, ec->Q, ec->d);
	if (status != 0) {
		return ECC_ENGINE_PRIVATE_KEY_DER_FAILED;
	}

	*length = DERGetEncodedLength (&derCtx);
	if (*length > sizeof (tmp_der)) {
		return ECC_ENGINE_PRIVATE_KEY_DER_FAILED;
	}

	*der = platform_malloc (*length);
	if (*der == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	memcpy (*der, tmp_der, *length);

	return status;
}

static int ecc_riot_get_public_key_der (struct ecc_engine *engine, const struct ecc_public_key *key,
	 uint8_t **der, size_t *length)
{
	uint8_t tmp_der[30 + (4 * RIOT_ECC_COORD_BYTES)];
	int status;
	ecc_keypair *ec;
	DERBuilderContext derCtx;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	ec = ecc_riot_get_ec_key_pair (key);

	if (RIOT_DSA_check_pubkey (ec) != RIOT_SUCCESS) {
		return ECC_ENGINE_NOT_PUBLIC_KEY;
	}

	DERInitContext (&derCtx, tmp_der, sizeof (tmp_der));
	status = X509GetDEREccPub (&derCtx, ec->Q);
	if (status != 0) {
		return ECC_ENGINE_PUBLIC_KEY_DER_FAILED;
	}

	*length = DERGetEncodedLength (&derCtx);
	if (*length > sizeof (tmp_der)) {
		return ECC_ENGINE_PUBLIC_KEY_DER_FAILED;
	}

	*der = platform_malloc (*length);
	if (*der == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	memcpy (*der, tmp_der, *length);

	return status;
}
#endif

static int ecc_riot_sign (struct ecc_engine *engine, struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t sig_length)
{
	struct ecc_engine_riot *riot = (struct ecc_engine_riot*) engine;
	ecc_keypair *ec;
	int out_len;
	int status;

	if ((riot == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if ((int) sig_length < ecc_riot_get_signature_max_length (engine, key)) {
		return ECC_ENGINE_SIG_BUFFER_TOO_SMALL;
	}

	if (length != SHA256_HASH_LENGTH) {
		return ECC_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	ec = ecc_riot_get_ec_key_pair (key);

	if (RIOT_DSA_check_privkey (&ec->d) != RIOT_SUCCESS) {
		return ECC_ENGINE_NOT_PRIVATE_KEY;
	}

	status = RIOT_DSASignDigest (digest, length, &ec->d, signature, sig_length, riot->rng,
		&out_len);

	return (status == RIOT_SUCCESS) ? out_len : ECC_ENGINE_SIGN_FAILED;
}

static int ecc_riot_verify (struct ecc_engine *engine, struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
 	int status;
	ecc_signature ecc_sig;
	ecc_keypair *ec;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	status = RIOT_DSA_decode_signature (&ecc_sig, signature, sig_length);
	if (status != RIOT_SUCCESS) {
		return ECC_ENGINE_BAD_SIGNATURE;
	}

	ec = ecc_riot_get_ec_key_pair (key);
	status = RIOT_DSAVerifyDigest (digest, length, &ecc_sig, &ec->Q);
	if (status != RIOT_SUCCESS) {
		return ECC_ENGINE_BAD_SIGNATURE;
	}

	return status;
}

/**
 * Initialize an instance for running ECC operations using riot core.
 *
 * @param engine The ECC engine to initialize.
 * @param rng The RNG engine to use for ECC operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int ecc_riot_init (struct ecc_engine_riot *engine, struct rng_engine *rng)
{
	if ((engine == NULL) || (rng == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct ecc_engine_riot));

	engine->rng = rng;

	engine->base.init_key_pair = ecc_riot_init_key_pair;
	engine->base.init_public_key = NULL;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.generate_derived_key_pair = ecc_riot_generate_derived_key_pair;
	engine->base.generate_key_pair = NULL;
	engine->base.release_key_pair = ecc_riot_release_key_pair;
#endif
	engine->base.get_signature_max_length = ecc_riot_get_signature_max_length;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.get_private_key_der = ecc_riot_get_private_key_der;
	engine->base.get_public_key_der = ecc_riot_get_public_key_der;
#endif
	engine->base.sign = ecc_riot_sign;
	engine->base.verify = ecc_riot_verify;
#ifdef ECC_ENABLE_ECDH
	engine->base.get_shared_secret_max_length = NULL;
	engine->base.compute_shared_secret = NULL;
#endif

	return 0;
}

/**
 * Release a riot ECC engine.
 *
 * @param engine The ECC engine to release.
 */
void ecc_riot_release (struct ecc_engine_riot *engine)
{

}
