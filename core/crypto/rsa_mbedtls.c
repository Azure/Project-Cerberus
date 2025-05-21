// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "crypto_logging.h"
#include "platform_api.h"
#include "rng_mbedtls.h"
#include "rsa_mbedtls.h"
#include "common/unused.h"
#include "crypto/mbedtls_compat.h"
#include "logging/debug_log.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"


#define	RSA_PRIV_DER_MAX_SIZE	47 + (3 * MBEDTLS_MPI_MAX_SIZE) + \
								(5 * ((MBEDTLS_MPI_MAX_SIZE / 2) + (MBEDTLS_MPI_MAX_SIZE % 2)))
#define	RSA_PUB_DER_MAX_SIZE	38 + (2 * MBEDTLS_MPI_MAX_SIZE)


/**
 * Get the mbedTLS RSA key instance for a private key instance.
 *
 * @return The mbedTLS RSA key.
 */
#define	rsa_mbedtls_get_rsa_key(x)	mbedtls_pk_rsa (*((mbedtls_pk_context*) x->context))

#if (defined RSA_ENABLE_PRIVATE_KEY || defined RSA_ENABLE_DER_PUBLIC_KEY)
/**
 * Allocate and initialize a context for an RSA key.
 *
 * @return The initialized key context or null.
 */
static mbedtls_pk_context* rsa_mbedtls_alloc_key_context ()
{
	mbedtls_pk_context *key = platform_malloc (sizeof (mbedtls_pk_context));

	if (key != NULL) {
		mbedtls_pk_init (key);
	}

	return key;
}

/**
 * Zeroize an RSA key context and free the memory.
 *
 * @param context The context to free.
 */
static void rsa_mbedtls_free_key_context (void *context)
{
	mbedtls_pk_free ((mbedtls_pk_context*) context);
	platform_free (context);
}
#endif

#ifdef RSA_ENABLE_PRIVATE_KEY
int rsa_mbedtls_generate_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	int bits)
{
	const struct rsa_engine_mbedtls *mbedtls = (const struct rsa_engine_mbedtls*) engine;
	mbedtls_pk_context *rsa;
	uint8_t msg_code;
	int status;

	if ((mbedtls == NULL) || (key == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	rsa = rsa_mbedtls_alloc_key_context ();
	if (rsa == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_setup (rsa, mbedtls_pk_info_from_type (MBEDTLS_PK_RSA));
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC;
		goto error;
	}

	status = mbedtls_rsa_gen_key (mbedtls_pk_rsa (*rsa), mbedtls->f_rng, mbedtls->rng, bits, 65537);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_RSA_GEN_KEY_EC;
		goto error;
	}

	mbedtls_rsa_set_padding (mbedtls_pk_rsa (*rsa), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
	key->context = rsa;

	return 0;

error:
	rsa_mbedtls_free_key_context (rsa);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO, msg_code, status,
		0);

	return status;
}

int rsa_mbedtls_init_private_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
	const struct rsa_engine_mbedtls *mbedtls = (const struct rsa_engine_mbedtls*) engine;
	mbedtls_pk_context *rsa;
	int status;

	if ((engine == NULL) || (key == NULL) || (der == NULL) || (length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (key, 0, sizeof (struct rsa_private_key));

	rsa = rsa_mbedtls_alloc_key_context ();
	if (rsa == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

#if MBEDTLS_IS_VERSION_3
	status = mbedtls_pk_parse_key (rsa, der, length, NULL, 0, mbedtls->f_rng, mbedtls->rng);
#else
	UNUSED (mbedtls);
	status = mbedtls_pk_parse_key (rsa, der, length, NULL, 0);
#endif
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_EC, status, 0);
		goto error;
	}

	if (mbedtls_pk_get_type (rsa) != MBEDTLS_PK_RSA) {
		status = RSA_ENGINE_NOT_RSA_KEY;
		goto error;
	}

	mbedtls_rsa_set_padding (mbedtls_pk_rsa (*rsa), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
	key->context = rsa;

	return 0;

error:
	rsa_mbedtls_free_key_context (rsa);

	return status;
}

void rsa_mbedtls_release_key (const struct rsa_engine *engine, struct rsa_private_key *key)
{
	if (engine && key) {
		rsa_mbedtls_free_key_context (key->context);
	}
}

int rsa_mbedtls_get_private_key_der (const struct rsa_engine *engine,
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

	*der = platform_malloc (RSA_PRIV_DER_MAX_SIZE);
	if (*der == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_write_key_der ((mbedtls_pk_context*) key->context, *der,
		RSA_PRIV_DER_MAX_SIZE);
	if (status >= 0) {
		memmove (*der, &(*der)[RSA_PRIV_DER_MAX_SIZE - status], status);
		*length = status;
		status = 0;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_KEY_DER_EC, status, 0);

		platform_free (*der);
		*der = NULL;
	}

	return status;
}

#ifndef RSA_DISABLE_DECRYPT
int rsa_mbedtls_decrypt (const struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	const struct rsa_engine_mbedtls *mbedtls = (const struct rsa_engine_mbedtls*) engine;
	int status;
	size_t length;

	if ((mbedtls == NULL) || (key == NULL) || (encrypted == NULL) || (in_length == 0) ||
		(decrypted == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	if (pad_hash > HASH_TYPE_SHA256) {
		return RSA_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

#ifndef MBEDTLS_SHA1_C
	if (pad_hash == HASH_TYPE_SHA1) {
		return RSA_ENGINE_UNSUPPORTED_HASH_TYPE;
	}
#endif
#ifndef MBEDTLS_SHA256_C
	if (pad_hash == HASH_TYPE_SHA256) {
		return RSA_ENGINE_UNSUPPORTED_HASH_TYPE;
	}
#endif

	if (pad_hash == HASH_TYPE_SHA256) {
		mbedtls_rsa_set_padding (rsa_mbedtls_get_rsa_key (key), MBEDTLS_RSA_PKCS_V21,
			MBEDTLS_MD_SHA256);
	}

#if MBEDTLS_IS_VERSION_3
	status = mbedtls_rsa_rsaes_oaep_decrypt (rsa_mbedtls_get_rsa_key (key), mbedtls->f_rng,
		mbedtls->rng, label, label_length, &length, encrypted, decrypted, out_length);
#else
	status = mbedtls_rsa_rsaes_oaep_decrypt (rsa_mbedtls_get_rsa_key (key), mbedtls->f_rng,
		mbedtls->rng, MBEDTLS_RSA_PRIVATE, label, label_length, &length, encrypted, decrypted,
		out_length);
#endif
	if (status == 0) {
		status = length;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_OAEP_DECRYPT_EC, status, 0);

		if (status == MBEDTLS_ERR_RSA_OUTPUT_TOO_LARGE) {
			status = RSA_ENGINE_OUT_BUFFER_TOO_SMALL;
		}
	}

	/* Restore the padding hash algorithm to the default. */
	mbedtls_rsa_set_padding (rsa_mbedtls_get_rsa_key (key), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);

	return status;
}
#endif	// RSA_DISABLE_DECRYPT
#endif	// RSA_ENABLE_PRIVATE_KEY

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
int rsa_mbedtls_init_public_key (const struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length)
{
	mbedtls_pk_context *pk;
	mbedtls_rsa_context *rsa;
	uint8_t exp[4];
	int status;

	if ((engine == NULL) || (key == NULL) || (der == NULL) || (length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (key, 0, sizeof (struct rsa_public_key));

	pk = rsa_mbedtls_alloc_key_context ();
	if (pk == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_parse_public_key (pk, der, length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_PUB_EC, status, 0);
		goto exit;
	}

	if (mbedtls_pk_get_type (pk) != MBEDTLS_PK_RSA) {
		status = RSA_ENGINE_NOT_RSA_KEY;
		goto exit;
	}

	rsa = mbedtls_pk_rsa (*pk);

	status = mbedtls_rsa_check_pubkey (rsa);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC, status, 0);
		goto exit;
	}

	key->mod_length = mbedtls_rsa_get_len (rsa);
	if (key->mod_length > sizeof (key->modulus)) {
		status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
		goto exit;
	}

	status = mbedtls_rsa_export_raw (rsa, key->modulus, key->mod_length, NULL, 0, NULL, 0, NULL, 0,
		exp, sizeof (exp));
	if (status != 0) {
		goto exit;
	}

	key->exponent = (exp[0] << 24) | (exp[1] << 16) | (exp[2] << 8) | exp[3];

exit:
	rsa_mbedtls_free_key_context (pk);

	return status;
}

int rsa_mbedtls_get_public_key_der (const struct rsa_engine *engine,
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

	*der = platform_malloc (RSA_PUB_DER_MAX_SIZE);
	if (*der == NULL) {
		return RSA_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_write_pubkey_der ((mbedtls_pk_context*) key->context, *der,
		RSA_PUB_DER_MAX_SIZE);
	if (status >= 0) {
		memmove (*der, &(*der)[RSA_PUB_DER_MAX_SIZE - status], status);
		*length = status;
		status = 0;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_PUBKEY_DER_EC, status, 0);

		platform_free (*der);
		*der = NULL;
	}

	return status;
}
#endif

/**
 * Initialize an RSA context with a specified public key.
 *
 * @param rsa The RSA context to initialize.
 * @param key The key to use for context initialization.
 *
 * @return 0 if the operation was successful or an error code.
 */
static int rsa_mbedtls_load_pubkey (mbedtls_rsa_context *rsa, const struct rsa_public_key *key)
{
	int status;
	uint8_t exp[4];

#if MBEDTLS_IS_VERSION_3
	mbedtls_rsa_init (rsa);
#else
	mbedtls_rsa_init (rsa, MBEDTLS_RSA_PKCS_V15, 0);
#endif

	exp[0] = key->exponent >> 24;
	exp[1] = key->exponent >> 16;
	exp[2] = key->exponent >> 8;
	exp[3] = key->exponent;

	status = mbedtls_rsa_import_raw (rsa, key->modulus, key->mod_length, NULL, 0, NULL, 0, NULL, 0,
		exp, sizeof (exp));
	if (status != 0) {
		goto exit;
	}

	status = mbedtls_rsa_check_pubkey (rsa);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC, status, 0);
		goto exit;
	}

	return 0;

exit:
	mbedtls_rsa_free (rsa);

	return status;
}

int rsa_mbedtls_sig_verify (const struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match,
	size_t match_length)
{
	mbedtls_rsa_context rsa;
	mbedtls_md_type_t match_type;
	int status;

	if ((engine == NULL) || (key == NULL) || (signature == NULL) || (match == NULL) ||
		(sig_length == 0) || (match_length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	switch (sig_hash) {
		case HASH_TYPE_SHA256:
			match_type = MBEDTLS_MD_SHA256;
			break;

		case HASH_TYPE_SHA384:
			match_type = MBEDTLS_MD_SHA384;
			break;

		case HASH_TYPE_SHA512:
			match_type = MBEDTLS_MD_SHA512;
			break;

		default:
			return RSA_ENGINE_UNSUPPORTED_SIG_TYPE;
	}

	if (sig_length != key->mod_length) {
		return RSA_ENGINE_BAD_SIGNATURE;
	}

	status = rsa_mbedtls_load_pubkey (&rsa, key);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_LOAD_EC, status, 0);

		return status;
	}

#if MBEDTLS_IS_VERSION_3
	status = mbedtls_rsa_pkcs1_verify (&rsa, match_type, match_length, match, signature);
#else
	status = mbedtls_rsa_pkcs1_verify (&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, match_type,
		match_length, match, signature);
#endif
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_PKCS1_VERIFY_EC, status, 0);

		if ((status == MBEDTLS_ERR_MPI_ALLOC_FAILED) ||
			(status == (MBEDTLS_ERR_MPI_ALLOC_FAILED + MBEDTLS_ERR_RSA_PUBLIC_FAILED))) {
			status = RSA_ENGINE_NO_MEMORY;
		}
		else {
			status = RSA_ENGINE_BAD_SIGNATURE;
		}
	}

	mbedtls_rsa_free (&rsa);

	return status;
}

/**
 * Initialize an mbedTLS RSA engine.
 *
 * Random number generation will be handled by an internally managed mbedTLS implementation of a
 * software DRBG.
 *
 * @param engine The RSA engine to initialize.
 * @param state Variable context for RSA operations.  This must be uninitialized.
 *
 * @return 0 if the RSA engine was successfully initialize or an error code.
 */
int rsa_mbedtls_init (struct rsa_engine_mbedtls *engine, struct rsa_engine_mbedtls_state *state)
{
	if (engine == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rsa_engine_mbedtls));

#ifdef RSA_ENABLE_PRIVATE_KEY
	engine->base.generate_key = rsa_mbedtls_generate_key;
	engine->base.init_private_key = rsa_mbedtls_init_private_key;
	engine->base.release_key = rsa_mbedtls_release_key;
	engine->base.get_private_key_der = rsa_mbedtls_get_private_key_der;
#ifndef RSA_DISABLE_DECRYPT
	engine->base.decrypt = rsa_mbedtls_decrypt;
#endif
#endif
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	engine->base.init_public_key = rsa_mbedtls_init_public_key;
	engine->base.get_public_key_der = rsa_mbedtls_get_public_key_der;
#endif
	engine->base.sig_verify = rsa_mbedtls_sig_verify;

	engine->state = state;
	engine->rng = &state->ctr_drbg;
	engine->f_rng = mbedtls_ctr_drbg_random;

	return rsa_mbedtls_init_state (engine);
}

/**
 * Initialize an mbedTLS RSA engine.
 *
 * Random number generation will be handled by the provided RNG engine.
 *
 * @note There is no variable state when operating in this mode, so no state structure is required.
 *
 * @param engine The RSA engine to initialize.
 * @param rng The source for random numbers during RSA operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int rsa_mbedtls_init_with_external_rng (struct rsa_engine_mbedtls *engine,
	const struct rng_engine *rng)
{
	if ((engine == NULL) || (rng == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rsa_engine_mbedtls));

#ifdef RSA_ENABLE_PRIVATE_KEY
	engine->base.generate_key = rsa_mbedtls_generate_key;
	engine->base.init_private_key = rsa_mbedtls_init_private_key;
	engine->base.release_key = rsa_mbedtls_release_key;
	engine->base.get_private_key_der = rsa_mbedtls_get_private_key_der;
#ifndef RSA_DISABLE_DECRYPT
	engine->base.decrypt = rsa_mbedtls_decrypt;
#endif
#endif
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	engine->base.init_public_key = rsa_mbedtls_init_public_key;
	engine->base.get_public_key_der = rsa_mbedtls_get_public_key_der;
#endif
	engine->base.sig_verify = rsa_mbedtls_sig_verify;

	engine->rng = (void*) rng;
	engine->f_rng = rng_mbedtls_rng_callback;

	return 0;
}

/**
 * Initialize only the variable state of an mbedTLS RSA engine.  The rest of the instance is assumed
 * to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @note Do not call this function for instances initialized to use an external source for random
 * numbers.  There is no variable state to initialize in this case.
 *
 * @param engine The RSA engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int rsa_mbedtls_init_state (const struct rsa_engine_mbedtls *engine)
{
	int status;

	if ((engine == NULL) || (engine->state == NULL)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	mbedtls_ctr_drbg_init (&engine->state->ctr_drbg);
	mbedtls_entropy_init (&engine->state->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->state->ctr_drbg, mbedtls_entropy_func,
		&engine->state->entropy, NULL, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC, status, 0);
		goto exit;
	}

	return 0;

exit:
	mbedtls_entropy_free (&engine->state->entropy);
	mbedtls_ctr_drbg_free (&engine->state->ctr_drbg);

	return status;
}

/**
 * Release the resources used by an mbedTLS RSA engine.
 *
 * @param engine The RSA engine to release.
 */
void rsa_mbedtls_release (const struct rsa_engine_mbedtls *engine)
{
	if ((engine != NULL) && (engine->state != NULL)) {
		mbedtls_entropy_free (&engine->state->entropy);
		mbedtls_ctr_drbg_free (&engine->state->ctr_drbg);
	}
}
