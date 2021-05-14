// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "rsa_mbedtls.h"
#include "platform.h"
#include "mbedtls/pk.h"
#include "mbedtls/pk_internal.h"
#include "mbedtls/rsa.h"
#include "logging/debug_log.h"
#include "crypto_logging.h"


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
static int rsa_mbedtls_generate_key (struct rsa_engine *engine, struct rsa_private_key *key,
	int bits)
{
	struct rsa_engine_mbedtls *mbedtls = (struct rsa_engine_mbedtls*) engine;
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

	status = mbedtls_rsa_gen_key (mbedtls_pk_rsa (*rsa), mbedtls_ctr_drbg_random,
		&mbedtls->ctr_drbg, bits, 65537);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_RSA_GEN_KEY_EC;
		goto error;
	}

	mbedtls_rsa_set_padding (mbedtls_pk_rsa (*rsa), MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1);
	key->context = rsa;

	return 0;

error:
	rsa_mbedtls_free_key_context (rsa);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
		msg_code, status, 0);
	return status;
}

static int rsa_mbedtls_init_private_key (struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length)
{
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

	status = mbedtls_pk_parse_key (rsa, der, length, NULL, 0);
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

static void rsa_mbedtls_release_key (struct rsa_engine *engine, struct rsa_private_key *key)
{
	if (engine && key) {
		rsa_mbedtls_free_key_context (key->context);
	}
}

static int rsa_mbedtls_get_private_key_der (struct rsa_engine *engine,
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

static int rsa_mbedtls_decrypt (struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length)
{
	struct rsa_engine_mbedtls *mbedtls = (struct rsa_engine_mbedtls*) engine;
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

	status = mbedtls_rsa_rsaes_oaep_decrypt (rsa_mbedtls_get_rsa_key (key), mbedtls_ctr_drbg_random,
		&mbedtls->ctr_drbg, MBEDTLS_RSA_PRIVATE, label, label_length, &length, encrypted, decrypted,
		out_length);
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
#endif

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
static int rsa_mbedtls_init_public_key (struct rsa_engine *engine, struct rsa_public_key *key,
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

	rsa = (mbedtls_rsa_context*) pk->pk_ctx;

	status = mbedtls_rsa_check_pubkey (rsa);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC, status, 0);
		goto exit;
	}

	key->mod_length = mbedtls_mpi_size (&rsa->N);
	if (key->mod_length > sizeof (key->modulus)) {
		status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
		goto exit;
	}

	status = mbedtls_mpi_write_binary (&rsa->N, key->modulus, key->mod_length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_MPI_WRITE_BIN_EC, status, 0);
		goto exit;
	}

	status = mbedtls_mpi_write_binary (&rsa->E, exp, sizeof (exp));
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_MPI_WRITE_BIN_EC, status, 0);
		if (status == MBEDTLS_ERR_MPI_BUFFER_TOO_SMALL) {
			status = RSA_ENGINE_UNSUPPORTED_KEY_LENGTH;
		}
		goto exit;
	}

	key->exponent = (exp[0] << 24) | (exp[1] << 16) | (exp[2] << 8) | exp[3];

exit:
	rsa_mbedtls_free_key_context (pk);
	return status;
}

static int rsa_mbedtls_get_public_key_der (struct rsa_engine *engine,
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
	uint8_t msg_code;

	mbedtls_rsa_init (rsa, MBEDTLS_RSA_PKCS_V15, 0);

	exp[0] = key->exponent >> 24;
	exp[1] = key->exponent >> 16;
	exp[2] = key->exponent >> 8;
	exp[3] = key->exponent;

	status = mbedtls_mpi_read_binary (&rsa->N, key->modulus, key->mod_length);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC;
		goto exit;
	}

	status = mbedtls_mpi_read_binary (&rsa->E, exp, sizeof (exp));
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC;
		goto exit;
	}

	rsa->len = mbedtls_mpi_size (&rsa->N);

	status = mbedtls_rsa_check_pubkey (rsa);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_CHECK_EC;
		goto exit;
	}

	return 0;

exit:
	mbedtls_rsa_free (rsa);

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
		msg_code, status, 0);
	return status;
}

static int rsa_mbedtls_sig_verify (struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, const uint8_t *match, size_t match_length)
{
	mbedtls_rsa_context rsa;
	int status;

	if ((engine == NULL) || (key == NULL) || (signature == NULL) || (match == NULL) ||
		(sig_length == 0) || (match_length == 0)) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	status = rsa_mbedtls_load_pubkey (&rsa, key);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_RSA_PUBKEY_LOAD_EC, status, 0);
		return status;
	}

	status = mbedtls_rsa_pkcs1_verify (&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256,
		match_length, match, signature);
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
 * @param engine The RSA engine to initialize.
 *
 * @return 0 if the RSA engine was successfully initialize or an error code.
 */
int rsa_mbedtls_init (struct rsa_engine_mbedtls *engine)
{
	int status;

	if (engine == NULL) {
		return RSA_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct rsa_engine_mbedtls));

	mbedtls_ctr_drbg_init (&engine->ctr_drbg);
	mbedtls_entropy_init (&engine->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->ctr_drbg, mbedtls_entropy_func, &engine->entropy, NULL,
		0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC, status, 0);
		goto exit;
	}

#ifdef RSA_ENABLE_PRIVATE_KEY
	engine->base.generate_key = rsa_mbedtls_generate_key;
	engine->base.init_private_key = rsa_mbedtls_init_private_key;
	engine->base.release_key = rsa_mbedtls_release_key;
	engine->base.get_private_key_der = rsa_mbedtls_get_private_key_der;
	engine->base.decrypt = rsa_mbedtls_decrypt;
#endif
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	engine->base.init_public_key = rsa_mbedtls_init_public_key;
	engine->base.get_public_key_der = rsa_mbedtls_get_public_key_der;
#endif
	engine->base.sig_verify = rsa_mbedtls_sig_verify;

	return 0;

exit:
	mbedtls_entropy_free (&engine->entropy);
	mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	return status;
}

/**
 * Release the resources used by an mbedTLS RSA engine.
 *
 * @param engine The RSA engine to release.
 */
void rsa_mbedtls_release (struct rsa_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_entropy_free (&engine->entropy);
		mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	}
}
