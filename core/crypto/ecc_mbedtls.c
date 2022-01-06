// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include "platform.h"
#include "ecc_mbedtls.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/bignum.h"
#include "logging/debug_log.h"
#include "crypto/crypto_logging.h"
#include "crypto/hash.h"
#include "common/unused.h"

/**
 * Get the mbedTLS ECC key pair instance for a public or private key instance.
 *
 * @return The mbedTLS ECC key pair.
 */
#define	ecc_mbedtls_get_ec_key_pair(x)	mbedtls_pk_ec (*((mbedtls_pk_context*) x->context))


/**
 * Allocate and initialize a context for an ECC key.
 *
 * @return The initialized key context or null.
 */
static mbedtls_pk_context* ecc_mbedtls_alloc_key_context ()
{
	mbedtls_pk_context *key = platform_malloc (sizeof (mbedtls_pk_context));

	if (key != NULL) {
		mbedtls_pk_init (key);
	}

	return key;
}

/**
 * Zeroize an ECC key context and free the memory.
 *
 * @param context The context to free.
 */
static void ecc_mbedtls_free_key_context (void *context)
{
	mbedtls_pk_free ((mbedtls_pk_context*) context);
	platform_free (context);
}

/**
 * Initialize a public key instance from a private key.
 *
 * @param key The private key instance to covert to a public key.
 * @param dup Flag indicating if a new key instance should be created for the public key.
 * @param error The error code for the operation.
 *
 * @return The public key instance or null if there was an error.
 */
static mbedtls_pk_context* ecc_mbedtls_convert_private_to_public (mbedtls_pk_context *key, bool dup,
	int *error)
{
	mbedtls_pk_context *pub = key;
	mbedtls_ecp_keypair *priv_ec;
	mbedtls_ecp_keypair *pub_ec;
	uint8_t msg_code;
	int status;

	if (dup) {
		pub = ecc_mbedtls_alloc_key_context ();
		if (pub == NULL) {
			status = ECC_ENGINE_NO_MEMORY;
			goto error_alloc;
		}

		status = mbedtls_pk_setup (pub, mbedtls_pk_info_from_type (MBEDTLS_PK_ECKEY));
		if (status != 0) {
			msg_code = CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC;
			goto error_exit;
		}

		priv_ec = mbedtls_pk_ec (*key);
		pub_ec = mbedtls_pk_ec (*pub);

		status = mbedtls_ecp_group_copy (&pub_ec->grp, &priv_ec->grp);
		if (status != 0) {
			msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_COPY_EC;
			goto error_exit;
		}

		status = mbedtls_ecp_copy (&pub_ec->Q, &priv_ec->Q);
		if (status != 0) {
			msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_COPY_EC;
			goto error_exit;
		}

		status = mbedtls_ecp_check_pub_priv (pub_ec, priv_ec);
		if (status != 0) {
			msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_CHECK_PUB_PRV_EC;
			goto error_exit;
		}
	}
	else {
		pub_ec = mbedtls_pk_ec (*pub);
		mbedtls_mpi_free (&pub_ec->d);
	}

	*error = 0;
	return pub;

error_exit:
	ecc_mbedtls_free_key_context (pub);
	*error = status;

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
		msg_code, status, 0);
error_alloc:
	return NULL;
}

static int ecc_mbedtls_init_key_pair (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	mbedtls_pk_context *key_ctx;
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

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_parse_key (key_ctx, key, key_length, NULL, 0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_EC, status, 0);

		goto error;
	}

	if (mbedtls_pk_get_type (key_ctx) != MBEDTLS_PK_ECKEY) {
		status = ECC_ENGINE_NOT_EC_KEY;
		goto error;
	}

	if (pub_key) {
		pub_key->context = ecc_mbedtls_convert_private_to_public (key_ctx, (priv_key), &status);
		if (pub_key->context == NULL) {
			goto error;
		}
	}

	if (priv_key) {
		priv_key->context = key_ctx;
	}

	return 0;

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}

static int ecc_mbedtls_init_public_key (struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key)
{
	mbedtls_pk_context *key_ctx;
	int status;

	if ((engine == NULL) || (key == NULL) || (key_length == 0) || (pub_key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (pub_key, 0, sizeof (struct ecc_public_key));

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_parse_public_key (key_ctx, key, key_length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_PARSE_PUB_EC, status, 0);

		goto error;
	}

	if (mbedtls_pk_get_type (key_ctx) != MBEDTLS_PK_ECKEY) {
		status = ECC_ENGINE_NOT_EC_KEY;
		goto error;
	}

	pub_key->context = key_ctx;

	return 0;

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_mbedtls_generate_derived_key_pair (struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_pk_context *key_ctx;
	mbedtls_ecp_keypair *ec;
	mbedtls_ecp_group_id curve;
	uint8_t msg_code;
	int status;

	if ((mbedtls == NULL) || (priv == NULL) || (key_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			curve = MBEDTLS_ECP_DP_SECP256R1;
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			curve = MBEDTLS_ECP_DP_SECP384R1;
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			curve = MBEDTLS_ECP_DP_SECP521R1;
			break;
#endif
#endif

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_setup (key_ctx, mbedtls_pk_info_from_type (MBEDTLS_PK_ECKEY));
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC;
		goto error_log;
	}

	ec = mbedtls_pk_ec (*key_ctx);

	status = mbedtls_ecp_group_load (&ec->grp, curve);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_GROUP_LOAD_EC;
		goto error_log;
	}

	status = mbedtls_mpi_read_binary (&ec->d, priv, key_length);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_MPI_READ_BIN_EC;
		goto error_log;
	}

	status = mbedtls_ecp_mul (&ec->grp, &ec->Q, &ec->d, &ec->grp.G, mbedtls_ctr_drbg_random,
		&mbedtls->ctr_drbg);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_MUL_EC;
		goto error_log;
	}

	status = mbedtls_ecp_check_privkey (&ec->grp, &ec->d);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_CHECK_PUB_PRV_EC;
		goto error_log;
	}

	if (pub_key) {
		pub_key->context = ecc_mbedtls_convert_private_to_public (key_ctx, (priv_key), &status);
		if (pub_key->context == NULL) {
			goto error;
		}
	}

	if (priv_key) {
		priv_key->context = key_ctx;
	}

	return 0;

error_log:
	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO, msg_code, status,
		0);

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}

static int ecc_mbedtls_generate_key_pair (struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_pk_context *key_ctx;
	mbedtls_ecp_keypair *ec;
	mbedtls_ecp_group_id curve;
	uint8_t msg_code;
	int status;

	if (mbedtls == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (!priv_key && !pub_key) {
		return 0;
	}

	switch (key_length) {
		case ECC_KEY_LENGTH_256:
			curve = MBEDTLS_ECP_DP_SECP256R1;
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
		case ECC_KEY_LENGTH_384:
			curve = MBEDTLS_ECP_DP_SECP384R1;
			break;

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
		case ECC_KEY_LENGTH_521:
			curve = MBEDTLS_ECP_DP_SECP521R1;
			break;
#endif
#endif

		default:
			return ECC_ENGINE_UNSUPPORTED_KEY_LENGTH;
	}

	if (priv_key) {
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}
	if (pub_key) {
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}

	key_ctx = ecc_mbedtls_alloc_key_context ();
	if (key_ctx == NULL) {
		return ECC_ENGINE_NO_MEMORY;
	}

	status = mbedtls_pk_setup (key_ctx, mbedtls_pk_info_from_type (MBEDTLS_PK_ECKEY));
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_PK_INIT_EC;
		goto error_log;
	}

	ec = mbedtls_pk_ec (*key_ctx);
	status = mbedtls_ecp_gen_key (curve, ec, mbedtls_ctr_drbg_random,
		&mbedtls->ctr_drbg);
	if (status != 0) {
		msg_code = CRYPTO_LOG_MSG_MBEDTLS_ECP_GEN_KEY_EC;
		goto error_log;
	}

	if (pub_key) {
		pub_key->context = ecc_mbedtls_convert_private_to_public (key_ctx, (priv_key), &status);
		if (pub_key->context == NULL) {
			goto error;
		}
	}

	if (priv_key) {
		priv_key->context = key_ctx;
	}

	return 0;

error_log:
	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO, msg_code, status,
		0);

error:
	ecc_mbedtls_free_key_context (key_ctx);
	return status;
}
#endif

static void ecc_mbedtls_release_key_pair (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key)
{
	UNUSED (engine);

	if (priv_key) {
		ecc_mbedtls_free_key_context (priv_key->context);
		memset (priv_key, 0, sizeof (struct ecc_private_key));
	}

	if (pub_key) {
		ecc_mbedtls_free_key_context (pub_key->context);
		memset (pub_key, 0, sizeof (struct ecc_public_key));
	}
}

static int ecc_mbedtls_get_signature_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	size_t key_len;

	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	key_len = mbedtls_pk_get_len ((mbedtls_pk_context*) key->context);
	return (((key_len + 3) * 2) + ((key_len > 61) ? 3 : 2));
}

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
static int ecc_mbedtls_get_private_key_der (struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length)
{
	uint8_t tmp_der[29 + (3 * MBEDTLS_ECP_MAX_BYTES)];
	int status;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (ecc_mbedtls_get_ec_key_pair (key)->d.n == 0) {
		return ECC_ENGINE_NOT_PRIVATE_KEY;
	}

	status = mbedtls_pk_write_key_der ((mbedtls_pk_context*) key->context, tmp_der,
		sizeof (tmp_der));
	if (status >= 0) {
		*der = platform_malloc (status);
		if (*der == NULL) {
			return ECC_ENGINE_NO_MEMORY;
		}

		memcpy (*der, &tmp_der[sizeof (tmp_der) - status], status);
		*length = status;
		status = 0;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_KEY_DER_EC, status, 0);
	}

	return status;
}

static int ecc_mbedtls_get_public_key_der (struct ecc_engine *engine,
	const struct ecc_public_key *key, uint8_t **der, size_t *length)
{
	uint8_t tmp_der[30 + (2 * MBEDTLS_ECP_MAX_BYTES)];
	int status;

	if (der == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	*der = NULL;
	if ((engine == NULL) || (key == NULL) || (length == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if (ecc_mbedtls_get_ec_key_pair (key)->d.n != 0) {
		return ECC_ENGINE_NOT_PUBLIC_KEY;
	}

	status = mbedtls_pk_write_pubkey_der ((mbedtls_pk_context*) key->context, tmp_der,
		sizeof (tmp_der));
	if (status >= 0) {
		*der = platform_malloc (status);
		if (*der == NULL) {
			return ECC_ENGINE_NO_MEMORY;
		}

		memcpy (*der, &tmp_der[sizeof (tmp_der) - status], status);
		*length = status;
		status = 0;
	}
	else {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_WRITE_PUBKEY_DER_EC, status, 0);
	}

	return status;
}
#endif

static int ecc_mbedtls_sign (struct ecc_engine *engine, struct ecc_private_key *key,
	const uint8_t *digest, size_t length, uint8_t *signature, size_t sig_length)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_ecp_keypair *ec;
	mbedtls_md_type_t hash_alg;
	int status;

	if ((mbedtls == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	if ((int) sig_length < ecc_mbedtls_get_signature_max_length (engine, key)) {
		return ECC_ENGINE_SIG_BUFFER_TOO_SMALL;
	}

	switch (length) {
		case SHA256_HASH_LENGTH:
			hash_alg = MBEDTLS_MD_SHA256;
			break;

		case SHA384_HASH_LENGTH:
			hash_alg = MBEDTLS_MD_SHA384;
			break;

		case SHA512_HASH_LENGTH:
			hash_alg = MBEDTLS_MD_SHA512;
			break;

		default:
			return ECC_ENGINE_UNSUPPORTED_HASH_TYPE;
	}

	ec = ecc_mbedtls_get_ec_key_pair (key);
	status = mbedtls_ecp_check_privkey (&ec->grp, &ec->d);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_ECP_CHECK_PUB_PRV_EC, status, 0);

		return status;
	}

	status = mbedtls_pk_sign ((mbedtls_pk_context*) key->context, hash_alg, digest, length,
		signature, &sig_length, mbedtls_ctr_drbg_random, &mbedtls->ctr_drbg);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_SIGN_EC, status, 0);
	}

	return (status == 0) ? (int) sig_length : status;
}

static int ecc_mbedtls_verify (struct ecc_engine *engine, struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length)
{
	int status;

	if ((engine == NULL) || (key == NULL) || (digest == NULL) || (signature == NULL) ||
		(length == 0) || (sig_length == 0)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	status = mbedtls_pk_verify ((mbedtls_pk_context*) key->context, MBEDTLS_MD_NONE, digest,
		length, signature, sig_length);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_PK_VERIFY_EC, status, 0);

		if ((status == MBEDTLS_ERR_MPI_ALLOC_FAILED) ||
			(status == (MBEDTLS_ERR_MPI_ALLOC_FAILED + MBEDTLS_ERR_ECP_BAD_INPUT_DATA))) {
			return ECC_ENGINE_NO_MEMORY;
		}
		else {
			return ECC_ENGINE_BAD_SIGNATURE;
		}
	}

	return status;
}

#ifdef ECC_ENABLE_ECDH
static int ecc_mbedtls_get_shared_secret_max_length (struct ecc_engine *engine,
	struct ecc_private_key *key)
{
	int status;

	if ((engine == NULL) || (key == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	status = mbedtls_pk_get_len ((mbedtls_pk_context*) key->context);
	if (status == 0) {
		return ECC_ENGINE_SECRET_LENGTH_FAILED;
	}

	return status;
}

static int ecc_mbedtls_compute_shared_secret (struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length)
{
	struct ecc_engine_mbedtls *mbedtls = (struct ecc_engine_mbedtls*) engine;
	mbedtls_ecp_keypair *priv_ec;
	mbedtls_ecp_keypair *pub_ec;
	mbedtls_mpi out;
	size_t out_len;
	int secret_len;
	int status;

	if ((mbedtls == NULL) || (priv_key == NULL) || (pub_key == NULL) || (secret == NULL)) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	secret_len = ecc_mbedtls_get_shared_secret_max_length (engine, priv_key);
	if (ROT_IS_ERROR (secret_len)) {
		return secret_len;
	}
	if (length < (size_t) secret_len) {
		return ECC_ENGINE_SECRET_BUFFER_TOO_SMALL;
	}

	priv_ec = ecc_mbedtls_get_ec_key_pair (priv_key);
	pub_ec = ecc_mbedtls_get_ec_key_pair (pub_key);

	mbedtls_mpi_init (&out);
	status = mbedtls_ecdh_compute_shared (&priv_ec->grp, &out, &pub_ec->Q, &priv_ec->d,
		mbedtls_ctr_drbg_random, &mbedtls->ctr_drbg);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_ECDH_COMPUTE_SHARED_SECRET_EC, status, 0);

		goto error;
	}

	out_len = mbedtls_mpi_size (&out);
	if (out_len > (size_t) secret_len) {
		status = ECC_ENGINE_SECRET_BUFFER_TOO_SMALL;
		goto error;
	}

	memset (secret, 0, length);
	mbedtls_mpi_write_binary (&out, &secret[secret_len - out_len], out_len);
	mbedtls_mpi_free (&out);

	return secret_len;

error:
	mbedtls_mpi_free (&out);
	return status;
}
#endif

/**
 * Initialize an instance for running ECC operations using mbedTLS.
 *
 * @param engine The ECC engine to initialize.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int ecc_mbedtls_init (struct ecc_engine_mbedtls *engine)
{
	int status;

	if (engine == NULL) {
		return ECC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct ecc_engine_mbedtls));

	mbedtls_ctr_drbg_init (&engine->ctr_drbg);
	mbedtls_entropy_init (&engine->entropy);

	status = mbedtls_ctr_drbg_seed (&engine->ctr_drbg, mbedtls_entropy_func, &engine->entropy, NULL,
		0);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_CTR_DRBG_SEED_EC, status, 0);

		goto exit;
	}

	engine->base.init_key_pair = ecc_mbedtls_init_key_pair;
	engine->base.init_public_key = ecc_mbedtls_init_public_key;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.generate_derived_key_pair = ecc_mbedtls_generate_derived_key_pair;
	engine->base.generate_key_pair = ecc_mbedtls_generate_key_pair;
#endif
	engine->base.release_key_pair = ecc_mbedtls_release_key_pair;
	engine->base.get_signature_max_length = ecc_mbedtls_get_signature_max_length;
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	engine->base.get_private_key_der = ecc_mbedtls_get_private_key_der;
	engine->base.get_public_key_der = ecc_mbedtls_get_public_key_der;
#endif
	engine->base.sign = ecc_mbedtls_sign;
	engine->base.verify = ecc_mbedtls_verify;
#ifdef ECC_ENABLE_ECDH
	engine->base.get_shared_secret_max_length = ecc_mbedtls_get_shared_secret_max_length;
	engine->base.compute_shared_secret = ecc_mbedtls_compute_shared_secret;
#endif

	return 0;

exit:
	mbedtls_entropy_free (&engine->entropy);
	mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	return status;
}

/**
 * Release an mbedTLS ECC engine.
 *
 * @param engine The ECC engine to release.
 */
void ecc_mbedtls_release (struct ecc_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_entropy_free (&engine->entropy);
		mbedtls_ctr_drbg_free (&engine->ctr_drbg);
	}
}
