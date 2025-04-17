// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdint.h>
#include "backend_rsa.h"
#include "platform_api.h"
#include "acvp/acvp_logging.h"
#include "common/unused.h"
#include "crypto/mbedtls_compat.h"
#include "logging/debug_log.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include "mbedtls/rsa.h"
#include "parser/cipher_definitions.h"

/**
 * The current implementation identifier for the ACVP backend.
 */
extern uint32_t acvp_implementation;


/**
 * Execute an RSA KeyGen ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data->n.buf, data->d.buf, data->p.buf, and data->q.buf and all must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_rsa_rsa_keygen (struct rsa_keygen_data *data, flags_t parsed_flags);

/**
 * List of registered RSA engines.
 */
static const struct backend_rsa_engine *rsa_engines = NULL;

/**
 * Number of registered RSA engines.
 */
static size_t rsa_engines_cnt = 0;

/**
 * RSA backend callback structure.
 */
static const struct rsa_backend backend_rsa = {
	.rsa_keygen = backend_rsa_rsa_keygen,
	.rsa_siggen = NULL,
	.rsa_sigver = NULL,
	.rsa_keygen_prime = NULL,
	.rsa_keygen_prov_prime = NULL,
	.rsa_keygen_en = NULL,
	.rsa_free_key = NULL,
	.rsa_signature_primitive = NULL,
	.rsa_decryption_primitive = NULL
};


/**
 * Get the RSA backend callback structure containing the RSA implementations.
 *
 * @return The RSA backend callback structure.
 */
const struct rsa_backend* backend_rsa_get_impl ()
{
	return &backend_rsa;
}

/**
 * Register a list of RSA engines with the RSA backend.  If any RSA engines were previously
 * registered, they will be replaced by the new list of RSA engines.  The engines must remain valid
 * for the lifetime of the RSA backend.
 *
 * @param rsa The list of RSA engines to register.
 * @param num_engines The number of RSA engines in the list.
 */
void backend_rsa_register_engines (const struct backend_rsa_engine *rsa, size_t num_engines)
{
	rsa_engines = rsa;
	rsa_engines_cnt = num_engines;
}

/**
 * Retrieve the RSA engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the RSA engine associated with the given implentation identifier.
 *
 * @return 0 if the RSA engine was found or an error code.
 */
static int backend_rsa_get_engine (int impl_id, const struct backend_rsa_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_RSA_INVALID_ARGUMENT;
	}

	if (rsa_engines == NULL) {
		return BACKEND_RSA_NO_ENGINE;
	}

	for (i = 0; i < rsa_engines_cnt; i++) {
		if (rsa_engines[i].impl_id == impl_id) {
			*engine = &rsa_engines[i];

			return 0;
		}
	}

	return BACKEND_RSA_ENGINE_NOT_FOUND;
}

/**
 * Free the RSA key components.  If any of the given components are null, they will be ignored.
 *
 * @param n The modulus to free.
 * @param p The first prime factor to free.
 * @param q The second prime factor to free.
 * @param d The private exponent to free.
 */
static void backend_rsa_free_key_components (unsigned char **n, unsigned char **p,
	unsigned char **q, unsigned char **d)
{
	if ((n != NULL) && (*n != NULL)) {
		platform_free (*n);
		*n = NULL;
	}

	if ((d != NULL) && (*d != NULL)) {
		platform_free (*d);
		*d = NULL;
	}

	if ((p != NULL) && (*p != NULL)) {
		platform_free (*p);
		*p = NULL;
	}

	if ((q != NULL) && (*q != NULL)) {
		platform_free (*q);
		*q = NULL;
	}
}

static int backend_rsa_rsa_keygen (struct rsa_keygen_data *data, flags_t parsed_flags)
{
	const struct backend_rsa_engine *engine;
	struct rsa_private_key key;
	uint8_t *key_der = NULL;
	size_t key_der_len;
	mbedtls_pk_context *pk_ctx = NULL;
	mbedtls_rsa_context *rsa_ctx = NULL;
	size_t n_len;
	size_t d_len;
	size_t p_len;
	size_t q_len;
	int status;

#if MBEDTLS_IS_VERSION_3
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

	mbedtls_ctr_drbg_init (&ctr_drbg);
	mbedtls_entropy_init (&entropy);
#endif

	UNUSED (parsed_flags);

	if (data == NULL) {
		status = BACKEND_RSA_INVALID_ARGUMENT;
		goto exit;
	}

	if (data->modulus > (RSA_MAX_KEY_LENGTH * 8)) {
		status = BACKEND_RSA_KEY_LEN_TOO_LARGE;
		goto exit;
	}

	if (rsa_engines == NULL) {
		status = BACKEND_RSA_NO_ENGINE;
		goto exit;
	}

	status = backend_rsa_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	/* At this time, random E generation is unsupported.  If a future implementation supports this,
	 * this check can be updated. */
	if (engine->random_e_supported || (data->e.buf == NULL) || (data->e.len == 0)) {
		status = BACKEND_RSA_RANDOM_E_UNSUPPORTED;
		goto exit;
	}

	status = engine->engine->generate_key (engine->engine, &key, data->modulus);
	if (ROT_IS_ERROR (status)) {
		goto exit;
	}

	status = engine->engine->get_private_key_der (engine->engine, &key, &key_der, &key_der_len);
	engine->engine->release_key (engine->engine, &key);
	if ((status != 0) || (key_der == NULL)) {
		goto exit;
	}

	/* Get MbedTLS RSA context to extract the key's components. */
	pk_ctx = platform_malloc (sizeof (mbedtls_pk_context));
	if (pk_ctx == NULL) {
		status = BACKEND_RSA_NO_MEMORY;
		goto exit;
	}

	mbedtls_pk_init (pk_ctx);

	status = mbedtls_pk_setup (pk_ctx, mbedtls_pk_info_from_type (MBEDTLS_PK_RSA));
	if (status != 0) {
		goto exit;
	}

#if MBEDTLS_IS_VERSION_3
	/* Use MbedTLS DRBG.  This has no impact on the implementation being tested and is only used
	 * to parse the generated key. */
	status = mbedtls_ctr_drbg_seed (&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (status != 0) {
		goto exit;
	}

	status = mbedtls_pk_parse_key (pk_ctx, (unsigned char*) key_der, key_der_len, NULL, 0,
		mbedtls_ctr_drbg_random, &ctr_drbg);
	if (status != 0) {
		goto exit;
	}
#else
	status = mbedtls_pk_parse_key (pk_ctx, (unsigned char*) key_der, key_der_len, NULL, 0);
	if (status != 0) {
		goto exit;
	}
#endif

	rsa_ctx = mbedtls_pk_rsa (*pk_ctx);
	if (rsa_ctx == NULL) {
		status = BACKEND_RSA_INVALID_KEY;
		goto exit;
	}

	n_len = mbedtls_mpi_size (&rsa_ctx->MBEDTLS_PRIVATE (N));
	p_len = mbedtls_mpi_size (&rsa_ctx->MBEDTLS_PRIVATE (P));
	q_len = mbedtls_mpi_size (&rsa_ctx->MBEDTLS_PRIVATE (Q));
	d_len = mbedtls_mpi_size (&rsa_ctx->MBEDTLS_PRIVATE (D));

	data->n.buf = platform_malloc (n_len);
	if (data->n.buf == NULL) {
		status = BACKEND_RSA_NO_MEMORY;
		goto exit;
	}
	data->n.len = n_len;

	data->p.buf = platform_malloc (p_len);
	if (data->p.buf == NULL) {
		backend_rsa_free_key_components (&data->n.buf, NULL, NULL, NULL);

		status = BACKEND_RSA_NO_MEMORY;
		goto exit;
	}
	data->p.len = p_len;

	data->q.buf = platform_malloc (q_len);
	if (data->q.buf == NULL) {
		backend_rsa_free_key_components (&data->n.buf, &data->p.buf, NULL, NULL);

		status = BACKEND_RSA_NO_MEMORY;
		goto exit;
	}
	data->q.len = q_len;

	data->d.buf = platform_malloc (d_len);
	if (data->d.buf == NULL) {
		backend_rsa_free_key_components (&data->n.buf, &data->p.buf, &data->q.buf, NULL);

		status = BACKEND_RSA_NO_MEMORY;
		goto exit;
	}
	data->d.len = d_len;

	status = mbedtls_rsa_export_raw (rsa_ctx, data->n.buf, n_len, data->p.buf, p_len, data->q.buf,
		q_len, data->d.buf, d_len, NULL, 0);
	if (status != 0) {
		backend_rsa_free_key_components (&data->n.buf, &data->p.buf, &data->q.buf, &data->d.buf);
	}

exit:
	if (key_der != NULL) {
		platform_free (key_der);
	}

	mbedtls_pk_free (pk_ctx);

	if (pk_ctx != NULL) {
		platform_free (pk_ctx);
	}

#if MBEDTLS_IS_VERSION_3
	mbedtls_ctr_drbg_free (&ctr_drbg);
	mbedtls_entropy_free (&entropy);
#endif

	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

/**
 * Register the RSA backend implementation with the ACVP backend.
 */
void backend_rsa_register_impl (void)
{
	register_rsa_impl ((struct rsa_backend*) &backend_rsa);
}
