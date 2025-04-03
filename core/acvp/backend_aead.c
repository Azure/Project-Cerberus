// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stdint.h>
#include "backend_aead.h"
#include "platform_api.h"
#include "acvp/acvp_logging.h"
#include "common/unused.h"
#include "logging/debug_log.h"
#include "parser/cipher_definitions.h"

/**
 * The current implementation identifier for the ACVP backend.
 */
extern uint32_t acvp_implementation;


/**
 * Execute an AES-GCM encrypt ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.
 *   - If data.iv.buf is NULL on input, then it will be allocated and must be freed by the caller.
 *   - data.tag.buf must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_aead_gcm_encrypt (struct aead_data *data, flags_t parsed_flags);

/**
 * Execute an AES-GCM decrypt ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_aead_gcm_decrypt (struct aead_data *data, flags_t parsed_flags);

/**
 * List of registered AEAD engines.
 */
static const struct backend_aead_engine *aead_engines = NULL;

/**
 * Number of registered AEAD engines.
 */
static size_t aead_engines_cnt = 0;

/**
 * AEAD backend callback structure.
 */
static struct aead_backend aead_impl = {
	.gcm_encrypt = backend_aead_gcm_encrypt,
	.gcm_decrypt = backend_aead_gcm_decrypt,
	.ccm_encrypt = NULL,
	.ccm_decrypt = NULL
};


/**
 * Get the AEAD backend callback structure containing the AEAD implementations.
 *
 * @return The AEAD backend callback structure.
 */
struct aead_backend* backend_aead_get_impl ()
{
	return &aead_impl;
}

/**
 * Register a list of AEAD engines with the AEAD backend.  If any AEAD engines were previously
 * registered, they will be replaced by the new list of AEAD engines.  The engines must remain valid
 * for the lifetime of the AEAD backend.
 *
 * @param aead The list of AEAD engines to register.
 * @param num_engines The number of AEAD engines in the list.
 */
void backend_aead_register_engines (const struct backend_aead_engine *aead, size_t num_engines)
{
	aead_engines = aead;
	aead_engines_cnt = num_engines;
}

/**
 * Retrieve the AEAD engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the AEAD engine associated with the given implentation identifier.
 *
 * @return 0 if the AEAD engine was found or an error code.
 */
static int backend_aead_get_engine (int impl_id, const struct backend_aead_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_AEAD_INVALID_ARGUMENT;
	}

	if (aead_engines == NULL) {
		return BACKEND_AEAD_NO_ENGINE;
	}

	for (i = 0; i < aead_engines_cnt; i++) {
		if (aead_engines[i].impl_id == impl_id) {
			*engine = &aead_engines[i];

			return 0;
		}
	}

	return BACKEND_AEAD_ENGINE_NOT_FOUND;
}

static int backend_aead_gcm_encrypt (struct aead_data *data, flags_t parsed_flags)
{
	const struct backend_aead_engine *engine;
	size_t iv_len_bytes;
	size_t tag_len_bytes;
	bool iv_gen;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->key.buf == NULL) ||
		((data->iv.buf == NULL) && (data->ivlen == 0)) || (data->tag.buf != NULL) ||
		(data->taglen != (AES_GCM_TAG_LENGTH * 8)) || (data->data.buf == NULL)) {
		status = BACKEND_AEAD_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_aead_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	// If data->iv is NULL, but data->ivlen is not 0, then use internal IV generation to generate
	// an IV of length data->ivlen (in bits). Allocate data->iv.buf and set appropriately.
	iv_gen = (data->iv.buf == NULL);

	if (iv_gen) {
		if (engine->rng == NULL) {
			status = BACKEND_AEAD_NO_RNG;
			goto exit;
		}

		iv_len_bytes = (data->ivlen + 7) / 8;

		data->iv.buf = platform_malloc (iv_len_bytes);
		if (data->iv.buf == NULL) {
			status = BACKEND_AEAD_NO_MEMORY;
			goto exit;
		}
		data->iv.len = iv_len_bytes;

		status = engine->rng->generate_random_buffer (engine->rng, iv_len_bytes, data->iv.buf);
		if (status != 0) {
			goto release;
		}
	}

	status = engine->gcm_engine->set_key (engine->gcm_engine, data->key.buf, data->key.len);
	if (status != 0) {
		goto release;
	}

	// data->tag.buf is NULL for encryption. The backend must allocate the buffer of the size given
	// by data->taglen (in bits). This buffer is released by the caller.
	tag_len_bytes = (data->taglen + 7) / 8;
	data->tag.buf = platform_malloc (tag_len_bytes);
	if (data->tag.buf == NULL) {
		status = BACKEND_AEAD_NO_MEMORY;
		goto release;
	}
	data->tag.len = tag_len_bytes;

	status = engine->gcm_engine->encrypt_with_add_data (engine->gcm_engine, data->data.buf,
		data->data.len, data->iv.buf, data->iv.len, data->assoc.buf, data->assoc.len,
		data->data.buf, data->data.len, data->tag.buf, data->tag.len);

release:
	if (status != 0) {
		if (iv_gen) {
			platform_free (data->iv.buf);
			data->iv.buf = NULL;
		}

		if (data->tag.buf != NULL) {
			platform_free (data->tag.buf);
			data->tag.buf = NULL;
		}
	}

exit:
	if (status != 0) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

static int backend_aead_gcm_decrypt (struct aead_data *data, flags_t parsed_flags)
{
	const struct backend_aead_engine *engine;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->key.buf == NULL) || (data->iv.buf == NULL) ||
		(data->tag.buf == NULL) || (data->tag.len != AES_GCM_TAG_LENGTH) ||
		(data->data.buf == NULL)) {
		status = BACKEND_AEAD_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_aead_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = engine->gcm_engine->set_key (engine->gcm_engine, data->key.buf, data->key.len);
	if (status != 0) {
		goto exit;
	}

	status = engine->gcm_engine->decrypt_with_add_data (engine->gcm_engine, data->data.buf,
		data->data.len, data->tag.buf, data->iv.buf, data->iv.len, data->assoc.buf, data->assoc.len,
		data->data.buf, data->data.len);

	// Set data->integrity_error if integrity error occurred. In this case, the returned status
	// should indicate success.
	if (status == AES_GCM_ENGINE_GCM_AUTH_FAILED) {
		data->integrity_error = 1;
		status = 0;
	}
	else {
		data->integrity_error = 0;
	}

exit:
	if (status != 0) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, 0);

		status = -1;
	}

	return status;
}

/**
 * Register the AEAD backend implementation with the ACVP backend.
 */
void backend_aead_register_impl (void)
{
	register_aead_impl (&aead_impl);
}
