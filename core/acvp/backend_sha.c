// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdint.h>
#include "backend_sha.h"
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
 * Execute a hash generate ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.mac.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_sha_hash_generate (struct sha_data *data, flags_t parsed_flags);

/**
 * List of registered SHA engines.
 */
static const struct backend_sha_engine *sha_engines = NULL;

/**
 * Number of registered SHA engines.
 */
static size_t sha_engines_cnt = 0;

/**
 * SHA backend callback structure.
 *
 * TODO:  Implement hash_mct_inner_loop support.
 */
static const struct sha_backend sha_impl = {
	.hash_generate = backend_sha_hash_generate,
	.hash_mct_inner_loop = NULL
};


/**
 * Get the SHA backend callback structure containing the SHA implementations.
 *
 * @return The SHA backend callback structure.
 */
const struct sha_backend* backend_sha_get_impl ()
{
	return &sha_impl;
}

/**
 * Register a list of SHA engines with the SHA backend.  If any SHA engines were previously
 * registered, they will be replaced by the new list of SHA engines.  The engines must remain valid
 * for the lifetime of the SHA backend.
 *
 * @param sha The list of SHA engines to register.
 * @param num_engines The number of SHA engines in the list.
 */
void backend_sha_register_engines (const struct backend_sha_engine *sha, size_t num_engines)
{
	sha_engines = sha;
	sha_engines_cnt = num_engines;
}

/**
 * Retrieve the SHA engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the SHA engine associated with the given implentation identifier.
 *
 * @return 0 if the SHA engine was found or an error code.
 */
static int backend_sha_get_engine (int impl_id, const struct backend_sha_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_SHA_INVALID_ARGUMENT;
	}

	if (sha_engines == NULL) {
		return BACKEND_SHA_NO_ENGINE;
	}

	for (i = 0; i < sha_engines_cnt; i++) {
		if (sha_engines[i].impl_id == impl_id) {
			*engine = &sha_engines[i];

			return 0;
		}
	}

	return BACKEND_SHA_ENGINE_NOT_FOUND;
}

/**
 * Convert the ACVP hash type to the type used by the hash engine.
 *
 * @param acvp_hash_type The ACVP hash type to convert.
 *
 * @return The hash type used by the hash engine.
 */
static enum hash_type backend_sha_get_hash_type (uint64_t acvp_hash_type)
{
	switch (acvp_hash_type) {
		case ACVP_SHA1:
			return HASH_TYPE_SHA1;

		case ACVP_SHA256:
			return HASH_TYPE_SHA256;

		case ACVP_SHA384:
			return HASH_TYPE_SHA384;

		case ACVP_SHA512:
			return HASH_TYPE_SHA512;

		default:
			return HASH_TYPE_INVALID;
	}
}

static int backend_sha_hash_generate (struct sha_data *data, flags_t parsed_flags)
{
	uint8_t hash_out[HASH_MAX_HASH_LEN];
	const struct backend_sha_engine *engine;
	enum hash_type type;
	int hash_out_len;
	int status;

	UNUSED (parsed_flags);

	if (data == NULL) {
		status = BACKEND_SHA_INVALID_ARGUMENT;
		goto exit;
	}

	if (sha_engines == NULL) {
		status = BACKEND_SHA_NO_ENGINE;
		goto exit;
	}

	status = backend_sha_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	type = backend_sha_get_hash_type (data->cipher);

	if (engine->is_one_shot) {
		status = hash_calculate (engine->engine, type, (uint8_t*) data->msg.buf, data->msg.len,
			hash_out, sizeof (hash_out));
		if (ROT_IS_ERROR (status)) {
			goto exit;
		}

		hash_out_len = status;
	}
	else {
		status = hash_start_new_hash (engine->engine, type);
		if (status != 0) {
			goto exit;
		}

		status = engine->engine->update (engine->engine, (uint8_t*) data->msg.buf, data->msg.len);
		if (status != 0) {
			goto cancel;
		}

		status = engine->engine->finish (engine->engine, hash_out, sizeof (hash_out));
		if (status != 0) {
			goto cancel;
		}

		hash_out_len = hash_get_hash_length (type);
	}

	if (hash_out_len != hash_get_hash_length (type)) {
		status = BACKEND_SHA_UNEXPECTED_HASH_LENGTH;
		goto exit;
	}

	data->mac.buf = platform_malloc (hash_out_len);
	if (data->mac.buf == NULL) {
		status = BACKEND_SHA_NO_MEMORY;
		goto exit;
	}
	memcpy (data->mac.buf, hash_out, hash_out_len);
	data->mac.len = hash_out_len;

	return 0;

cancel:
	if (engine->engine) {
		engine->engine->cancel (engine->engine);
	}

exit:
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
 * Register the SHA backend implementation with the ACVP backend.
 */
void backend_sha_register_impl (void)
{
	register_sha_impl ((struct sha_backend*) &sha_impl);
}
