// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdbool.h>
#include <stdint.h>
#include "backend_hmac.h"
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
 * Execute an HMAC operation with the given data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.mac.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_hmac_hmac_generate (struct hmac_data *data, flags_t parsed_flags);

/**
 * List of registered HMAC engines.
 */
static const struct backend_hmac_engine *hmac_engines = NULL;

/**
 * Number of registered HMAC engines.
 */
static size_t hmac_engines_cnt = 0;

/**
 * HMAC backend callback structure.
 */
static struct hmac_backend hmac_impl = {
	.hmac_generate = backend_hmac_hmac_generate,
	.cmac_verify = NULL
};


/**
 * Get the HMAC backend callback structure containing the HMAC implementations.
 *
 * @return The HMAC backend callback structure.
 */
struct hmac_backend* backend_hmac_get_impl ()
{
	return &hmac_impl;
}

/**
 * Register a list of HMAC engines with the HMAC backend.  If any HMAC engines were previously
 * registered, they will be replaced by the new list of HMAC engines.  The engines must remain valid
 * for the lifetime of the HMAC backend.
 *
 * @param hmac The list of HMAC engines to register.
 * @param num_engines The number of HMAC engines in the list.
 */
void backend_hmac_register_engines (const struct backend_hmac_engine *hmac, size_t num_engines)
{
	hmac_engines = hmac;
	hmac_engines_cnt = num_engines;
}

/**
 * Retrieve the HMAC engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the HMAC engine associated with the given implentation identifier.
 *
 * @return 0 if the HMAC engine was found or an error code.
 */
static int backend_hmac_get_engine (int impl_id, const struct backend_hmac_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_HMAC_INVALID_ARGUMENT;
	}

	if (hmac_engines == NULL) {
		return BACKEND_HMAC_NO_ENGINE;
	}

	for (i = 0; i < hmac_engines_cnt; i++) {
		if (hmac_engines[i].impl_id == impl_id) {
			*engine = &hmac_engines[i];

			return 0;
		}
	}

	return BACKEND_HMAC_ENGINE_NOT_FOUND;
}

/**
 * Convert the ACVP HMAC hash type to the type used by the HMAC engine.
 *
 * @param acvp_hash_type The ACVP HMAC hash type to convert.
 *
 * @return The hash type used by the hash engine.
 */
static enum hmac_hash backend_hmac_get_hash_type (uint64_t acvp_hash_type)
{
	switch (acvp_hash_type) {
		case ACVP_HMACSHA1:
			return HMAC_SHA1;

		case ACVP_HMACSHA2_256:
			return HMAC_SHA256;

		case ACVP_HMACSHA2_384:
			return HMAC_SHA384;

		case ACVP_HMACSHA2_512:
			return HMAC_SHA512;

		default:
			return HMAC_INVALID;
	}
}

static int backend_hmac_hmac_generate (struct hmac_data *data, flags_t parsed_flags)
{
	const struct backend_hmac_engine *engine;
	enum hmac_hash type;
	size_t mac_len;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->key.buf == NULL) || (data->key.len == 0) ||
		(data->msg.buf == NULL) || (data->msg.len == 0) || (data->mac.buf != NULL) ||
		(data->mac.len != 0)) {
		status = BACKEND_HMAC_INVALID_ARGUMENT;
		goto exit;
	}

	if (hmac_engines == NULL) {
		status = BACKEND_HMAC_NO_ENGINE;
		goto exit;
	}

	status = backend_hmac_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	type = backend_hmac_get_hash_type (data->cipher);
	if (type == HMAC_INVALID) {
		status = BACKEND_HMAC_HASH_TYPE_UNSUPPORTED;
		goto exit;
	}

	mac_len = hash_hmac_get_hmac_length (type);
	if (mac_len == HASH_ENGINE_UNKNOWN_HASH) {
		status = BACKEND_HMAC_HASH_TYPE_UNSUPPORTED;
		goto exit;
	}

	data->mac.buf = platform_malloc (mac_len);
	if (data->mac.buf == NULL) {
		status = BACKEND_HMAC_NO_MEMORY;
		goto exit;
	}
	data->mac.len = mac_len;

	status = hash_generate_hmac (engine->engine, data->key.buf, data->key.len, data->msg.buf,
		data->msg.len, type, data->mac.buf, data->mac.len);
	if (status != 0) {
		platform_free (data->mac.buf);
		data->mac.buf = NULL;
	}

exit:
	if (ROT_IS_ERROR (status)) {
		// On failure, set status to -1 to trigger test failure handling in Acvpparser library. Log
		// error to give more information about the failure.
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_ACVP,
			ACVP_LOGGING_TEST_FAILURE, status, ACVP_ALGORITHM_HMAC);

		status = -1;
	}

	return status;
}

/**
 * Register the HMAC backend implementation with the ACVP backend.
 */
void backend_hmac_register_impl (void)
{
	register_hmac_impl (&hmac_impl);
}
