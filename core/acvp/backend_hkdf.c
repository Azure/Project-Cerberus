// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdint.h>
#include "backend_hkdf.h"
#include "platform_api.h"
#include "acvp/acvp_logging.h"
#include "common/buffer_util.h"
#include "common/unused.h"
#include "crypto/hash.h"
#include "logging/debug_log.h"
#include "parser/cipher_definitions.h"

/**
 * The current implementation identifier for the ACVP backend.
 */
extern uint32_t acvp_implementation;


/**
 * Execute an RFC5869 HMAC-based key derivation function (HKDF) test using the provided data.
 *
 * @param data The container for the parsed test input and test output.  If data.dkm is NULL on
 * input, then the derived key material output is stored in data.dkm and must be freed by the
 * caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_hkdf_hkdf (struct hkdf_data *data, flags_t parsed_flags);

/**
 * List of registered HKDR engines.
 */
static const struct backend_hkdf_engine *hkdf_engines = NULL;

/**
 * Number of registered HKDR engines.
 */
static size_t hkdf_engines_cnt = 0;

/**
 * HKDF backend callback structure.
 */
static const struct hkdf_backend hkdf_impl = {
	.hkdf = backend_hkdf_hkdf
};


/**
 * Get the HKDF backend callback structure containing the HKDF implementations.
 *
 * @return The HKDF backend callback structure.
 */
const struct hkdf_backend* backend_hkdf_get_impl ()
{
	return &hkdf_impl;
}

/**
 * Register a list of HKDF engines with the HKDF backend.  If any HKDF engines were previously
 * registered, they will be replaced by the new list of HKDF engines.  The engines must remain valid
 * for the lifetime of the HKDF backend.
 *
 * @param hkdf The list of HKDF engines to register.
 * @param num_engines The number of HKDF engines in the list.
 */
void backend_hkdf_register_engines (const struct backend_hkdf_engine *hkdf,	size_t num_engines)
{
	hkdf_engines = hkdf;
	hkdf_engines_cnt = num_engines;
}

/**
 * Retrieve the HKDF engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the HKDF engine associated with the given implentation identifier.
 *
 * @return 0 if the HKDF engine was found or an error code.
 */
static int backend_hkdf_get_engine (int impl_id, const struct backend_hkdf_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_HKDF_INVALID_ARGUMENT;
	}

	if (hkdf_engines == NULL) {
		return BACKEND_HKDF_NO_ENGINE;
	}

	for (i = 0; i < hkdf_engines_cnt; i++) {
		if (hkdf_engines[i].impl_id == impl_id) {
			*engine = &hkdf_engines[i];

			return 0;
		}
	}

	return BACKEND_HKDF_ENGINE_NOT_FOUND;
}

/**
 * Convert the ACVP hash type to the type used by the hash engine.
 *
 * @param acvp_hash_type The ACVP hash type to convert.
 *
 * @return The hash type used by the hash engine.
 */
static enum hash_type backend_hkdf_get_hash_type (uint64_t acvp_hash_type)
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

static int backend_hkdf_hkdf (struct hkdf_data *data, flags_t parsed_flags)
{
	const struct backend_hkdf_engine *engine;
	enum hash_type hash_type;
	uint8_t *okm = NULL;
	size_t okm_len_bytes;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->z.buf == NULL) || (data->z.len == 0)) {
		status = BACKEND_HKDF_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_hkdf_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	hash_type = backend_hkdf_get_hash_type (data->hash);

	status = engine->intf->extract (engine->intf, hash_type, data->z.buf, data->z.len,
		data->salt.buf, data->salt.len);
	if (status != 0) {
		goto exit;
	}

	// Allocate a new buffer to hold the result.
	okm_len_bytes = (data->dkmlen + 7) / 8;
	okm = platform_malloc (okm_len_bytes);
	if (okm == NULL) {
		status = BACKEND_HKDF_NO_MEMORY;
		goto exit;
	}

	status = engine->intf->expand (engine->intf, data->info.buf, data->info.len, okm,
		okm_len_bytes);
	if (status != 0) {
		platform_free (okm);
		goto exit;
	}

	if (data->dkm.buf == NULL) {
		// Set the output buffer to the output keying material.
		data->dkm.buf = okm;
		data->dkm.len = okm_len_bytes;
	}
	else {
		// Compare the output keying material to the expected value.
		status = buffer_compare (okm, data->dkm.buf, okm_len_bytes);
		if (status == 0) {
			data->validity_success = 1;
		}
		else {
			data->validity_success = 0;
			status = 0;
		}

		platform_free (okm);
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
 * Register the HKDF backend implementation with the ACVP backend.
 */
void backend_hkdf_register_impl (void)
{
	register_hkdf_impl ((struct hkdf_backend*) &hkdf_impl);
}
