// Copyright (c) Microsoft Corporation. All rights reserved.

#include <stdint.h>
#include "backend_sym.h"
#include "platform_api.h"
#include "acvp/acvp_logging.h"
#include "common/unused.h"
#include "logging/debug_log.h"
#include "parser/cipher_definitions.h"
#include "parser/common.h"

/**
 * The current implementation identifier for the ACVP backend.
 */
extern uint32_t acvp_implementation;


/**
 * Execute a symmetric encryption ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.data.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 *
 * @return 0 if the test was executed successfully, else -1.
 */
static int backend_sym_encrypt (struct sym_data *data, flags_t parsed_flags);

/**
 * Execute a symmetric decryption ACVP test on the provided data.
 *
 * @param data The container for the parsed test input and test output.  The test output is stored
 * in data.data.buf and must be freed by the caller.
 * @param parsed_flags Flags parsed from the ACVP request.
 */
static int backend_sym_decrypt (struct sym_data *data, flags_t parsed_flags);

/**
 * List of registered symmetric cipher engines.
 */
static const struct backend_sym_engine *sym_engines = NULL;

/**
 * Number of registered symmetric cipher engines.
 */
static size_t sym_engines_cnt = 0;

/**
 * Symmetric cipher backend callback structure.
 */
static const struct sym_backend sym_impl = {
	.encrypt = backend_sym_encrypt,
	.decrypt = backend_sym_decrypt,
	.mct_init = NULL,
	.mct_update = NULL,
	.mct_fini = NULL
};


/**
 * Get the symmetric cipher backend callback structure containing the symmetric cipher implementations.
 *
 * @return The symmetric cipher backend callback structure.
 */
const struct sym_backend* backend_sym_get_impl ()
{
	return &sym_impl;
}

/**
 * Register a list of symmetric cipher engines with the symmetric cipher backend.  If any symmetric
 * cipher engines were previously registered, they will be replaced by the new list of symmetric
 * cipher engines.  The engines must remain valid for the lifetime of the symmetric cipher backend.
 *
 * @param sym The list of symmetric cipher engines to register.
 * @param num_engines The number of symmetric cipher engines in the list.
 */
void backend_sym_register_engines (const struct backend_sym_engine *sym, size_t num_engines)
{
	sym_engines = sym;
	sym_engines_cnt = num_engines;
}

/**
 * Retrieve the symmetric cipher engine for the specified implementation identifier.
 *
 * @param impl_id The implementation identifier to search for.
 * @param engine Output for the symmetric cipher engine associated with the given implentation
 * identifier.
 *
 * @return 0 if the symmetric cipher engine was found or an error code.
 */
static int backend_sym_get_engine (int impl_id, const struct backend_sym_engine **engine)
{
	size_t i;

	if (engine == NULL) {
		return BACKEND_SYM_INVALID_ARGUMENT;
	}

	if (sym_engines == NULL) {
		return BACKEND_SYM_NO_ENGINE;
	}

	for (i = 0; i < sym_engines_cnt; i++) {
		if (sym_engines[i].impl_id == impl_id) {
			*engine = &sym_engines[i];

			return 0;
		}
	}

	return BACKEND_SYM_ENGINE_NOT_FOUND;
}

/**
 * Check if the symmetric cipher engine supports the specified cipher.
 *
 * @param cipher The cipher to check.
 * @param type The symmetric cipher engine type.
 *
 * @return 0 if the cipher is supported, else an error code.
 */
static int backend_sym_check_cipher (uint64_t cipher, enum backend_sym_engine_type type)
{
	switch (cipher) {
		case ACVP_KW:
		case ACVP_KW_INV:
			if (type == BACKEND_SYM_ENGINE_TYPE_AES_KW) {
				return 0;
			}

			break;

		case ACVP_KWP:
		case ACVP_KWP_INV:
			if (type == BACKEND_SYM_ENGINE_TYPE_AES_KWP) {
				return 0;
			}

			break;

		default:
			return BACKEND_SYM_UNSUPPORTED_CIPHER_TYPE;
	}

	return BACKEND_SYM_UNSUPPORTED_CIPHER_TYPE;
}

static int backend_sym_encrypt (struct sym_data *data, flags_t parsed_flags)
{
	const struct backend_sym_engine *engine;
	uint8_t *wrapped_data = NULL;
	size_t wrapped_data_len;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->key.buf == NULL) || (data->key.len == 0) ||
		(data->data.buf == NULL) ||
		(data->data.len == 0)) {
		status = BACKEND_SYM_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_sym_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_sym_check_cipher (data->cipher, engine->type);
	if (status != 0) {
		goto exit;
	}

	status = engine->aes_kw->set_kek (engine->aes_kw, data->key.buf, data->key.len);
	if (status != 0) {
		goto exit;
	}

	wrapped_data_len = AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (data->data.len);
	wrapped_data = platform_malloc (wrapped_data_len);
	if (wrapped_data == NULL) {
		status = BACKEND_SYM_NO_MEMORY;
		goto exit;
	}

	status = engine->aes_kw->wrap (engine->aes_kw, data->data.buf, data->data.len, wrapped_data,
		wrapped_data_len);
	if (status != 0) {
		platform_free (wrapped_data);
		goto exit;
	}

	// Replace data input with wrapped data output.
	platform_free (data->data.buf);
	data->data.buf = wrapped_data;
	data->data.len = wrapped_data_len;

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

static int backend_sym_decrypt (struct sym_data *data, flags_t parsed_flags)
{
	const struct backend_sym_engine *engine;
	int status;

	UNUSED (parsed_flags);

	if ((data == NULL) || (data->key.buf == NULL) || (data->key.len == 0) ||
		(data->data.buf == NULL) ||
		(data->data.len == 0)) {
		status = BACKEND_SYM_INVALID_ARGUMENT;
		goto exit;
	}

	status = backend_sym_get_engine (acvp_implementation, &engine);
	if (status != 0) {
		goto exit;
	}

	status = backend_sym_check_cipher (data->cipher, engine->type);
	if (status != 0) {
		goto exit;
	}

	status = engine->aes_kw->set_kek (engine->aes_kw, data->key.buf, data->key.len);
	if (status != 0) {
		goto exit;
	}

	status = engine->aes_kw->unwrap (engine->aes_kw, data->data.buf, data->data.len, data->data.buf,
		&data->data.len);
	if ((status == AES_KEY_WRAP_INTEGRITY_CHECK_FAIL) ||
		(status == AES_KEY_WRAP_LENGTH_CHECK_FAIL) || (status == AES_KEY_WRAP_PADDING_CHECK_FAIL)) {
		data->integrity_error = 1;
		status = 0;

		/* If an authenticating cipher returns an integrity error during decryption, the data
		 * buffer with the return data must contain the value of CIPHER_DECRYPTION_FAILED with
		 * CIPHER_DECRYPTION_FAILED_LEN buffer size. */
		platform_free (data->data.buf);

		data->data.buf = platform_malloc (CIPHER_DECRYPTION_FAILED_LEN);
		if (data->data.buf == NULL) {
			status = BACKEND_SYM_NO_MEMORY;
			goto exit;
		}

		memcpy (data->data.buf, CIPHER_DECRYPTION_FAILED, CIPHER_DECRYPTION_FAILED_LEN);
		data->data.len = CIPHER_DECRYPTION_FAILED_LEN;
	}
	else if (status == 0) {
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
 * Register the symmetric cipher backend implementation with the ACVP backend.
 */
void backend_sym_register_impl (void)
{
	register_sym_impl ((struct sym_backend*) &sym_impl);
}
