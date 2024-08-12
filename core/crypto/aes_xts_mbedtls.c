// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_xts_mbedtls.h"
#include "crypto_logging.h"
#include "common/buffer_util.h"
#include "mbedtls/aes.h"


int aes_xts_mbedtls_set_key (const struct aes_xts_engine *engine, const uint8_t *key, size_t length)
{
	const struct aes_xts_engine_mbedtls *mbedtls = (const struct aes_xts_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (key == NULL)) {
		return AES_XTS_ENGINE_INVALID_ARGUMENT;
	}

	status = buffer_compare (key, &key[length / 2], length / 2);
	if (status == 0) {
		/* The two AES keys must be different. */
		return AES_XTS_ENGINE_MATCHING_KEYS;
	}

	status = mbedtls_aes_xts_setkey_enc (&mbedtls->state->encrypt, key, length * 8);
	if (status == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
		return AES_XTS_ENGINE_INVALID_KEY_LENGTH;
	}
	else if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_XTS_SET_KEY_EC, MBEDTLS_AES_ENCRYPT, status);

		return status;
	}

	status = mbedtls_aes_xts_setkey_dec (&mbedtls->state->decrypt, key, length * 8);
	if (status != 0) {
		/* Since the key length has already been validated, that condition doesn't need to be
		 * checked here. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_XTS_SET_KEY_EC, MBEDTLS_AES_DECRYPT, status);

		return status;
	}

	mbedtls->state->has_key = true;

	return 0;
}

/**
 * Perform an AES-XTS encrypt or decrypt operation on one full unit of data.
 *
 * @param engine The AES engine to use for the operation.
 * @param mode The operation to perform.  MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT.
 * @param input The input buffer for the operation.
 * @param length Length of the XTS data unit.
 * @param data_unit_id Encoded data unit identifier.
 * @param output Output buffer for the operation.
 * @param out_length Length of the output buffer.
 *
 * @return 0 if the operation completed successfully or an error code.
 */
static int aes_xts_mbedtls_crypt (const struct aes_xts_engine *engine, int mode,
	const uint8_t *input, size_t length, const uint8_t data_unit_id[16], uint8_t *output,
	size_t out_length)
{
	const struct aes_xts_engine_mbedtls *mbedtls = (const struct aes_xts_engine_mbedtls*) engine;
	struct mbedtls_aes_xts_context *context;
	int status;

	if ((engine == NULL) || (input == NULL) || (data_unit_id == NULL) || (output == NULL)) {
		return AES_XTS_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_XTS_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (!mbedtls->state->has_key) {
		return AES_XTS_ENGINE_NO_KEY;
	}

	if (mode == MBEDTLS_AES_ENCRYPT) {
		context = &mbedtls->state->encrypt;
	}
	else {
		context = &mbedtls->state->decrypt;
	}

	status = mbedtls_aes_crypt_xts (context, mode, length, data_unit_id, input, output);
	if (status == MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH) {
		return AES_XTS_ENGINE_INVALID_DATA_LENGTH;
	}
	else if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_XTS_CRYPT_EC, mode, status);

		return status;
	}

	return 0;
}

int aes_xts_mbedtls_encrypt_data (const struct aes_xts_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t data_unit_id[16], uint8_t *ciphertext, size_t out_length)
{
	return aes_xts_mbedtls_crypt (engine, MBEDTLS_AES_ENCRYPT, plaintext, length, data_unit_id,
		ciphertext, out_length);
}

int aes_xts_mbedtls_decrypt_data (const struct aes_xts_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t data_unit_id[16], uint8_t *plaintext, size_t out_length)
{
	return aes_xts_mbedtls_crypt (engine, MBEDTLS_AES_DECRYPT, ciphertext, length, data_unit_id,
		plaintext, out_length);
}

/**
 * Initialize an instance for running AES-XTS operations using mbedTLS.
 *
 * @param engine The AES-XTS engine to initialize.
 * @param state Variable context for AES operations.  This must be uninitialized.
 *
 * @return 0 if the AES-XTS engine was successfully initialized or an error code.
 */
int aes_xts_mbedtls_init (struct aes_xts_engine_mbedtls *engine,
	struct aes_xts_engine_mbedtls_state *state)
{
	if (engine == NULL) {
		return AES_XTS_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (*engine));

	engine->base.set_key = aes_xts_mbedtls_set_key;
	engine->base.encrypt_data = aes_xts_mbedtls_encrypt_data;
	engine->base.decrypt_data = aes_xts_mbedtls_decrypt_data;

	engine->state = state;

	return aes_xts_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of an mbedTLS AES-XTS engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The AES-XTS engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int aes_xts_mbedtls_init_state (const struct aes_xts_engine_mbedtls *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return AES_XTS_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	mbedtls_aes_xts_init (&engine->state->encrypt);
	mbedtls_aes_xts_init (&engine->state->decrypt);

	return 0;
}

/**
 * Release the resources used by an mbedTLS AES-XTS engine.
 *
 * @param engine The AES-XTS engine to release.
 */
void aes_xts_mbedtls_release (const struct aes_xts_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_aes_xts_free (&engine->state->encrypt);
		mbedtls_aes_xts_free (&engine->state->decrypt);
	}
}
