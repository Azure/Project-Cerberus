// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_ecb_mbedtls.h"
#include "crypto_logging.h"
#include "mbedtls/aes.h"


int aes_ecb_mbedtls_set_key (const struct aes_ecb_engine *engine, const uint8_t *key, size_t length)
{
	const struct aes_ecb_engine_mbedtls *mbedtls = (const struct aes_ecb_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (key == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	switch (length) {
		case (128 / 8):
		case (192 / 8):
			return AES_ECB_ENGINE_UNSUPPORTED_KEY_LENGTH;

		case AES_ECB_256_KEY_LENGTH:
			break;

		default:
			return AES_ECB_ENGINE_INVALID_KEY_LENGTH;
	}

	status = mbedtls_aes_setkey_enc (&mbedtls->state->encrypt, key, length * 8);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_SET_KEY_EC, MBEDTLS_AES_ENCRYPT, status);

		return status;
	}

	status = mbedtls_aes_setkey_dec (&mbedtls->state->decrypt, key, length * 8);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_SET_KEY_EC, MBEDTLS_AES_DECRYPT, status);

		return status;
	}

	mbedtls->state->has_key = true;

	return 0;
}

int aes_ecb_mbedtls_clear_key (const struct aes_ecb_engine *engine)
{
	const struct aes_ecb_engine_mbedtls *mbedtls = (const struct aes_ecb_engine_mbedtls*) engine;

	if (mbedtls == NULL) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	/* Reinitialize the ECB contexts to reset the key. */
	mbedtls_aes_free (&mbedtls->state->encrypt);
	mbedtls_aes_init (&mbedtls->state->encrypt);

	mbedtls_aes_free (&mbedtls->state->decrypt);
	mbedtls_aes_init (&mbedtls->state->decrypt);

	mbedtls->state->has_key = false;

	return 0;
}

/**
 * Perform an AES-ECB encrypt or decrypt operation on any length of data.  The data must be aligned
 * to the AES block size.
 *
 * @param engine The AES engine to use for the operation.
 * @param mode The operation to perform.  MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT.
 * @param input The input buffer for the operation.
 * @param length Length of the input data.
 * @param output Output buffer for the operation.
 * @param out_length Length of the output buffer.
 *
 * @return 0 if the operation completed successfully or an error code.
 */
static int aes_ecb_mbedtls_crypt (const struct aes_ecb_engine *engine, int mode,
	const uint8_t *input, size_t length, uint8_t *output, size_t out_length)
{
	const struct aes_ecb_engine_mbedtls *mbedtls = (const struct aes_ecb_engine_mbedtls*) engine;
	struct mbedtls_aes_context *context;
	int status;

	if ((engine == NULL) || (input == NULL) || (output == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ECB_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (((length % AES_ECB_BLOCK_SIZE) != 0) || (length == 0)) {
		return AES_ECB_ENGINE_INVALID_DATA_LENGTH;
	}

	if (!mbedtls->state->has_key) {
		return AES_ECB_ENGINE_NO_KEY;
	}

	if (mode == MBEDTLS_AES_ENCRYPT) {
		context = &mbedtls->state->encrypt;
	}
	else {
		context = &mbedtls->state->decrypt;
	}

	while (length > 0) {
		status = mbedtls_aes_crypt_ecb (context, mode, input, output);
		if (status != 0) {
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
				CRYPTO_LOG_MSG_MBEDTLS_AES_ECB_CRYPT_EC, mode, status);

			return status;
		}

		input += AES_ECB_BLOCK_SIZE;
		output += AES_ECB_BLOCK_SIZE;
		length -= AES_ECB_BLOCK_SIZE;
	}

	return 0;
}

int aes_ecb_mbedtls_encrypt_data (const struct aes_ecb_engine *engine, const uint8_t *plaintext,
	size_t length, uint8_t *ciphertext, size_t out_length)
{
	return aes_ecb_mbedtls_crypt (engine, MBEDTLS_AES_ENCRYPT, plaintext, length, ciphertext,
		out_length);
}

int aes_ecb_mbedtls_decrypt_data (const struct aes_ecb_engine *engine, const uint8_t *ciphertext,
	size_t length, uint8_t *plaintext, size_t out_length)
{
	return aes_ecb_mbedtls_crypt (engine, MBEDTLS_AES_DECRYPT, ciphertext, length, plaintext,
		out_length);
}

/**
 * Initialize an instance for running AES-ECB operations using mbedTLS.
 *
 * @param engine The AES-ECB engine to initialize.
 * @param state Variable context for AES operations.  This must be uninitialized.
 *
 * @return 0 if the AES-ECB engine was successfully initialized or an error code.
 */
int aes_ecb_mbedtls_init (struct aes_ecb_engine_mbedtls *engine,
	struct aes_ecb_engine_mbedtls_state *state)
{
	if (engine == NULL) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (*engine));

	engine->base.set_key = aes_ecb_mbedtls_set_key;
	engine->base.clear_key = aes_ecb_mbedtls_clear_key;
	engine->base.encrypt_data = aes_ecb_mbedtls_encrypt_data;
	engine->base.decrypt_data = aes_ecb_mbedtls_decrypt_data;

	engine->state = state;

	return aes_ecb_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of an mbedTLS AES-ECB engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The AES-ECB engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int aes_ecb_mbedtls_init_state (const struct aes_ecb_engine_mbedtls *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	mbedtls_aes_init (&engine->state->encrypt);
	mbedtls_aes_init (&engine->state->decrypt);

	return 0;
}

/**
 * Release the resources used by an mbedTLS AES-ECB engine.
 *
 * @param engine The AES-ECB engine to release.
 */
void aes_ecb_mbedtls_release (const struct aes_ecb_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_aes_free (&engine->state->encrypt);
		mbedtls_aes_free (&engine->state->decrypt);
	}
}
