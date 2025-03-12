// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_cbc_mbedtls.h"
#include "crypto_logging.h"
#include "common/buffer_util.h"
#include "mbedtls/aes.h"


int aes_cbc_mbedtls_set_key (const struct aes_cbc_engine *engine, const uint8_t *key, size_t length)
{
	const struct aes_cbc_engine_mbedtls *mbedtls = (const struct aes_cbc_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (key == NULL)) {
		return AES_CBC_ENGINE_INVALID_ARGUMENT;
	}

	switch (length) {
		case (128 / 8):
		case (192 / 8):
			return AES_CBC_ENGINE_UNSUPPORTED_KEY_LENGTH;

		case AES_CBC_256_KEY_LENGTH:
			break;

		default:
			return AES_CBC_ENGINE_INVALID_KEY_LENGTH;
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

/**
 * Perform an AES-CBC encrypt or decrypt operation on any length of data.  The data must be aligned
 * to the AES block size.
 *
 * @param engine The AES engine to use for the operation.
 * @param mode The operation to perform.  MBEDTLS_AES_ENCRYPT or MBEDTLS_AES_DECRYPT.
 * @param input The input buffer for the operation.
 * @param length Length of the input data.
 * @param iv Input IV for the start of the operation.
 * @param output Output buffer for the operation.
 * @param out_length Length of the output buffer.
 * @param out_iv Optional output of the IV at the end of the operation to use for chaining
 * encrypt/decrypt requests.
 *
 * @return 0 if the operation completed successfully or an error code.
 */
static int aes_cbc_mbedtls_crypt (const struct aes_cbc_engine *engine, int mode,
	const uint8_t *input, size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE], uint8_t *output,
	size_t out_length, uint8_t out_iv[AES_CBC_BLOCK_SIZE])
{
	const struct aes_cbc_engine_mbedtls *mbedtls = (const struct aes_cbc_engine_mbedtls*) engine;
	struct mbedtls_aes_context *context;
	uint8_t temp_iv[AES_CBC_BLOCK_SIZE];
	int status;

	if ((engine == NULL) || (input == NULL) || (iv == NULL) || (output == NULL)) {
		return AES_CBC_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_CBC_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (((length % AES_CBC_BLOCK_SIZE) != 0) || (length == 0)) {
		return AES_CBC_ENGINE_INVALID_DATA_LENGTH;
	}

	if (!mbedtls->state->has_key) {
		return AES_CBC_ENGINE_NO_KEY;
	}

	if (mode == MBEDTLS_AES_ENCRYPT) {
		context = &mbedtls->state->encrypt;
	}
	else {
		context = &mbedtls->state->decrypt;
	}

	memcpy (temp_iv, iv, sizeof (temp_iv));

	status = mbedtls_aes_crypt_cbc (context, mode, length, temp_iv, input, output);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_CBC_CRYPT_EC, MBEDTLS_AES_ENCRYPT, status);

		goto exit;
	}

	if (out_iv != NULL) {
		memcpy (out_iv, temp_iv, sizeof (temp_iv));
	}

exit:
	buffer_zeroize (temp_iv, sizeof (temp_iv));

	return status;
}

int aes_cbc_mbedtls_encrypt_data (const struct aes_cbc_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE], uint8_t *ciphertext, size_t out_length,
	uint8_t out_iv[AES_CBC_BLOCK_SIZE])
{
	return aes_cbc_mbedtls_crypt (engine, MBEDTLS_AES_ENCRYPT, plaintext, length, iv, ciphertext,
		out_length, out_iv);
}

int aes_cbc_mbedtls_decrypt_data (const struct aes_cbc_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE], uint8_t *plaintext, size_t out_length,
	uint8_t out_iv[AES_CBC_BLOCK_SIZE])
{
	return aes_cbc_mbedtls_crypt (engine, MBEDTLS_AES_DECRYPT, ciphertext, length, iv, plaintext,
		out_length, out_iv);
}

/**
 * Initialize an instance for running AES-CBC operations using mbedTLS.
 *
 * @param engine The AES-CBC engine to initialize.
 * @param state Variable context for AES operations.  This must be uninitialized.
 *
 * @return 0 if the AES-CBC engine was successfully initialized or an error code.
 */
int aes_cbc_mbedtls_init (struct aes_cbc_engine_mbedtls *engine,
	struct aes_cbc_engine_mbedtls_state *state)
{
	if (engine == NULL) {
		return AES_CBC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (*engine));

	engine->base.set_key = aes_cbc_mbedtls_set_key;
	engine->base.encrypt_data = aes_cbc_mbedtls_encrypt_data;
	engine->base.decrypt_data = aes_cbc_mbedtls_decrypt_data;

	engine->state = state;

	return aes_cbc_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of an mbedTLS AES-CBC engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The AES-CBC engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int aes_cbc_mbedtls_init_state (const struct aes_cbc_engine_mbedtls *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return AES_CBC_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	mbedtls_aes_init (&engine->state->encrypt);
	mbedtls_aes_init (&engine->state->decrypt);

	return 0;
}

/**
 * Release the resources used by an mbedTLS AES-CBC engine.
 *
 * @param engine The AES-CBC engine to release.
 */
void aes_cbc_mbedtls_release (const struct aes_cbc_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_aes_free (&engine->state->encrypt);
		mbedtls_aes_free (&engine->state->decrypt);
	}
}
