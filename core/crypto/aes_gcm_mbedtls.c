// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_gcm_mbedtls.h"
#include "crypto_logging.h"
#include "logging/debug_log.h"


int aes_gcm_mbedtls_set_key (const struct aes_gcm_engine *engine, const uint8_t *key, size_t length)
{
	const struct aes_gcm_engine_mbedtls *mbedtls = (const struct aes_gcm_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (key == NULL)) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	switch (length) {
		case (128 / 8):
		case (192 / 8):
			return AES_GCM_ENGINE_UNSUPPORTED_KEY_LENGTH;

		case (256 / 8):
			break;

		default:
			return AES_GCM_ENGINE_INVALID_KEY_LENGTH;
	}

	status = mbedtls_gcm_setkey (&mbedtls->state->context, MBEDTLS_CIPHER_ID_AES, key, 256);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_INIT_EC, status, 0);

		return status;
	}

	mbedtls->state->has_key = true;

	return 0;
}

int aes_gcm_mbedtls_encrypt_with_add_data (const struct aes_gcm_engine *engine,
	const uint8_t *plaintext, size_t length, const uint8_t *iv, size_t iv_length,
	const uint8_t *additional_data,	size_t additional_data_length, uint8_t *ciphertext,
	size_t out_length, uint8_t *tag, size_t tag_length)
{
	const struct aes_gcm_engine_mbedtls *mbedtls = (const struct aes_gcm_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (plaintext == NULL) || (length == 0) || (iv == NULL) ||
		(iv_length == 0) || (ciphertext == NULL) || (tag == NULL) ||
		((additional_data_length > 0) && (additional_data == NULL))) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	if ((out_length < length) || (tag_length < 16)) {
		return AES_GCM_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (!mbedtls->state->has_key) {
		return AES_GCM_ENGINE_NO_KEY;
	}

	status = mbedtls_gcm_crypt_and_tag (&mbedtls->state->context, MBEDTLS_GCM_ENCRYPT, length, iv,
		iv_length, additional_data, additional_data_length, plaintext, ciphertext, 16, tag);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_CRYPT_EC, status, 0);

		return status;
	}

	return 0;
}

int aes_gcm_mbedtls_encrypt_data (const struct aes_gcm_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length,
	uint8_t *tag, size_t tag_length)
{
	return aes_gcm_mbedtls_encrypt_with_add_data (engine, plaintext, length, iv, iv_length, NULL, 0,
		ciphertext, out_length, tag, tag_length);
}

int aes_gcm_mbedtls_decrypt_with_add_data (const struct aes_gcm_engine *engine,
	const uint8_t *ciphertext, size_t length, const uint8_t *tag, const uint8_t *iv,
	size_t iv_length, const uint8_t *additional_data, size_t additional_data_length,
	uint8_t *plaintext,	size_t out_length)
{
	const struct aes_gcm_engine_mbedtls *mbedtls = (const struct aes_gcm_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (ciphertext == NULL) || (length == 0) || (tag == NULL) ||
		(iv == NULL) || (iv_length == 0) || (plaintext == NULL)) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_GCM_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (!mbedtls->state->has_key) {
		return AES_GCM_ENGINE_NO_KEY;
	}

	status = mbedtls_gcm_auth_decrypt (&mbedtls->state->context, length, iv, iv_length,
		additional_data, additional_data_length, tag, 16, ciphertext, plaintext);
	if (status != 0) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_CRYPTO,
			CRYPTO_LOG_MSG_MBEDTLS_AES_GCM_AUTH_DECRYPT_EC, status, 0);

		if (status == MBEDTLS_ERR_GCM_AUTH_FAILED) {
			status = AES_GCM_ENGINE_GCM_AUTH_FAILED;
		}
	}

	return status;
}

int aes_gcm_mbedtls_decrypt_data (const struct aes_gcm_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
	size_t out_length)
{
	return aes_gcm_mbedtls_decrypt_with_add_data (engine, ciphertext, length, tag, iv, iv_length,
		NULL, 0, plaintext, out_length);
}

/**
 * Initialize an instance for running AES-GCM operations using mbedTLS.
 *
 * @param engine The AES engine to initialize.
 * @param state The state information for the engine.
 *
 * @return 0 if the AES engine was successfully initialized or an error code.
 */
int aes_gcm_mbedtls_init (struct aes_gcm_engine_mbedtls *engine,
	struct aes_gcm_engine_mbedtls_state *state)
{
	if ((engine == NULL) || (state == NULL)) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct aes_gcm_engine_mbedtls));

	engine->state = state;

	engine->base.set_key = aes_gcm_mbedtls_set_key;
	engine->base.encrypt_data = aes_gcm_mbedtls_encrypt_data;
	engine->base.encrypt_with_add_data = aes_gcm_mbedtls_encrypt_with_add_data;
	engine->base.decrypt_data = aes_gcm_mbedtls_decrypt_data;
	engine->base.decrypt_with_add_data = aes_gcm_mbedtls_decrypt_with_add_data;

	return aes_gcm_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of an mbedTLS AES-GCM engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The AES-GCM engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int aes_gcm_mbedtls_init_state (const struct aes_gcm_engine_mbedtls *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return AES_GCM_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	mbedtls_gcm_init (&engine->state->context);

	return 0;
}

/**
 * Release a mbedTLS AES-GCM engine.
 *
 * @param engine The AES engine to release.
 */
void aes_gcm_mbedtls_release (const struct aes_gcm_engine_mbedtls *engine)
{
	if (engine) {
		mbedtls_gcm_free (&engine->state->context);
	}
}
