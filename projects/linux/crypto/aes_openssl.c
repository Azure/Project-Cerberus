// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <openssl/err.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_openssl.h"


int aes_openssl_set_key (const struct aes_engine *engine, const uint8_t *key, size_t length)
{
	const struct aes_engine_openssl *openssl = (const struct aes_engine_openssl*) engine;
	int status;

	if ((openssl == NULL) || (key == NULL)) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	switch (length) {
		case (128 / 8):
		case (192 / 8):
			return AES_ENGINE_UNSUPPORTED_KEY_LENGTH;

		case (256 / 8):
			break;

		default:
			return AES_ENGINE_INVALID_KEY_LENGTH;
	}

	ERR_clear_error ();

	status = EVP_CIPHER_CTX_cleanup (openssl->state->context);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	EVP_CIPHER_CTX_init (openssl->state->context);

	status = EVP_CipherInit_ex (openssl->state->context, EVP_aes_256_gcm (), NULL, key, NULL, -1);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	return 0;
}

/**
 * Initialize the IV for an AES operation.
 *
 * @param openssl The AES instance to configure.
 * @param iv The IV being used.
 * @param length The length of the IV.
 * @param encrypt Flag indicating if the operation will be an encrypt or decrypt operation.
 *
 * @return 0 if the IV was successfully initialized or an error code.
 */
static int aes_openssl_init_iv (const struct aes_engine_openssl *openssl, const uint8_t *iv,
	size_t length, int encrypt)
{
	int status;

	status = EVP_CIPHER_CTX_ctrl (openssl->state->context, EVP_CTRL_GCM_SET_IVLEN, length, NULL);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	status = EVP_CipherInit_ex (openssl->state->context, NULL, NULL, NULL, iv, encrypt);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	return 0;
}

int aes_openssl_encrypt_with_add_data (const struct aes_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, const uint8_t *additional_data,
	size_t additional_data_length, uint8_t *ciphertext, size_t out_length, uint8_t *tag,
	size_t tag_length)
{
	const struct aes_engine_openssl *openssl = (const struct aes_engine_openssl*) engine;
	int status;
	int enc_length;

	if ((openssl == NULL) || (plaintext == NULL) || (length == 0) || (iv == NULL) ||
		(iv_length == 0) || (ciphertext == NULL) ||
		((additional_data_length > 0) && (additional_data == NULL))) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (tag && (tag_length < 16)) {
		return AES_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (EVP_CIPHER_CTX_key_length (openssl->state->context) == 0) {
		return AES_ENGINE_NO_KEY;
	}

	ERR_clear_error ();

	status = aes_openssl_init_iv (openssl, iv, iv_length, 1);
	if (status != 0) {
		return status;
	}

	if (additional_data) {
		status = EVP_EncryptUpdate (openssl->state->context, NULL, &enc_length, additional_data,
			additional_data_length);
		if (status != 1) {
			status = ERR_get_error ();

			return -status;
		}
	}

	status = EVP_EncryptUpdate (openssl->state->context, ciphertext, &enc_length, plaintext,
		length);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	status = EVP_EncryptFinal_ex (openssl->state->context, ciphertext + enc_length, &enc_length);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	if (tag) {
		status = EVP_CIPHER_CTX_ctrl (openssl->state->context, EVP_CTRL_GCM_GET_TAG, 16, tag);
		if (status != 1) {
			status = ERR_get_error ();

			return -status;
		}
	}

	return 0;
}

int aes_openssl_encrypt_data (const struct aes_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length,
	uint8_t *tag, size_t tag_length)
{
	return aes_openssl_encrypt_with_add_data (engine, plaintext, length, iv, iv_length, NULL, 0,
		ciphertext, out_length, tag, tag_length);
}

int aes_openssl_decrypt_with_add_data (const struct aes_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length,
	const uint8_t *additional_data, size_t additional_data_length, uint8_t *plaintext,
	size_t out_length)
{
	const struct aes_engine_openssl *openssl = (const struct aes_engine_openssl*) engine;
	int status;
	int dec_length;

	if ((openssl == NULL) || (ciphertext == NULL) || (length == 0) || (iv == NULL) ||
		(iv_length == 0) || (plaintext == NULL) ||
		((additional_data_length > 0) && (additional_data == NULL))) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (EVP_CIPHER_CTX_key_length (openssl->state->context) == 0) {
		return AES_ENGINE_NO_KEY;
	}

	ERR_clear_error ();

	status = aes_openssl_init_iv (openssl, iv, iv_length, 0);
	if (status != 0) {
		return status;
	}

	if (additional_data) {
		status = EVP_DecryptUpdate (openssl->state->context, NULL, &dec_length, additional_data,
			additional_data_length);
		if (status != 1) {
			status = ERR_get_error ();

			return -status;
		}
	}

	status = EVP_DecryptUpdate (openssl->state->context, plaintext, &dec_length, ciphertext,
		length);
	if (status != 1) {
		status = ERR_get_error ();

		return -status;
	}

	if (tag) {
		status = EVP_CIPHER_CTX_ctrl (openssl->state->context, EVP_CTRL_GCM_SET_TAG, 16,
			(void*) tag);
		if (status != 1) {
			status = ERR_get_error ();

			return -status;
		}
	}

	status = EVP_DecryptFinal_ex (openssl->state->context, plaintext + dec_length, &dec_length);

	if (tag) {
		return (status == 1) ? 0 : AES_ENGINE_GCM_AUTH_FAILED;
	}
	else {
		return 0;
	}
}

int aes_openssl_decrypt_data (const struct aes_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
	size_t out_length)
{
	return aes_openssl_decrypt_with_add_data (engine, ciphertext, length, tag, iv, iv_length, NULL,
		0, plaintext, out_length);
}

/**
 * Initialize an instance for running AES-GCM operations using OpenSSL.
 *
 * @param engine The AES engine to initialize.
 *
 * @return 0 if the AES engine was successfully initialized or an error code.
 */
int aes_openssl_init (struct aes_engine_openssl *engine, struct aes_engine_openssl_state *state)
{
	if (engine == NULL) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct aes_engine_openssl));

	engine->base.set_key = aes_openssl_set_key;
	engine->base.encrypt_data = aes_openssl_encrypt_data;
	engine->base.encrypt_with_add_data = aes_openssl_encrypt_with_add_data;
	engine->base.decrypt_data = aes_openssl_decrypt_data;
	engine->base.decrypt_with_add_data = aes_openssl_decrypt_with_add_data;

	engine->state = state;

	return aes_openssl_init_state (engine);
}

/**
 * Initialize only the variable state of an OpenSSL AES-GCM engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The AES-GCM engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int aes_openssl_init_state (const struct aes_engine_openssl *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	engine->state->context = EVP_CIPHER_CTX_new ();
	if (engine->state->context == NULL) {
		return AES_ENGINE_NO_MEMORY;
	}

	EVP_CIPHER_CTX_reset (engine->state->context);

	return 0;
}

/**
 * Release an OpenSSL AES engine.
 *
 * @param engine The AES engine to release.
 */
void aes_openssl_release (const struct aes_engine_openssl *engine)
{
	if (engine) {
		EVP_CIPHER_CTX_free (engine->state->context);
	}
}
