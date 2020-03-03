// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <openssl/err.h>
#include "aes_openssl.h"


static int aes_openssl_set_key (struct aes_engine *engine, const uint8_t *key, size_t length)
{
	struct aes_engine_openssl *openssl = (struct aes_engine_openssl*) engine;
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

	status = EVP_CIPHER_CTX_cleanup (openssl->context);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	EVP_CIPHER_CTX_init (openssl->context);

	status = EVP_CipherInit_ex (openssl->context, EVP_aes_256_gcm (), NULL, key, NULL, -1);
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
static int aes_openssl_init_iv (struct aes_engine_openssl *openssl, const uint8_t *iv,
	size_t length, int encrypt)
{
	int status;

	status = EVP_CIPHER_CTX_ctrl (openssl->context, EVP_CTRL_GCM_SET_IVLEN, length, NULL);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	status = EVP_CipherInit_ex (openssl->context, NULL, NULL, NULL, iv, encrypt);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	return 0;
}

static int aes_openssl_encrypt_data (struct aes_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length,
	uint8_t *tag, size_t tag_length)
{
	struct aes_engine_openssl *openssl = (struct aes_engine_openssl*) engine;
	int status;
	int enc_length;

	if ((openssl == NULL) || (plaintext == NULL) || (length == 0) || (iv == NULL) ||
		(iv_length == 0) || (ciphertext == NULL)) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (tag && (tag_length < 16)) {
		return AES_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (EVP_CIPHER_CTX_key_length (openssl->context) == 0) {
		return AES_ENGINE_NO_KEY;
	}

	ERR_clear_error ();

	status = aes_openssl_init_iv (openssl, iv, iv_length, 1);
	if (status != 0) {
		return status;
	}

	status = EVP_EncryptUpdate (openssl->context, ciphertext, &enc_length, plaintext, length);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	status = EVP_EncryptFinal_ex (openssl->context, ciphertext + enc_length, &enc_length);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	if (tag) {
		status = EVP_CIPHER_CTX_ctrl (openssl->context, EVP_CTRL_GCM_GET_TAG, 16, tag);
		if (status != 1) {
			status = ERR_get_error ();
			return -status;
		}
	}

	return 0;
}

static int aes_openssl_decrypt_data (struct aes_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
	size_t out_length)
{
	struct aes_engine_openssl *openssl = (struct aes_engine_openssl*) engine;
	int status;
	int dec_length;

	if ((openssl == NULL) || (ciphertext == NULL) || (length == 0) || (iv == NULL) ||
		(iv_length == 0) || (plaintext == NULL)) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (EVP_CIPHER_CTX_key_length (openssl->context) == 0) {
		return AES_ENGINE_NO_KEY;
	}

	ERR_clear_error ();

	status = aes_openssl_init_iv (openssl, iv, iv_length, 0);
	if (status != 0) {
		return status;
	}

	status = EVP_DecryptUpdate (openssl->context, plaintext, &dec_length, ciphertext, length);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	if (tag) {
		status = EVP_CIPHER_CTX_ctrl (openssl->context, EVP_CTRL_GCM_SET_TAG, 16, (void*) tag);
		if (status != 1) {
			status = ERR_get_error ();
			return -status;
		}
	}

	status = EVP_DecryptFinal_ex (openssl->context, plaintext + dec_length, &dec_length);

	if (tag) {
		return (status == 1) ? 0 : AES_ENGINE_GCM_AUTH_FAILED;
	}
	else {
		return 0;
	}
}

/**
 * Initialize an instance for run AES operations using OpenSSL.
 *
 * @param engine The AES engine to initialize.
 *
 * @return 0 if the AES engine was successfully initialized or an error code.
 */
int aes_openssl_init (struct aes_engine_openssl *engine)
{
	if (engine == NULL) {
		return AES_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct aes_engine_openssl));

	engine->context = EVP_CIPHER_CTX_new ();
	if (engine->context == NULL) {
		return AES_ENGINE_NO_MEMORY;
	}

	EVP_CIPHER_CTX_reset (engine->context);

	engine->base.set_key = aes_openssl_set_key;
	engine->base.encrypt_data = aes_openssl_encrypt_data;
	engine->base.decrypt_data = aes_openssl_decrypt_data;

	return 0;
}

/**
 * Release an OpenSSL AES engine.
 *
 * @param engine The AES engine to release.
 */
void aes_openssl_release (struct aes_engine_openssl *engine)
{
	if (engine) {
		EVP_CIPHER_CTX_free (engine->context);
	}
}
