// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include "aes_ecb_openssl.h"
#include "platform_io_api.h"


int aes_ecb_openssl_set_key (const struct aes_ecb_engine *engine, const uint8_t *key, size_t length)
{
	const struct aes_ecb_engine_openssl *openssl = (const struct aes_ecb_engine_openssl*) engine;
	const EVP_CIPHER *cipher;
	int status;

	if ((openssl == NULL) || (key == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	switch (length) {
		case (128 / 8):
		case (192 / 8):
			return AES_ECB_ENGINE_UNSUPPORTED_KEY_LENGTH;

		case AES_ECB_256_KEY_LENGTH:
			cipher = EVP_aes_256_ecb ();
			break;

		default:
			return AES_ECB_ENGINE_INVALID_KEY_LENGTH;
	}

	ERR_clear_error ();

	status = EVP_CIPHER_CTX_reset (openssl->state->encrypt);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	EVP_CIPHER_CTX_init (openssl->state->encrypt);

	status = EVP_EncryptInit_ex (openssl->state->encrypt, cipher, NULL, key, NULL);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	EVP_CIPHER_CTX_set_padding (openssl->state->encrypt, 0);

	status = EVP_CIPHER_CTX_reset (openssl->state->decrypt);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	EVP_CIPHER_CTX_init (openssl->state->decrypt);

	status = EVP_DecryptInit_ex (openssl->state->decrypt, cipher, NULL, key, NULL);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	EVP_CIPHER_CTX_set_padding (openssl->state->decrypt, 0);

	return 0;
}

int aes_ecb_openssl_clear_key (const struct aes_ecb_engine *engine)
{
	const struct aes_ecb_engine_openssl *openssl = (const struct aes_ecb_engine_openssl*) engine;
	int status;

	if (openssl == NULL) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	ERR_clear_error ();

	status = EVP_CIPHER_CTX_reset (openssl->state->encrypt);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	status = EVP_CIPHER_CTX_reset (openssl->state->decrypt);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	return 0;
}

int aes_ecb_openssl_encrypt_data (const struct aes_ecb_engine *engine, const uint8_t *plaintext,
	size_t length, uint8_t *ciphertext, size_t out_length)
{
	const struct aes_ecb_engine_openssl *openssl = (const struct aes_ecb_engine_openssl*) engine;
	int status;
	int enc_length;

	if ((openssl == NULL) || (plaintext == NULL) || (ciphertext == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ECB_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (((length % AES_ECB_BLOCK_SIZE) != 0) || (length == 0)) {
		return AES_ECB_ENGINE_INVALID_DATA_LENGTH;
	}

	if (EVP_CIPHER_CTX_key_length (openssl->state->encrypt) <= 0) {
		return AES_ECB_ENGINE_NO_KEY;
	}

	ERR_clear_error ();

	status = EVP_EncryptUpdate (openssl->state->encrypt, ciphertext, &enc_length, plaintext,
		length);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	return 0;
}

int aes_ecb_openssl_decrypt_data (const struct aes_ecb_engine *engine, const uint8_t *ciphertext,
	size_t length, uint8_t *plaintext, size_t out_length)
{
	const struct aes_ecb_engine_openssl *openssl = (const struct aes_ecb_engine_openssl*) engine;
	int status;
	int dec_length;

	if ((openssl == NULL) || (ciphertext == NULL) || (plaintext == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	if (out_length < length) {
		return AES_ECB_ENGINE_OUT_BUFFER_TOO_SMALL;
	}

	if (((length % AES_ECB_BLOCK_SIZE) != 0) || (length == 0)) {
		return AES_ECB_ENGINE_INVALID_DATA_LENGTH;
	}

	if (EVP_CIPHER_CTX_key_length (openssl->state->decrypt) <= 0) {
		return AES_ECB_ENGINE_NO_KEY;
	}

	ERR_clear_error ();

	status = EVP_DecryptUpdate (openssl->state->decrypt, plaintext, &dec_length, ciphertext,
		length);
	if (status != 1) {
		status = ERR_get_error ();
		return -status;
	}

	return 0;
}

/**
 * Initialize an instance for running AES-ECB operations using OpenSSL.
 *
 * @param engine The AES-ECB engine to initialize.
 * @param state Variable context for AES operations.  This must be uninitialized.
 *
 * @return 0 if the AES-ECB engine was successfully initialized or an error code.
 */
int aes_ecb_openssl_init (struct aes_ecb_engine_openssl *engine,
	struct aes_ecb_engine_openssl_state *state)
{
	if ((engine == NULL) || (state == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (*engine));

	engine->base.set_key = aes_ecb_openssl_set_key;
	engine->base.clear_key = aes_ecb_openssl_clear_key;
	engine->base.encrypt_data = aes_ecb_openssl_encrypt_data;
	engine->base.decrypt_data = aes_ecb_openssl_decrypt_data;

	engine->state = state;

	return aes_ecb_openssl_init_state (engine);
}

/**
 * Initialize only the variable state of an OpenSSL AES-ECB engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The AES-ECB engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int aes_ecb_openssl_init_state (const struct aes_ecb_engine_openssl *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return AES_ECB_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	engine->state->encrypt = EVP_CIPHER_CTX_new ();
	if (engine->state->encrypt == NULL) {
		return AES_ECB_ENGINE_NO_MEMORY;
	}

	engine->state->decrypt = EVP_CIPHER_CTX_new ();
	if (engine->state->decrypt == NULL) {
		EVP_CIPHER_CTX_free (engine->state->encrypt);

		return AES_ECB_ENGINE_NO_MEMORY;
	}

	EVP_CIPHER_CTX_reset (engine->state->encrypt);
	EVP_CIPHER_CTX_reset (engine->state->decrypt);

	return 0;
}

/**
 * Release the resources used by an OpenSSL AES-ECB engine.
 *
 * @param engine The AES-ECB engine to release.
 */
void aes_ecb_openssl_release (const struct aes_ecb_engine_openssl *engine)
{
	if (engine) {
		EVP_CIPHER_CTX_free (engine->state->encrypt);
		EVP_CIPHER_CTX_free (engine->state->decrypt);
	}
}
