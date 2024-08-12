// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AES_H_
#define AES_H_

#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/**
 * The length of AES-GCM authentication tags.
 */
#define	AES_TAG_LENGTH			16

/**
 * The length of an AES 256 key.
 */
#define	AES256_KEY_LENGTH		32


/**
 * A platform-independent API for encrypting data using AES-GCM.  AES-GCM engine instances are not
 * guaranteed to be thread-safe.
 */
struct aes_engine {
	/**
	 * Set the key to use for AES-GCM operations.  This must be called at least once before any
	 * encryption operation can be performed, and again if a different key should be used.
	 *
	 * @param engine The AES engine to configure.
	 * @param key The encryption key to use.  The key does not need to remain in scope for
	 * encryption and decryption operations.
	 * @param length The length of the key.
	 *
	 * @return 0 if the AES key was configured successfully or an error code.
	 */
	int (*set_key) (struct aes_engine *engine, const uint8_t *key, size_t length);

	/**
	 * Encrypt data using AES-GCM mode.  The operation must be initialized with a key prior to
	 * calling this function.
	 *
	 * @param engine The AES engine to use for encryption.
	 * @param plaintext The data to encrypt.
	 * @param length The amount of data to encrypt.
	 * @param iv The initialization vector to use for encryption.
	 * @param iv_length The length of the IV.  A 12-byte IV is best.
	 * @param ciphertext The buffer to hold the encrypted data.  The ciphertext will be the same
	 * length as the plaintext.  This buffer may be the same as the input plaintext buffer.
	 * @param out_length The size of the output buffer.
	 * @param tag The buffer to hold the GCM authentication tag.  All tags will be 16 bytes.
	 * @param tag_length The size of the tag output buffer.
	 *
	 * @return 0 if the data was encrypted successfully or an error code.
	 */
	int (*encrypt_data) (struct aes_engine *engine, const uint8_t *plaintext, size_t length,
		const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length, uint8_t *tag,
		size_t tag_length);

	/**
	 * Encrypt data using AES-GCM mode.
	 * This function accepts optional data to be included in MAC generation.
	 * The operation must be initialized with a key prior to calling this function.
	 *
	 * @param engine The AES engine to use for encryption.
	 * @param plaintext The data to encrypt.
	 * @param length The amount of data to encrypt.
	 * @param iv The initialization vector to use for encryption.
	 * @param iv_length The length of the IV.  A 12-byte IV is best.
	 * @param additional_data Optional data to be included in MAC generation.
	 * @param additional_data_length The length of the additional data.
	 * @param ciphertext The buffer to hold the encrypted data.  The ciphertext will be the same
	 * length as the plaintext.  This buffer may be the same as the input plaintext buffer.
	 * @param out_length The size of the output buffer.
	 * @param tag The buffer to hold the GCM authentication tag.  All tags will be 16 bytes.
	 * @param tag_length The size of the tag output buffer.
	 *
	 * @return 0 if the data was encrypted successfully or an error code.
	 */
	int (*encrypt_with_add_data) (struct aes_engine *engine, const uint8_t *plaintext,
		size_t length, const uint8_t *iv, size_t iv_length, const uint8_t *additional_data,
		size_t additional_data_length, uint8_t *ciphertext, size_t out_length, uint8_t *tag,
		size_t tag_length);

	/**
	 * Decrypt data using AES-GCM mode.  The operation must be initialized with a key prior to
	 * calling this function.
	 *
	 * @param engine The AES engine to use for decryption.
	 * @param ciphertext The encrypted data to decrypt.
	 * @param length The length of the encrypted data.
	 * @param tag The GCM tag for the ciphertext.  This must be 16 bytes.
	 * @param iv The initialization vector used to generate the ciphertext.
	 * @param iv_length The length of the IV.
	 * @param plaintext The buffer to hold the decrypted data.  The plaintext will be the same
	 * length as the ciphertext.  This buffer may be the same as the input ciphertext buffer.
	 * @param out_length The size of the output buffer.
	 *
	 * @return 0 if the data was decrypted successfully or an error code.
	 */
	int (*decrypt_data) (struct aes_engine *engine, const uint8_t *ciphertext, size_t length,
		const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
		size_t out_length);

	/**
	 * Decrypt data using AES-GCM mode.
	 * This function accepts optional data to be included in MAC validation.
	 * The operation must be initialized with a key prior to calling this function.
	 *
	 * @param engine The AES engine to use for decryption.
	 * @param ciphertext The encrypted data to decrypt.
	 * @param length The length of the encrypted data.
	 * @param tag The GCM tag for the ciphertext.  This must be 16 bytes.
	 * @param iv The initialization vector used to generate the ciphertext.
	 * @param iv_length The length of the IV.
	 * @param additional_data Optional data to be included in MAC validation.
	 * @param additional_data_length The length of the additional data.
	 * @param plaintext The buffer to hold the decrypted data.  The plaintext will be the same
	 * length as the ciphertext. This buffer may be the same as the input ciphertext buffer.
	 * @param out_length The size of the output buffer.
	 *
	 * @return 0 if the data was decrypted successfully or an error code.
	 */
	int (*decrypt_with_add_data) (struct aes_engine *engine, const uint8_t *ciphertext,
		size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length,
		const uint8_t *additional_data, size_t additional_data_length, uint8_t *plaintext,
		size_t out_length);
};


#define	AES_ENGINE_ERROR(code)		ROT_ERROR (ROT_MODULE_AES_ENGINE, code)

/**
 * Error codes that can be generated by an AES-GCM engine.
 */
enum {
	AES_ENGINE_INVALID_ARGUMENT = AES_ENGINE_ERROR (0x00),			/**< Input parameter is null or not valid. */
	AES_ENGINE_NO_MEMORY = AES_ENGINE_ERROR (0x01),					/**< Memory allocation failed. */
	AES_ENGINE_SET_KEY_FAILED = AES_ENGINE_ERROR (0x02),			/**< The encryption key could not be set. */
	AES_ENGINE_ENCRYPT_FAILED = AES_ENGINE_ERROR (0x03),			/**< The ciphertext was not decrypted. */
	AES_ENGINE_DECRYPT_FAILED = AES_ENGINE_ERROR (0x04),			/**< The plaintext was not encrypted. */
	AES_ENGINE_UNSUPPORTED_KEY_LENGTH = AES_ENGINE_ERROR (0x05),	/**< The encryption key length is not supported by the engine. */
	AES_ENGINE_INVALID_KEY_LENGTH = AES_ENGINE_ERROR (0x06),		/**< The key length is not a valid AES key length. */
	AES_ENGINE_OUT_BUFFER_TOO_SMALL = AES_ENGINE_ERROR (0x07),		/**< Not enough space in an output buffer provided for the operation. */
	AES_ENGINE_NO_KEY = AES_ENGINE_ERROR (0x08),					/**< No key was set prior to encryption/decryption. */
	AES_ENGINE_GCM_AUTH_FAILED = AES_ENGINE_ERROR (0x09),			/**< The decrypted plaintext failed authentication. */
	AES_ENGINE_HW_NOT_INIT = AES_ENGINE_ERROR (0x0a),				/**< The AES hardware has not been initialized. */
	AES_ENGINE_SELF_TEST_FAILED = AES_ENGINE_ERROR (0x0b),			/**< An internal self-test of the AES engine failed. */
	AES_ENGINE_UNSUPPORTED_OPERATION = AES_ENGINE_ERROR (0x0c),		/**< The requested operation is not supported. */
};


#endif	/* AES_H_ */
