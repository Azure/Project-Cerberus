// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_H_
#define RSA_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "hash.h"


#define	RSA_KEY_LENGTH_4K		(4096 / 8)
#define	RSA_KEY_LENGTH_3K		(3072 / 8)
#define	RSA_KEY_LENGTH_2K		(2048 / 8)


/* Configurable RSA parameters.  Defaults can be overridden in platform_config.h. */
#include "platform_config.h"
#ifndef RSA_MAX_KEY_LENGTH
#define	RSA_MAX_KEY_LENGTH		RSA_KEY_LENGTH_4K
#endif


/**
 * Context for an RSA private key.  A private key context can only be used by the engine that
 * allocated it.
 */
struct rsa_private_key {
	void *context;
};

/**
 * Defines the information for an RSA public key.
 */
#pragma pack(push,1)
struct rsa_public_key {
	uint8_t modulus[RSA_MAX_KEY_LENGTH];	/**< The RSA key pair modulus. */
	size_t mod_length;						/**< The length of the modulus. */
	uint32_t exponent;						/**< The RSA public exponent. */
};
#pragma pack(pop)

/**
 * A platform-independent API for using RSA key pairs.  RSA engine instances are not guaranteed to
 * be thread-safe.
 */
struct rsa_engine {
#ifdef RSA_ENABLE_PRIVATE_KEY
	/**
	 * Generate a random RSA key.
	 *
	 * @param engine The RSA engine to use to generate the key.
	 * @param key The key instance to initialize with the new key.
	 * @param bits The length of the RSA key, in bits.
	 *
	 * @return 0 if the key was successfully generated or an error code.
	 */
	int (*generate_key) (struct rsa_engine *engine, struct rsa_private_key *key, int bits);

	/**
	 * Load a DER formatted RSA private key.
	 *
	 * @param engine The RSA engine to initialize the key with.
	 * @param key The key instance to initialize.
	 * @param der The DER formatted private key data.
	 * @param length The length of the key data.
	 *
	 * @return 0 if the key was successfully initialized or an error code.
	 */
	int (*init_private_key) (struct rsa_engine *engine, struct rsa_private_key *key,
		const uint8_t *der, size_t length);

	/**
	 * Release an RSA key.  The memory for a released key will be zeroed.
	 *
	 * @param engine The RSA engine that initialized the key.
	 * @param key The key to release.
	 */
	void (*release_key) (struct rsa_engine *engine, struct rsa_private_key *key);

	/**
	 * Get the DER formatted private key for an RSA key pair.
	 *
	 * @param engine The RSA engine that initialized the key.
	 * @param key The private key to format as DER.
	 * @param der Output buffer for the DER formatted private key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_private_key_der) (struct rsa_engine *engine, const struct rsa_private_key *key,
		uint8_t **der, size_t *length);

	/**
	 * Decrypt data with an RSA private key.  The data is expected to have used OAEP padding.
	 *
	 * @param engine The RSA engine to use to decrypt the data.
	 * @param key The key to use for decryption.
	 * @param encrypted The encrypted data to decrypt.
	 * @param in_length The length of the encrypted data.
	 * @param label An optional label used to encrypt the data.
	 * @param label_length The length of the optional encryption label.
	 * @param pad_hash The hashing algorithm used for padding generation.
	 * @param decrypted The buffer to hold the decrypted data.
	 * @param out_length The size of the output buffer.
	 *
	 * @return The length of the decrypted data or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*decrypt) (struct rsa_engine *engine, const struct rsa_private_key *key,
		const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
		enum hash_type pad_hash, uint8_t *decrypted, size_t out_length);
#endif

#ifdef RSA_ENABLE_DER_PUBLIC_KEY
	/**
	 * Load a DER formatted RSA public key.
	 *
	 * @param engine The RSA engine to initialize the key with.
	 * @param key The key instance to initialize.
	 * @param der The DER formatted public key data.
	 * @param length The length of the key data.
	 *
	 * @return 0 if the key was successfully initialized or an error code.
	 */
	int (*init_public_key) (struct rsa_engine *engine, struct rsa_public_key *key,
		const uint8_t *der, size_t length);

	/**
	 * Get the DER formatted public key for an RSA private key.
	 *
	 * @param engine The RSA engine that initialized the key.
	 * @param key The private key to get the public key for.
	 * @param der Output buffer for the DER formatted public key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_public_key_der) (struct rsa_engine *engine, const struct rsa_private_key *key,
		uint8_t **der, size_t *length);
#endif

	/**
	 * Verify that a signature matches the expected SHA-256 hash.  The signature is expected to be
	 * in PKCS v1.5 format.
	 *
	 * @param engine The RSA engine to use for signature validation.
	 * @param key The public key to decrypt the signature.
	 * @param signature The signature to validate.
	 * @param sig_length The length of the signature.
	 * @param match The value that should match the decrypted signature.
	 * @param match_length The length of the match value.
	 *
	 * @return 0 if the signature matches the digest or an error code.
	 */
	int (*sig_verify) (struct rsa_engine *engine, const struct rsa_public_key *key,
		const uint8_t *signature, size_t sig_length, const uint8_t *match, size_t match_length);
};


bool rsa_same_public_key (const struct rsa_public_key *key1, const struct rsa_public_key *key2);


#define	RSA_ENGINE_ERROR(code)		ROT_ERROR (ROT_MODULE_RSA_ENGINE, code)

/**
 * Error codes that can be generated by an RSA engine.
 */
enum {
	RSA_ENGINE_INVALID_ARGUMENT = RSA_ENGINE_ERROR (0x00),			/**< Input parameter is null or not valid. */
	RSA_ENGINE_NO_MEMORY = RSA_ENGINE_ERROR (0x01),					/**< Memory allocation failed. */
	RSA_ENGINE_GENERATE_KEY_FAILED = RSA_ENGINE_ERROR (0x02),		/**< Failed to generate a random RSA key pair. */
	RSA_ENGINE_KEY_PAIR_FAILED = RSA_ENGINE_ERROR (0x03),			/**< Failed to initialize a private key from DER data. */
	RSA_ENGINE_PRIVATE_KEY_DER_FAILED = RSA_ENGINE_ERROR (0x04),	/**< The private key was not encoded to DER. */
	RSA_ENGINE_PUBLIC_KEY_DER_FAILED = RSA_ENGINE_ERROR (0x05),		/**< The public key was not encoded to DER. */
	RSA_ENGINE_DECRYPT_FAILED = RSA_ENGINE_ERROR (0x06),			/**< The data was not decrypted. */
	RSA_ENGINE_VERIFY_FAILED = RSA_ENGINE_ERROR (0x07),				/**< A error unrelated to signature checking caused verification to fail. */
	RSA_ENGINE_NOT_RSA_KEY = RSA_ENGINE_ERROR (0x08),				/**< Key data does not contain an RSA key. */
	RSA_ENGINE_NOT_PRIVATE_KEY = RSA_ENGINE_ERROR (0x09),			/**< The key is not a private key. */
	RSA_ENGINE_OUT_BUFFER_TOO_SMALL = RSA_ENGINE_ERROR (0x0a),		/**< Not enough space in the output buffer for decryption. */
	RSA_ENGINE_BAD_SIGNATURE = RSA_ENGINE_ERROR (0x0b),				/**< RSA signature verification failed. */
	RSA_ENGINE_HW_NOT_INIT = RSA_ENGINE_ERROR (0x0c),				/**< The RSA hardware has not been initialized. */
	RSA_ENGINE_PUBLIC_KEY_FAILED = RSA_ENGINE_ERROR (0x0d),			/**< Failed to initialize a public key from DER data. */
	RSA_ENGINE_UNSUPPORTED_KEY_LENGTH = RSA_ENGINE_ERROR (0x0e),	/**< The RSA key length is not supported. */
	RSA_ENGINE_UNSUPPORTED_HASH_TYPE = RSA_ENGINE_ERROR (0x0f),		/**< The encryption hash type is not supported. */
	RSA_ENGINE_SELF_TEST_FAILED = RSA_ENGINE_ERROR (0x10),			/**< An internal self-test of the RSA engine failed. */
};


#endif /* RSA_H_ */
