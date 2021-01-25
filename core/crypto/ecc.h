// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_H_
#define ECC_H_

#include <stdint.h>
#include <stddef.h>
#include "platform_config.h"
#include "status/rot_status.h"


/* Confiugrable ECC parameters.  Defaults can be overridden in platform_config.h. */
#ifndef ECC_MAX_KEY_LENGTH
#define	ECC_MAX_KEY_LENGTH		521
#endif

/**
 * Length of the public key portion of a maximum length ECC DER key.
 */
#define ECC_MAX_PUBKEY_DER_LEN	(((ECC_MAX_KEY_LENGTH / 8) + 1) * 2 + 32)


/**
 * An ECC private key.  A key instance is only usable by the engine that initialized it.
 */
struct ecc_private_key {
	void *context;		/**< The implementation context for the private key. */
};

/**
 * An ECC public key.  A key instance is only usable by the engine that initialized it.
 */
struct ecc_public_key {
	void *context;		/**< The implementation context for the public key. */
};

/**
 * A platform-independent API for generating and using ECC key pairs.  ECC engine instances are not
 * guaranteed to be thread-safe.
 */
struct ecc_engine {
	/**
	 * Initialize an ECC key pair to be used by the ECC engine.
	 *
	 * @param engine The ECC engine to use for key initialization.
	 * @param key The private key to use for key initialization.
	 * @param key_length The length of the private key data.
	 * @param priv_key Output for the initialized private key.  This can be null to skip private key
	 * initialization.
	 * @param pub_key Output for the initialized public key.  This can be null to skip public key
	 * initialization.
	 *
	 * @return 0 if the key pair was successfully initialized or an error code.
	 */
	int (*init_key_pair) (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
		struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);

	/**
	 * Initialize an ECC public key to be used by the ECC engine.
	 *
	 * @param engine The ECC engine to use for key initialization.
	 * @param key The public key to use for key initialization.
	 * @param key_length The length of the public key data.
	 * @param pub_key Output for the initialized public key.
	 *
	 * @return 0 if the public key was successfully initialized or an error code.
	 */
	int (*init_public_key) (struct ecc_engine *engine, const uint8_t *key, size_t key_length,
		struct ecc_public_key *pub_key);

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	/**
	 * Generate an ECC key pair using a specified value for the private key.
	 *
	 * @param engine The ECC engine to use to generate the key pair.
	 * @param priv The private value to use for key generation.
	 * @param key_length The length of the private key.
	 * @param priv_key Output for the generated private key.  This can be null to skip private key
	 * generation.
	 * @param pub_key Output for the generated public key.  This can be null to skip public key
	 * generation.
	 *
	 * @return 0 if the key pair was successfully generated or an error code.
	 */
	int (*generate_derived_key_pair) (struct ecc_engine *engine, const uint8_t *priv,
		size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);

	/**
	 * Generate a random ECC key pair.
	 *
	 * @param engine The ECC engine to use to generate the key pair.
	 * @param priv_key Output for the generated private key.  This can be null to skip private key
	 * generation.
	 * @param pub_key Output for the generated public key.  This can be null to skip public key
	 * generation.
	 *
	 * @return 0 if the key pair was successfully generated or an error code.
	 */
	int (*generate_key_pair) (struct ecc_engine *engine, struct ecc_private_key *priv_key,
		struct ecc_public_key *pub_key);
#endif

	/**
	 * Release ECC keys.  The memory for released keys will be zeroed.
	 *
	 * @param engine The ECC engine used to generated the keys.
	 * @param priv_key The private key to release.  This can be null to not release a private key.
	 * @param pub_key The public key to release.  This can be null to not release a public key.
	 */
	void (*release_key_pair) (struct ecc_engine *engine, struct ecc_private_key *priv_key,
		struct ecc_public_key *pub_key);

	/**
	 * Get the maximum length for a ECDSA signature generated using a given key.
	 *
	 * @param engine The ECC engine to query.
	 * @param key The private key that would be used for the signature.
	 *
	 * @return The maximum number of signature bytes or an error code.  Use ROT_IS_ERROR to check
	 * the return value.
	 */
	int (*get_signature_max_length) (struct ecc_engine *engine, struct ecc_private_key *key);

#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
	/**
	 * Encode an ECC private key in DER format.
	 *
	 * @param engine The ECC engine used to generate the key.
	 * @param key The private key to encode to DER.
	 * @param der Output buffer for the DER formatted private key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_private_key_der) (struct ecc_engine *engine, const struct ecc_private_key *key,
		uint8_t **der, size_t *length);

	/**
	 * Encode an ECC public key in DER format.
	 *
	 * @param engine The ECC engine used to generate the key.
	 * @param key The public key to encode to DER.
	 * @param der Output buffer for the DER formatted public key.  This is a dynamically allocated
	 * buffer, and it is the responsibility of the caller to free it.  This will return null in the
	 * case of an error.
	 * @param length Output for the length of the DER key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*get_public_key_der) (struct ecc_engine *engine, const struct ecc_public_key *key,
		uint8_t **der, size_t *length);
#endif

	/**
	 * Create an ECDSA signature for a SHA-256 message digest.
	 *
	 * @param engine The ECC engine to use to sign the digest.
	 * @param key The private key to sign with.
	 * @param digest The message digest to use to generate the signature.
	 * @param length The length of the digest.
	 * @param signature Output buffer for the ECDSA signature.
	 * @param sig_length The length of the signature output buffer.
	 *
	 * @return The length of the signature or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*sign) (struct ecc_engine *engine, struct ecc_private_key *key, const uint8_t *digest,
		size_t length, uint8_t *signature, size_t sig_length);

	/**
	 * Verify an ECDSA signature against a SHA-256 message digest.
	 *
	 * @param engine The ECC engine to use for signature verification.
	 * @param key The public key to verify the signature with.
	 * @param digest The message digest to use for signature verification.
	 * @param length The length of the digest.
	 * @param signature The ECDSA signature to verify.
	 * @param sig_length The length of the signature.
	 *
	 * @return 0 if the signature matches the digest or an error code.
	 */
	int (*verify) (struct ecc_engine *engine, struct ecc_public_key *key, const uint8_t *digest,
		size_t length, const uint8_t *signature, size_t sig_length);

#ifdef ECC_ENABLE_ECDH
	/**
	 * Get the maximum length for an ECDH shared secret generated using a given key.
	 *
	 * @param engine The ECC engine to query.
	 * @param key The private key that would be used to generate the secret.
	 *
	 * @return The maximum number of bytes in the secret or an error code.  Use ROT_IS_ERROR to
	 * check the return value.
	 */
	int (*get_shared_secret_max_length) (struct ecc_engine *engine, struct ecc_private_key *key);

	/**
	 * Generate the ECDH shared secret for a pair of keys.
	 *
	 * @param engine The ECC engine to use to generate the secret.
	 * @param priv_key The private key to use to generate the secret.
	 * @param pub_key The public key to use to generate the secret.
	 * @param secret Output buffer to hold the generated secret.  This is the raw data generated by
	 * ECDH which can be fed into additional key derivation functions, as appropriate.
	 * @param length The length of the secret buffer.
	 *
	 * @return The length of the shared secret or an error code.  Use ROT_IS_ERROR to check the
	 * return value.
	 */
	int (*compute_shared_secret) (struct ecc_engine *engine, struct ecc_private_key *priv_key,
		struct ecc_public_key *pub_key, uint8_t *secret, size_t length);
#endif
};


#define	ECC_ENGINE_ERROR(code)		ROT_ERROR (ROT_MODULE_ECC_ENGINE, code)

/**
 * Error codes that can be generated by an ECC engine.
 */
enum {
	ECC_ENGINE_INVALID_ARGUMENT = ECC_ENGINE_ERROR (0x00),			/**< Input parameter is null or not valid. */
	ECC_ENGINE_NO_MEMORY = ECC_ENGINE_ERROR (0x01),					/**< Memory allocation failed. */
	ECC_ENGINE_KEY_PAIR_FAILED = ECC_ENGINE_ERROR (0x02),			/**< Failed to initialize a key pair from DER data. */
	ECC_ENGINE_PUBLIC_KEY_FAILED = ECC_ENGINE_ERROR (0x03),			/**< Failed to initialize a public key from DER data. */
	ECC_ENGINE_DERIVED_KEY_FAILED = ECC_ENGINE_ERROR (0x04),		/**< Failed to generate a deterministic key pair. */
	ECC_ENGINE_GENERATE_KEY_FAILED = ECC_ENGINE_ERROR (0x05),		/**< Failed to generate a random key pair. */
	ECC_ENGINE_PRIVATE_KEY_DER_FAILED = ECC_ENGINE_ERROR (0x06),	/**< The private key was not encoded to DER. */
	ECC_ENGINE_PUBLIC_KEY_DER_FAILED = ECC_ENGINE_ERROR (0x07),		/**< The public key was not encoded to DER. */
	ECC_ENGINE_SIGN_FAILED = ECC_ENGINE_ERROR (0x08),				/**< The ECDSA signature was not generated. */
	ECC_ENGINE_VERIFY_FAILED = ECC_ENGINE_ERROR (0x09),				/**< A error unrelated to signature checking caused verification to fail. */
	ECC_ENGINE_SHARED_SECRET_FAILED = ECC_ENGINE_ERROR (0x0a),		/**< The ECDH secret was not generated. */
	ECC_ENGINE_NOT_EC_KEY = ECC_ENGINE_ERROR (0x0b),				/**< Key data does not contain an EC key. */
	ECC_ENGINE_NOT_PRIVATE_KEY = ECC_ENGINE_ERROR (0x0c),			/**< The key is not a private key. */
	ECC_ENGINE_NOT_PUBLIC_KEY = ECC_ENGINE_ERROR (0x0d),			/**< The key is not a public key. */
	ECC_ENGINE_SIG_BUFFER_TOO_SMALL = ECC_ENGINE_ERROR (0x0e),		/**< There is not enough buffer space to store the signature. */
	ECC_ENGINE_SECRET_BUFFER_TOO_SMALL = ECC_ENGINE_ERROR (0x0f),	/**< There is not enough buffer space to store the ECDH secret. */
	ECC_ENGINE_BAD_SIGNATURE = ECC_ENGINE_ERROR (0x10),				/**< ECDSA signature verification failed. */
	ECC_ENGINE_HW_NOT_INIT = ECC_ENGINE_ERROR (0x11),				/**< The ECC hardware has not been initialized. */
	ECC_ENGINE_SIG_LENGTH_FAILED = ECC_ENGINE_ERROR (0x12),			/**< Failed to get the maximum signature length. */
	ECC_ENGINE_SECRET_LENGTH_FAILED = ECC_ENGINE_ERROR (0x13),		/**< Failed to get the maximum shared secret length. */
};


#endif /* ECC_H_ */
