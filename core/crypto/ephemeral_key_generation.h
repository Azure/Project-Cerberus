// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef EPHEMERAL_KEY_GENERATION_H_
#define EPHEMERAL_KEY_GENERATION_H_

#include <stdint.h>
#include <string.h>
#include "status/rot_status.h"


/**
 * Define Ephemeral Key Generation.
 */
struct ephemeral_key_generation {
	/**
	 * Generate an ephemeral key for a given key length in bits
	 *
	 * @param key_gen A pointer to ephemeral key generation.
	 * @param key_size - Defines key size in number of bits.
	 * @param key - Output buffer for the DER encoded cryptographic key.  This is a dynamically
	 * allocated buffer, and caller API must free it using platform_free() when this pointer is not
	 * null.  This will return null in the case of an error.
	 * @param key_length Output for the length of the DER encoded key.
	 *
	 * @return 0 if the key was successfully encoded or an error code.
	 */
	int (*generate_key) (const struct ephemeral_key_generation *key_gen, int key_size, uint8_t **key,
		size_t *key_length);
};


#define	EPHEMERAL_KEY_GEN_ERROR(code)	ROT_ERROR(ROT_MODULE_EPHEMERAL_KEY_GENERATION, code)

/**
 * Error codes that can be generated for ephemeral key generation.
 */
enum {
	EPHEMERAL_KEY_GEN_INVALID_ARGUMENT = EPHEMERAL_KEY_GEN_ERROR (0x00),			/**< Input parameter is null or not valid. */
	EPHEMERAL_KEY_GEN_NO_MEMORY = EPHEMERAL_KEY_GEN_ERROR (0x01),					/**< Memory allocation failed. */
	EPHEMERAL_KEY_GEN_PRIVATE_KEY_GEN_UNSUPPORTED = EPHEMERAL_KEY_GEN_ERROR (0x02),	/**< Requested operation not supported. */
	EPHEMERAL_KEY_GEN_GENERATE_KEY_FAILED = EPHEMERAL_KEY_GEN_ERROR (0x03),			/**< Key Generate API Failed. */
	EPHEMERAL_KEY_GEN_EXTRACT_KEY_FAILED = EPHEMERAL_KEY_GEN_ERROR (0x04),			/**< Key extract API Failed. */
	EPHEMERAL_KEY_GEN_PRIVATE_KEY_GEN_FAILED = EPHEMERAL_KEY_GEN_ERROR (0x05),		/**< Private key generation failed. */
};


#endif	/* EPHEMERAL_KEY_GENERATION_H_ */
