// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_H_
#define HASH_H_

#include <stddef.h>
#include <stdint.h>
#include "status/rot_status.h"


/* Hash lengths */
#define	SHA1_HASH_LENGTH	(160 / 8)
#define SHA256_HASH_LENGTH	(256 / 8)
#define	SHA384_HASH_LENGTH	(384 / 8)
#define	SHA512_HASH_LENGTH	(512 / 8)

#define	SHA1_BLOCK_SIZE		(512 / 8)
#define	SHA256_BLOCK_SIZE	(512 / 8)
#define	SHA384_BLOCK_SIZE	(1024 / 8)
#define	SHA512_BLOCK_SIZE	(1024 / 8)


/**
 * The types of hashes supported by the hashing API.
 */
enum hash_type {
	HASH_TYPE_SHA1,						/**< SHA-1 hash */
	HASH_TYPE_SHA256,					/**< SHA2-256 hash */
	HASH_TYPE_SHA384,					/**< SHA2-384 hash */
	HASH_TYPE_SHA512,					/**< SHA2-512 hash */
};

/* Definitions of hash engine state for internal implementation use, as necessary.  These map to
 * enum hash_type, except there is the added value indicating there is no active context. */
enum {
	HASH_ACTIVE_SHA1 = HASH_TYPE_SHA1,	/**< SHA-1 context is active. */
	HASH_ACTIVE_SHA256,					/**< SHA2-256 context is active. */
	HASH_ACTIVE_SHA384,					/**< SHA2-384 context is active. */
	HASH_ACTIVE_SHA512,					/**< SHA2-512 context is active. */
	HASH_ACTIVE_NONE = 0xff,			/**< No hash context is active. */
};


/**
 * A platform-independent API for calculating hashes.  Hash engine instances are not guaranteed to
 * be thread-safe.
 */
struct hash_engine {
#ifdef HASH_ENABLE_SHA1
	/**
	 * Calculate the SHA-1 hash on a complete set of data.
	 *
	 * @param engine The hash engine to use to calculate the hash.
	 * @param data The data to hash.
	 * @param length The length of the data.
	 * @param hash The buffer that will contain the generated hash.  It must be large enough to hold
	 * at least SHA1_HASH_LENGTH bytes.
	 * @param hash_length The size of the hash buffer.
	 *
	 * @return 0 if the hash calculated successfully or an error code.
	 */
	int (*calculate_sha1) (struct hash_engine *engine, const uint8_t *data, size_t length,
		uint8_t *hash, size_t hash_length);

	/**
	 * Configure the hash engine to process independent blocks of data to calculate the SHA-1 hash
	 * of the aggregated data.
	 *
	 * Every call to start MUST be followed by either a call to finish or cancel.
	 *
	 * @param engine The hash engine to configure.
	 *
	 * @return 0 if the hash engine was configured successfully or an error code.
	 */
	int (*start_sha1) (struct hash_engine *engine);
#endif

	/**
	 * Calculate the SHA2-256 hash on a complete set of data.
	 *
	 * @param engine The hash engine to use to calculate the hash.
	 * @param data The data to hash.
	 * @param length The length of the data.
	 * @param hash The buffer that will contain the generated hash.  It must be large enough to hold
	 * at least SHA256_HASH_LENGTH bytes.
	 * @param hash_length The size of the hash buffer.
	 *
	 * @return 0 if the hash calculated successfully or an error code.
	 */
	int (*calculate_sha256) (struct hash_engine *engine, const uint8_t *data, size_t length,
		uint8_t *hash, size_t hash_length);

	/**
	 * Configure the hash engine to process independent blocks of data to calculate the SHA2-256
	 * hash of the aggregated data.
	 *
	 * Every call to start MUST be followed by either a call to finish or cancel.
	 *
	 * @param engine The hash engine to configure.
	 *
	 * @return 0 if the hash engine was configured successfully or an error code.
	 */
	int (*start_sha256) (struct hash_engine *engine);

#ifdef HASH_ENABLE_SHA384
	/**
	 * Calculate the SHA2-384 hash on a complete set of data.
	 *
	 * @param engine The hash engine to use to calculate the hash.
	 * @param data The data to hash.
	 * @param length The length of the data.
	 * @param hash The buffer that will contain the generated hash.  It must be large enough to hold
	 * at least SHA384_HASH_LENGTH bytes.
	 * @param hash_length The size of the hash buffer.
	 *
	 * @return 0 if the hash calculated successfully or an error code.
	 */
	int (*calculate_sha384) (struct hash_engine *engine, const uint8_t *data, size_t length,
		uint8_t *hash, size_t hash_length);

	/**
	 * Configure the hash engine to process independent blocks of data to calculate the SHA2-384
	 * hash of the aggregated data.
	 *
	 * Every call to start MUST be followed by either a call to finish or cancel.
	 *
	 * @param engine The hash engine to configure.
	 *
	 * @return 0 if the hash engine was configured successfully or an error code.
	 */
	int (*start_sha384) (struct hash_engine *engine);
#endif

#ifdef HASH_ENABLE_SHA512
	/**
	 * Calculate the SHA2-512 hash on a complete set of data.
	 *
	 * @param engine The hash engine to use to calculate the hash.
	 * @param data The data to hash.
	 * @param length The length of the data.
	 * @param hash The buffer that will contain the generated hash.  It must be large enough to hold
	 * at least SHA512_HASH_LENGTH bytes.
	 * @param hash_length The size of the hash buffer.
	 *
	 * @return 0 if the hash calculated successfully or an error code.
	 */
	int (*calculate_sha512) (struct hash_engine *engine, const uint8_t *data, size_t length,
		uint8_t *hash, size_t hash_length);

	/**
	 * Configure the hash engine to process independent blocks of data to calculate the SHA2-512
	 * hash of the aggregated data.
	 *
	 * Every call to start MUST be followed by either a call to finish or cancel.
	 *
	 * @param engine The hash engine to configure.
	 *
	 * @return 0 if the hash engine was configured successfully or an error code.
	 */
	int (*start_sha512) (struct hash_engine *engine);
#endif

	/**
	 * Update the current hash operation with a block of data.
	 *
	 * @param engine The hash engine to update.
	 * @param data The data that should be added to generate the final hash.
	 * @param length The length of the data.
	 *
	 * @return 0 if the hash operation was updated successfully or an error code.
	 */
	int (*update) (struct hash_engine *engine, const uint8_t *data, size_t length);

	/**
	 * Complete the current hash operation and get the calculated digest.
	 *
	 * If a call to finish fails, finish MUST be called until it succeeds or the operation can be
	 * terminated with a call to cancel.
	 *
	 * @param engine The hash engine to get the final hash from.
	 * @param hash The buffer to hold the completed hash.
	 * @param hash_length The length of the hash buffer.
	 *
	 * @return 0 if the hash was completed successfully or an error code.
	 */
	int (*finish) (struct hash_engine *engine, uint8_t *hash, size_t hash_length);

	/**
	 * Cancel an in-progress hash operation without getting the hash values.  After canceling, any
	 * intermediate hash calculations will be lost and a new hash operation can be started.
	 *
	 * @param engine The hash engine to cancel.
	 */
	void (*cancel) (struct hash_engine *engine);
};


int hash_start_new_hash (struct hash_engine *engine, enum hash_type type);
int hash_calculate (struct hash_engine *engine, enum hash_type type, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);

int hash_get_hash_len (enum hash_type hash_type);



/* HMAC functions */

/**
 * The types of hashes that can be used to generate an HMAC.
 */
enum hmac_hash {
	HMAC_SHA1 = HASH_TYPE_SHA1,			/**< HMAC with SHA-1 hash. */
	HMAC_SHA256 = HASH_TYPE_SHA256,		/**< HMAC with SHA-256 hash. */
	HMAC_SHA384 = HASH_TYPE_SHA384,		/**< HMAC with SHA-384 hash. */
	HMAC_SHA512 = HASH_TYPE_SHA512,		/**< HMAC with SHA-512 hash. */
};

/**
 * A context for generating an HMAC using partial sets of data.
 */
struct hmac_engine {
	struct hash_engine *hash;			/**< The hash engine to use when generating the HMAC. */
	enum hmac_hash type;				/**< The type of hash being used for the HMAC. */
	uint8_t key[SHA512_BLOCK_SIZE];		/**< The key for the HMAC operation. */
	uint8_t block_size;					/**< The block size for the hash algorithm. */
	uint8_t hash_length;				/**< The digest length for the hash algorithm. */
};


int hash_generate_hmac (struct hash_engine *engine, const uint8_t *key, size_t key_length,
	const uint8_t *data, size_t length, enum hmac_hash hash, uint8_t *hmac, size_t hmac_length);

int hash_hmac_init (struct hmac_engine *engine, struct hash_engine *hash, enum hmac_hash hash_type,
	const uint8_t *key, size_t key_length);
int hash_hmac_update (struct hmac_engine *engine, const uint8_t *data, size_t length);
int hash_hmac_finish (struct hmac_engine *engine, uint8_t *hmac, size_t hmac_length);
void hash_hmac_cancel (struct hmac_engine *engine);


#define	HASH_ENGINE_ERROR(code)		ROT_ERROR (ROT_MODULE_HASH_ENGINE, code)

/**
 * Error codes that can be generated by a hash or HMAC engine.
 */
enum {
	HASH_ENGINE_INVALID_ARGUMENT = HASH_ENGINE_ERROR (0x00),		/**< Input parameter is null or not valid. */
	HASH_ENGINE_NO_MEMORY = HASH_ENGINE_ERROR (0x01),				/**< Memory allocation failed. */
	HASH_ENGINE_SHA1_FAILED = HASH_ENGINE_ERROR (0x02),				/**< The SHA-1 hash was not calculated. */
	HASH_ENGINE_SHA256_FAILED = HASH_ENGINE_ERROR (0x03),			/**< The SHA-256 hash was not calculated. */
	HASH_ENGINE_START_SHA1_FAILED = HASH_ENGINE_ERROR (0x04),		/**< The engine has not been initialized for SHA-1. */
	HASH_ENGINE_START_SHA256_FAILED = HASH_ENGINE_ERROR (0x05),		/**< The engine has not been initialized for SHA-256. */
	HASH_ENGINE_UPDATE_FAILED = HASH_ENGINE_ERROR (0x06),			/**< The hash has not been updated with new data. */
	HASH_ENGINE_FINISH_FAILED = HASH_ENGINE_ERROR (0x07),			/**< The hash was not calculated. */
	HASH_ENGINE_HASH_BUFFER_TOO_SMALL = HASH_ENGINE_ERROR (0x08),	/**< The output buffer is not large enough for the specified hash. */
	HASH_ENGINE_NO_ACTIVE_HASH = HASH_ENGINE_ERROR (0x09),			/**< No hash has been started for calculation. */
	HASH_ENGINE_UNSUPPORTED_HASH = HASH_ENGINE_ERROR (0x0a),		/**< The hash is not supported by the engine. */
	HASH_ENGINE_HW_NOT_INIT = HASH_ENGINE_ERROR (0x0b),				/**< The hash hardware has not been initialized. */
	HASH_ENGINE_SHA384_FAILED = HASH_ENGINE_ERROR (0x0c),			/**< The SHA-384 hash was not calculated. */
	HASH_ENGINE_SHA512_FAILED = HASH_ENGINE_ERROR (0x0d),			/**< The SHA-512 hash was not calculated. */
	HASH_ENGINE_START_SHA384_FAILED = HASH_ENGINE_ERROR (0x0e),		/**< The engine has not been initialized for SHA-384. */
	HASH_ENGINE_START_SHA512_FAILED = HASH_ENGINE_ERROR (0x0f),		/**< The engine has not been initialized for SHA-512. */
	HASH_ENGINE_UNKNOWN_HASH = HASH_ENGINE_ERROR (0x10),			/**< An unknown hash type was requested. */
	HASH_ENGINE_HASH_IN_PROGRESS = HASH_ENGINE_ERROR (0x11),		/**< Attempt to start a new hash before finishing the previous one. */
	HASH_ENGINE_SELF_TEST_FAILED = HASH_ENGINE_ERROR (0x12),		/**< An internal self-test of the hash engine failed. */
};


#endif /* HASH_H_ */
