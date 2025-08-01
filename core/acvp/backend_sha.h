// Copyright (c) Microsoft Corporation. All rights reserved.

#ifndef BACKEND_SHA_H_
#define BACKEND_SHA_H_

#include <stdbool.h>
#include <stddef.h>
#include "crypto/hash.h"
#include "parser/parser_sha.h"


/**
 * Backend SHA engine structure used for ACVP test handling.
 */
struct backend_sha_engine {
	int impl_id;						/**< Implementation identifier. */
	bool is_one_shot;					/**< Flag indicating if the engine uses one-shot or multi-update hash operation(s) */
	const struct hash_engine *engine;	/**< Hash instance to use. */
};


const struct sha_backend* backend_sha_get_impl ();


void backend_sha_register_engines (const struct backend_sha_engine *sha, size_t num_engines);
void backend_sha_register_impl (void);


#define BACKEND_SHA_ERROR(code)		ROT_ERROR (ROT_MODULE_BACKEND_SHA, code)

/**
 * Error codes that can be generated by backend SHA handling.
 */
enum {
	BACKEND_SHA_INVALID_ARGUMENT = BACKEND_SHA_ERROR (0x00),				/**< Input parameter is null or not valid. */
	BACKEND_SHA_NO_MEMORY = BACKEND_SHA_ERROR (0x01),						/**< Memory allocation failed. */
	BACKEND_SHA_NO_ENGINE = BACKEND_SHA_ERROR (0x02),						/**< No SHA engine is available. */
	BACKEND_SHA_ENGINE_NOT_FOUND = BACKEND_SHA_ERROR (0x03),				/**< No SHA engine found for the specified implementation. */
	BACKEND_SHA_ENGINE_HASH_GENERATE_FAILED = BACKEND_SHA_ERROR (0x04),		/**< SHA hash generation failed. */
	BACKEND_SHA_ENGINE_MCT_INNER_LOOP_FAILED = BACKEND_SHA_ERROR (0x05),	/**< SHA MCT inner loop failed. */
	BACKEND_SHA_UNEXPECTED_HASH_LENGTH = BACKEND_SHA_ERROR (0x06),			/**< SHA hash length does not match the expected length. */
};


#endif	/* BACKEND_SHA_H_ */
