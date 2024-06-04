// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTH_TOKEN_H_
#define AUTH_TOKEN_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "platform_api.h"
#include "crypto/ecc.h"
#include "crypto/hash.h"
#include "crypto/rng.h"
#include "crypto/signature_verification.h"
#include "riot/riot_key_manager.h"
#include "status/rot_status.h"


/**
 * Variable context for authorization token management.
 */
struct auth_token_state {
	size_t token_length;		/**< Length of the active authorization token. */
	platform_clock expiration;	/**< Expiration time of the active token. */
};

/**
 * Manage a single authorization token for an authenticated workflow.
 */
struct auth_token {
	/**
	 * Create a new authorization token.  This will invalidate any previously created token.
	 *
	 * @param auth The token handler to use for token generation.
	 * @param data Optional context-specific data to add to the token.  The length of this data will
	 * be specified during initialization of the token handler.  If no data is provided, the context
	 * data in the token will be padded with zeros.
	 * @param data_length Length of the optional context-specific data provided for the token.  This
	 * must not be more than the additional length supported by the token.  If this length is
	 * smaller than what the token expects, the remaining length with be padded with zeros.  If the
	 * data buffer is null, this argument is ignored.
	 * @param token Output for the generated authorization token.  The memory for this token is
	 * owned by the token manager and must not be freed or otherwise changed by the caller.
	 * @param length Output for the length of the generated token.
	 *
	 * @return 0 if the authorization token was generated successfully or an error code.
	 */
	int (*new_token) (const struct auth_token *auth, const uint8_t *data, size_t data_length,
		const uint8_t **token, size_t *length);

	/**
	 * Check if data is authorized for use by the device.  Properly authorized data contains the
	 * current authorization token and is signed by the authorizing entity.
	 *
	 * @param auth The token handler to use for data verification.
	 * @param authorized The authorized data that should be checked for validity.  This must begin
	 * with the authorization token.
	 * @param length Total length of the authorized data, including signature.
	 * @param token_offset Offset within the authorized data where the authorization token starts.
	 * Data before this offset is included as part of the signature, but is not considered part of
	 * the AAD.
	 * @param aad_length Length of any Additional Authenticated Data present in the data.  This is
	 * data that is appended to the token before signing by the authorizing entity for use by the
	 * device.
	 * @param sig_hash Hash algorithm used by the authorizing entity when signing the token.
	 *
	 * @return 0 if the data is authorized for use or an error code.  If the token fails any
	 * verification check, AUTH_TOKEN_NOT_VALID will be returned.
	 */
	int (*verify_data) (const struct auth_token *auth, const uint8_t *authorized, size_t length,
		size_t token_offset, size_t aad_length, enum hash_type sig_hash);

	/**
	 * Invalidate any active authorization token.  Any future checks against this token will fail.
	 *
	 * @param auth The token handler for the token to invalidate.
	 *
	 * @return 0 if the token was successfully invalidated or error code.
	 */
	int (*invalidate) (const struct auth_token *auth);

	struct auth_token_state *state;					/**< Variable context for the token. */
	struct rng_engine *rng;							/**< RNG for nonce generation. */
	struct hash_engine *hash;						/**< Hash engine for token digests. */
	struct ecc_engine *ecc;							/**< ECC engine for token signing. */
	struct riot_key_manager *device_key;			/**< Manager for device key used to sign tokens. */
	const struct signature_verification *authority;	/**< Verification handler for the token signing authority. */
	const uint8_t *authority_key;					/**< Public key for the token signing authority. */
	size_t auth_key_length;							/**< Length of the authority public key. */
	uint8_t *buffer;								/**< Internal buffer for managing the active token. */
	size_t buffer_length;							/**< Size of the internal token buffer. */
	bool alloc_buffer;								/**< Flag indicating if the buffer was internally allocated. */
	size_t data_length;								/**< Length of the additional data prepended to the token. */
	size_t nonce_length;							/**< Length of the token nonce. */
	size_t sig_length;								/**< Maximum length of the token signature. */
	enum hash_type token_hash;						/**< Hash algorithm to use for token signing. */
	uint32_t validity_time;							/**< Length of time any token is valid. */
};


int auth_token_init (struct auth_token *auth, struct auth_token_state *state,
	struct rng_engine *rng, struct hash_engine *hash, struct ecc_engine *ecc,
	struct riot_key_manager *device_key, const uint8_t *authority_key, size_t key_length,
	const struct signature_verification *authority, size_t data_length, size_t nonce_length,
	enum hash_type sig_hash, uint32_t validity_time);
int auth_token_init_with_buffer (struct auth_token *auth, struct auth_token_state *state,
	struct rng_engine *rng, struct hash_engine *hash, struct ecc_engine *ecc,
	struct riot_key_manager *device_key, const uint8_t *authority_key, size_t key_length,
	const struct signature_verification *authority, size_t data_length, size_t nonce_length,
	enum hash_type sig_hash, uint32_t validity_time, uint8_t *token_buffer, size_t buffer_length);

int auth_token_init_dynamic_state (struct auth_token *auth);
int auth_token_init_state (const struct auth_token *auth);

void auth_token_release (const struct auth_token *auth);


#define	AUTH_TOKEN_ERROR(code)		ROT_ERROR (ROT_MODULE_AUTH_TOKEN, code)

/**
 * Error codes that can be generated by an authorization token handler.
 */
enum {
	AUTH_TOKEN_INVALID_ARGUMENT = AUTH_TOKEN_ERROR (0x00),	/**< Input parameter is null or not valid. */
	AUTH_TOKEN_NO_MEMORY = AUTH_TOKEN_ERROR (0x01),			/**< Memory allocation failed. */
	AUTH_TOKEN_BUILD_FAILED = AUTH_TOKEN_ERROR (0x02),		/**< Failed to build a new token. */
	AUTH_TOKEN_CHECK_FAILED = AUTH_TOKEN_ERROR (0x03),		/**< Failed to verify against the active token. */
	AUTH_TOKEN_INVALIDATE_FAILED = AUTH_TOKEN_ERROR (0x04),	/**< Failed to invalidate the active token. */
	AUTH_TOKEN_NOT_VALID = AUTH_TOKEN_ERROR (0x05),			/**< A token is not valid for the device. */
	AUTH_TOKEN_SMALL_BUFFER = AUTH_TOKEN_ERROR (0x06),		/**< The token buffer is not large enough. */
	AUTH_TOKEN_WRONG_SIG_LENGTH = AUTH_TOKEN_ERROR (0x07),	/**< The configured signature length does not match the token key. */
	AUTH_TOKEN_DATA_TOO_LONG = AUTH_TOKEN_ERROR (0x08),		/**< Too much context data was provided for the token. */
};


#endif	/* AUTH_TOKEN_H_ */
