// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RMA_UNLOCK_TOKEN_H_
#define RMA_UNLOCK_TOKEN_H_

#include <stddef.h>
#include <stdint.h>
#include "cmd_interface/cmd_device.h"
#include "crypto/hash.h"
#include "crypto/signature_verification.h"
#include "status/rot_status.h"


/**
 * Handler for authenticating token used to unlock device RMA transition.
 */
struct rma_unlock_token {
	/**
	 * Authenticate a received RMA unlock token.  An authorized token must:
	 * - Be signed by the token authority key.
	 * - Have the expected length and structure.
	 * - Match the device type OID, UUID, and device ID hash for the device.
	 *
	 * @param handler The RMA unlock handler to use for authentication.
	 * @param data The authorized RMA unlock token data to authenticate.
	 * @param length Length of the unlock token data.
	 *
	 * @return 0 if the RMA token is authorized or an error code.
	 */
	int (*authenticate) (const struct rma_unlock_token *handler, const uint8_t *data,
		size_t length);

	const struct hash_engine *hash;					/**< Hash engine for token digests. */
	const struct signature_verification *authority;	/**< Verification handler for the token signing authority. */
	const uint8_t *authority_key;					/**< Public key for the token signing authority. */
	size_t auth_key_length;							/**< Length of the authority public key. */
	enum hash_type auth_hash;						/**< Hash algorithm for data authentication. */
	const struct cmd_device *uuid;					/**< Interface to retrieve the device UUID. */
	const uint8_t *oid;								/**< OID for the device type. */
	size_t oid_length;								/**< Length of the device type OID. */
	const uint8_t *dice_hash;						/**< Digest of the DICE public key. */
	size_t dice_length;								/**< Length of the DICE key digest. */
};


int rma_unlock_token_init (struct rma_unlock_token *handler, const uint8_t *authority_key,
	size_t key_length, const struct signature_verification *authority,
	const struct hash_engine *hash, enum hash_type auth_hash, const struct cmd_device *uuid,
	const uint8_t *oid, size_t oid_length, const uint8_t *dice_hash, size_t hash_length);
void rma_unlock_token_release (const struct rma_unlock_token *handler);


#define	RMA_UNLOCK_TOKEN_ERROR(code)		ROT_ERROR (ROT_MODULE_RMA_UNLOCK_TOKEN, code)

/**
 * Error codes that can be generated by a RMA unlock token handler.
 */
enum {
	RMA_UNLOCK_TOKEN_INVALID_ARGUMENT = RMA_UNLOCK_TOKEN_ERROR (0x00),	/**< Input parameter is null or not valid. */
	RMA_UNLOCK_TOKEN_NO_MEMORY = RMA_UNLOCK_TOKEN_ERROR (0x01),			/**< Memory allocation failed. */
	RMA_UNLOCK_TOKEN_BAD_TOKEN_DATA = RMA_UNLOCK_TOKEN_ERROR (0x02),	/**< The token data is not structured correctly. */
	RMA_UNLOCK_TOKEN_DEVICE_MISMATCH = RMA_UNLOCK_TOKEN_ERROR (0x03),	/**< The token is not for this device. */
};


#endif	/* RMA_UNLOCK_TOKEN_H_ */
