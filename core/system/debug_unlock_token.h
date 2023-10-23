// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEBUG_UNLOCK_TOKEN_H_
#define DEBUG_UNLOCK_TOKEN_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "cmd_interface/cmd_device.h"
#include "common/auth_token.h"


/**
 * Length of the UUID field in the unlock token.
 */
#define	DEBUG_UNLOCK_TOKEN_UUID_LENGTH		16

/**
 * Length of the nonce field of the unlock token.
 */
#define	DEBUG_UNLOCK_TOKEN_NONCE_LENGTH		32

/**
 * Determine the size of the additional token data being added to the unlock token.
 *
 * NOTE:  This is only valid for device OIDs less than 128 bytes, which should cover all cases.  If
 * an OID is ever longer, adjustments will be needed.
 *
 * @param oid_length Length of the device type OID.  Must be less than 128 bytes.
 * @param counter_length Length of the unlock counter that will be in the token.
 */
#define	DEBUG_UNLOCK_TOKEN_SIZEOF_EXTRA_DATA(oid_length, counter_length)	\
	(2 + oid_length + sizeof (uint16_t) + DEBUG_UNLOCK_TOKEN_UUID_LENGTH + sizeof (uint8_t) + \
		counter_length)


/**
 * Handler for generating and authenticating debug unlock tokens.
 */
struct debug_unlock_token {
	const struct auth_token *auth;	/**< Manager for authorization tokens. */
	const struct cmd_device *uuid;	/**< Interface to retrieve the device UUID. */
	const uint8_t *oid;				/**< OID for the device type. */
	size_t oid_length;				/**< Length of the device type OID. */
	size_t counter_length;			/**< Length of the unlock counter. */
	size_t data_length;				/**< Total length of the device context data in the token. */
	enum hash_type auth_hash;		/**< Hash algorithm for data authentication. */
};


int debug_unlock_token_init (struct debug_unlock_token *token, const struct auth_token *auth,
	const struct cmd_device *uuid, const uint8_t *oid, size_t oid_length, size_t counter_length,
	enum hash_type auth_hash);
void debug_unlock_token_release (const struct debug_unlock_token *token);

size_t debug_unlock_token_get_counter_length (const struct debug_unlock_token *token);

int debug_unlock_token_generate (const struct debug_unlock_token *token,
	const uint8_t *unlock_counter, size_t counter_length, uint8_t *data, size_t length);
int debug_unlock_token_authenicate (const struct debug_unlock_token *token, const uint8_t *data,
	size_t length);
int debug_unlock_token_invalidate (const struct debug_unlock_token *token);

/* Utility functions for parsing raw authorized unlock data. */
int debug_unlock_token_get_unlock_counter (const uint8_t *auth_data, size_t length,
	const uint8_t **counter, size_t *counter_length);
int debug_unlock_token_get_nonce (const uint8_t *auth_data, size_t length, const uint8_t **nonce,
	size_t *nonce_length);
int debug_unlock_token_get_unlock_policy (const uint8_t *auth_data, size_t length,
	const uint8_t **policy, size_t *policy_length);


#define	DEBUG_UNLOCK_TOKEN_ERROR(code)		ROT_ERROR (ROT_MODULE_DEBUG_UNLOCK_TOKEN, code)

/**
 * Error codes that can be generated by a debug unlock token handler.
 */
enum {
	DEBUG_UNLOCK_TOKEN_INVALID_ARGUMENT = DEBUG_UNLOCK_TOKEN_ERROR (0x00),	/**< Input parameter is null or not valid. */
	DEBUG_UNLOCK_TOKEN_NO_MEMORY = DEBUG_UNLOCK_TOKEN_ERROR (0x01),			/**< Memory allocation failed. */
	DEBUG_UNLOCK_TOKEN_BAD_AUTH_DATA = DEBUG_UNLOCK_TOKEN_ERROR (0x02),		/**< Authorized data cannot be parsed. */
	DEBUG_UNLOCK_TOKEN_SMALL_BUFFER = DEBUG_UNLOCK_TOKEN_ERROR (0x03),		/**< Output token buffer is not large enough. */
	DEBUG_UNLOCK_TOKEN_INVALID_COUNTER = DEBUG_UNLOCK_TOKEN_ERROR (0x04),	/**< The counter value is not valid for the token. */
};


#endif /* DEBUG_UNLOCK_TOKEN_H_ */
