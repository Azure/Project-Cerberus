// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RMA_UNLOCK_TOKEN_STATIC_H_
#define RMA_UNLOCK_TOKEN_STATIC_H_

#include "rma_unlock_token.h"


/* Internal functions declared to allow for static initialization. */
int rma_unlock_token_authenticate (const struct rma_unlock_token *handler, const uint8_t *data,
	size_t length);


/**
 * Initialize a static instance of a handler authorizing RMA unlock tokens.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param authority_key_ptr The public key for entity that will be generating RMA tokens.
 * @param key_length_arg Length of the authority public key.
 * @param authority_ptr Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param hash_ptr The hash engine to use for token digests.
 * @param auth_hash_arg Hash algorithm to use for signature verification of the token.
 * @param uuid_ptr Interface for retrieving the device UUID.
 * @param oid_ptr The OID indicating the type of device generating the tokens.  This must be a
 * base128 encoded value.
 * @param oid_length_arg Length of the device type OID.
 * @param dice_hash_ptr Digest of the DICE Device ID public key.  This would typically be available
 * through the DME structure.
 * @param hash_length_arg Length of the Device ID digest.
 */
#define	rma_unlock_token_static_init(authority_key_ptr, key_length_arg, authority_ptr, hash_ptr, \
	auth_hash_arg, uuid_ptr, oid_ptr, oid_length_arg, dice_hash_ptr, hash_length_arg)	{ \
		.authenticate = rma_unlock_token_authenticate, \
		.hash = hash_ptr, \
		.authority = authority_ptr, \
		.authority_key = authority_key_ptr, \
		.auth_key_length = key_length_arg, \
		.auth_hash = auth_hash_arg, \
		.uuid = uuid_ptr, \
		.oid = oid_ptr, \
		.oid_length = oid_length_arg, \
		.dice_hash = dice_hash_ptr, \
		.dice_length = hash_length_arg, \
	}


#endif	/* RMA_UNLOCK_TOKEN_STATIC_H_ */
