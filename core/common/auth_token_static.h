// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTH_TOKEN_STATIC_H_
#define AUTH_TOKEN_STATIC_H_

#include "auth_token.h"


/* Internal functions declared to allow for static initialization. */
int auth_token_new_token (const struct auth_token *auth, const uint8_t *data, const uint8_t **token,
	size_t *length);
int auth_token_verify_data (const struct auth_token *auth, const uint8_t *authorized, size_t length,
	size_t token_offset, size_t aad_length, enum hash_type sig_hash);
int auth_token_invalidate (const struct auth_token *auth);


/**
 * Constant initializer for the token handler API.
 */
#define	AUTH_TOKEN_API_INIT \
	.new_token = auth_token_new_token, \
	.verify_data = auth_token_verify_data, \
	.invalidate = auth_token_invalidate


/**
 * Initialize a static instance for authorization token management.  Since the token buffer is also
 * static, this can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the token handler.
 * @param rng_ptr The RNG engine to use for token nonce generation.
 * @param hash_ptr The hash engine to use for token digests.
 * @param ecc_ptr The ECC engine to use for token signing.
 * @param device_key_ptr Manager for the device key that will be used to sign the authorization
 * token.
 * @param authority_key_ptr The public key for entity that will be authorizing tokens.
 * @param key_length_arg Length of the authority public key.
 * @param authority_ptr Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param data_length_arg Length of any optional, context-specific data that will be added during
 * token creation.
 * @param nonce_length_arg Length of the random nonce that should be added to the token.  This will
 * be appended to the context data, if any is provided.
 * @param sig_max_length_arg Maximum length of the token signature.
 * @param sig_hash_arg The hash algorithm to use when generating the token signature.
 * @param validity_time_arg The amount of time, in milliseconds, that a token will remain valid.  If
 * a token never expires, set this to 0.
 * @param token_buffer_ptr The buffer to use for token management.
 * @param buffer_length_arg Length of the token buffer.
 */
#define	auth_token_static_init(state_ptr, rng_ptr, hash_ptr, ecc_ptr, device_key_ptr, \
	authority_key_ptr, key_length_arg, authority_ptr, data_length_arg, nonce_length_arg, \
	sig_max_length_arg, sig_hash_arg, validity_time_arg, token_buffer_ptr, buffer_length_arg)	{ \
		AUTH_TOKEN_API_INIT, \
		.state = state_ptr, \
		.rng = rng_ptr, \
		.hash = hash_ptr, \
		.ecc = ecc_ptr, \
		.device_key = device_key_ptr, \
		.authority = authority_ptr, \
		.authority_key = authority_key_ptr, \
		.auth_key_length = key_length_arg, \
		.buffer = token_buffer_ptr, \
		.buffer_length = buffer_length_arg, \
		.alloc_buffer = false, \
		.data_length = data_length_arg, \
		.nonce_length = nonce_length_arg, \
		.sig_length = sig_max_length_arg, \
		.token_hash = sig_hash_arg, \
		.validity_time = validity_time_arg, \
	}

/**
 * Initialize a static instance for authorization token management.  The buffer will be dynamically
 * allocated when the state is initialized, so this cannot be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the token handler.
 * @param rng_ptr The RNG engine to use for token nonce generation.
 * @param hash_ptr The hash engine to use for token digests.
 * @param ecc_ptr The ECC engine to use for token signing.
 * @param device_key_ptr Manager for the device key that will be used to sign the authorization
 * token.
 * @param authority_key_ptr The public key for entity that will be authorizing tokens.
 * @param key_length_arg Length of the authority public key.
 * @param authority_ptr Verification handler for the authority public key.  This does not need to be
 * pre-loaded with the authority key since the verification flow will reload the key each time.
 * @param data_length_arg Length of any optional, context-specific data that will be added during
 * token creation.
 * @param nonce_length_arg Length of the random nonce that should be added to the token.  This will
 * be appended to the context data, if any is provided.
 * @param sig_max_length_arg Maximum length of the token signature.
 * @param sig_hash_arg The hash algorithm to use when generating the token signature.
 * @param validity_time_arg The amount of time, in milliseconds, that a token will remain valid.  If
 * a token never expires, set this to 0.
 */
#define	auth_token_dynamic_buffer_static_init(state_ptr, rng_ptr, hash_ptr, ecc_ptr, \
	device_key_ptr, authority_key_ptr, key_length_arg, authority_ptr, data_length_arg, \
	nonce_length_arg, sig_max_length_arg, sig_hash_arg, validity_time_arg)	{ \
		AUTH_TOKEN_API_INIT, \
		.state = state_ptr, \
		.rng = rng_ptr, \
		.hash = hash_ptr, \
		.ecc = ecc_ptr, \
		.device_key = device_key_ptr, \
		.authority = authority_ptr, \
		.authority_key = authority_key_ptr, \
		.auth_key_length = key_length_arg, \
		.buffer_length = (data_length_arg + nonce_length_arg + sig_max_length_arg), \
		.alloc_buffer = true, \
		.data_length = data_length_arg, \
		.nonce_length = nonce_length_arg, \
		.sig_length = sig_max_length_arg, \
		.token_hash = sig_hash_arg, \
		.validity_time = validity_time_arg, \
	}


#endif /* AUTH_TOKEN_STATIC_H_ */
