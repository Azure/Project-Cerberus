// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef AUTHORIZATION_GLOBAL_STATIC_H_
#define AUTHORIZATION_GLOBAL_STATIC_H_

#include "authorization_global.h"


/* Internal functions declared to allow for static initialization. */
int authorization_global_authorize (const struct authorization *auth, const uint8_t **token,
	size_t *length);


/**
 * Constant initializer for the authorization API.
 */
#define	AUTHORIZATION_GLOBAL_API_INIT  { \
		.authorize = authorization_global_authorize, \
	}


/**
 * Initialize a static authorization manager that uses the same authorized data for all devices.
 *
 * There is no validation done on the arguments.
 *
 * @param auth_data_ptr Authorized data parser used to extract the authorizing signature
 * information.
 * @param hash_ptr Hash engine to use for authorized data verification.
 * @param verification_ptr Signature verification for the authorized data.
 * @param authorizing_key_ptr The authority public key responsible for for authorizing the operation
 * on the device.  This key must be valid for the signature verification context.
 * @param key_length_arg Length of the public key.
 * @param auth_hash_arg Hash algorithm to use for signature verification of the authorized data.
 */
#define	authorization_global_static_init(auth_data_ptr, hash_ptr, verification_ptr, \
	authorizing_key_ptr, key_length_arg, auth_hash_arg) { \
		.base = AUTHORIZATION_GLOBAL_API_INIT, \
		.auth_data = auth_data_ptr, \
		.hash = hash_ptr, \
		.verification = verification_ptr, \
		.authorizing_key = authorizing_key_ptr, \
		.key_length = key_length_arg, \
		.auth_hash = auth_hash_arg, \
	}


#endif	/* AUTHORIZATION_GLOBAL_STATIC_H_ */
