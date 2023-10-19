// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef DEBUG_UNLOCK_TOKEN_STATIC_H_
#define DEBUG_UNLOCK_TOKEN_STATIC_H_

#include "debug_unlock_token.h"


/**
 * Initialize a static instance of a handler for debug unlock tokens.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param auth_ptr Authorization token manager to use for unlock tokens.  This must have been
 * initialized to require additional token data of DEBUG_UNLOCK_TOKEN_SIZEOF_EXTRA_DATA bytes.
 * @param oid_ptr The OID indicating the type of device generating the tokens.  This must be a
 * base128 encoded value.
 * @param oid_length_arg Length of the device type OID.
 * @param counter_length_arg Length of the anti-replay unlock counter that will be present in the
 * tokens.
 * @param ueid_ptr UEID for the device.  This will always be 16 bytes.
 * @param auth_hash_arg Hash algorithm to use for signature verification of authorized unlock data.
 */
#define	debug_unlock_token_static_init(auth_ptr, oid_ptr, oid_length_arg, counter_length_arg, \
	ueid_ptr, auth_hash_arg)	{ \
		.auth = auth_ptr, \
		.oid = oid_ptr, \
		.oid_length = oid_length_arg, \
		.counter_length = counter_length_arg, \
		.ueid = ueid_ptr, \
		.data_length = DEBUG_UNLOCK_TOKEN_SIZEOF_EXTRA_DATA (oid_length_arg, counter_length_arg), \
		.auth_hash = auth_hash_arg, \
	}


#endif /* DEBUG_UNLOCK_TOKEN_STATIC_H_ */
