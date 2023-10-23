// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURE_DEVICE_UNLOCK_STATIC_H_
#define SECURE_DEVICE_UNLOCK_STATIC_H_

#include "secure_device_unlock.h"


int secure_device_unlock_get_unlock_token (const struct secure_device_unlock *unlock,
	uint8_t *token, size_t length);
int secure_device_unlock_apply_unlock_policy (const struct secure_device_unlock *unlock,
	const uint8_t *policy, size_t length);
int secure_device_unlock_clear_unlock_policy (const struct secure_device_unlock *unlock);


/**
 * Constant initializer for the secure unlock API.
 */
#define	SECURE_DEVICE_UNLOCK_API_INIT	\
	.get_unlock_token = secure_device_unlock_get_unlock_token, \
	.apply_unlock_policy = secure_device_unlock_apply_unlock_policy, \
	.clear_unlock_policy = secure_device_unlock_clear_unlock_policy


/**
 * Initialize a static instance of a handler for secure unlock flows.  This can be a constant
 * instance.
 *
 * There is no validation done on the arguments.
 *
 * @param token_ptr Handler for unlock token generation and authentication.
 * @param manager_ptr The security manager for the device that will execute unlock operations.
 */
#define	secure_device_unlock_static_init(token_ptr, manager_ptr)	{ \
		SECURE_DEVICE_UNLOCK_API_INIT, \
		.token = token_ptr, \
		.manager = manager_ptr, \
	}


#endif /* SECURE_DEVICE_UNLOCK_STATIC_H_ */
