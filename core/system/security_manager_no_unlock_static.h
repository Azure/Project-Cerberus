// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#ifndef SECURITY_MANAGER_NO_UNLOCK_STATIC_H_
#define SECURITY_MANAGER_NO_UNLOCK_STATIC_H_

#include "security_manager_no_unlock.h"


/* Internal functions declared to allow for static initialization. */
int security_manager_no_unlock_lock_device (const struct security_manager *manager);
int security_manager_no_unlock_unlock_device (const struct security_manager *manager,
	const uint8_t *policy, size_t length);
int security_manager_no_unlock_get_unlock_counter (const struct security_manager *manager,
	uint8_t *counter, size_t length);
int security_manager_no_unlock_has_unlock_policy (const struct security_manager *manager);
int security_manager_no_unlock_load_security_policy (const struct security_manager *manager);
int security_manager_no_unlock_apply_device_config (const struct security_manager *manager);

int security_manager_no_unlock_get_security_policy (const struct security_manager *manager,
	const struct security_policy **policy);


/**
 * Constant initializer for the security manager API.
 */
#define	SECURITY_MANAGER_NO_UNLOCK_API_INIT	{ \
		.lock_device = security_manager_no_unlock_lock_device, \
		.unlock_device = security_manager_no_unlock_unlock_device, \
		.get_unlock_counter = security_manager_no_unlock_get_unlock_counter, \
		.has_unlock_policy = security_manager_no_unlock_has_unlock_policy, \
		.load_security_policy = security_manager_no_unlock_load_security_policy, \
		.apply_device_config = security_manager_no_unlock_apply_device_config, \
		.internal = { \
			.get_security_policy = security_manager_no_unlock_get_security_policy, \
		}, \
	}


/**
 * Initialize a static instance of a security manager that doesn't support unlock flows.  This can
 * be a constant instance.
 */
#define	security_manager_no_unlock_static_init	{ \
		.base = SECURITY_MANAGER_NO_UNLOCK_API_INIT, \
	}


#endif /* SECURITY_MANAGER_NO_UNLOCK_STATIC_H_ */
