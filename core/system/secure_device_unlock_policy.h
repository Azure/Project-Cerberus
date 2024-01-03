// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURE_DEVICE_UNLOCK_POLICY_H_
#define SECURE_DEVICE_UNLOCK_POLICY_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "system/device_unlock_token.h"
#include "system/secure_device_unlock.h"
#include "system/security_manager.h"


/**
 * Handles requests to unlock the device for development or debug through application of an unlock
 * policy.
 */
struct secure_device_unlock_policy {
	struct secure_device_unlock base;			/**< Base device unlock handler. */
	const struct device_unlock_token *token;	/**< Token handler for authenticating unlock operations. */
	const struct security_manager *manager;		/**< Security manager for executing unlock operations. */
};


int secure_device_unlock_policy_init (struct secure_device_unlock_policy *unlock,
	const struct device_unlock_token *token, const struct security_manager *manager);
void secure_device_unlock_policy_release (const struct secure_device_unlock_policy *unlock);


#endif /* SECURE_DEVICE_UNLOCK_POLICY_H_ */
