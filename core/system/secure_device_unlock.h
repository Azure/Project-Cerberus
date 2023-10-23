// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SECURE_DEVICE_UNLOCK_H_
#define SECURE_DEVICE_UNLOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "status/rot_status.h"
#include "system/debug_unlock_token.h"
#include "system/security_manager.h"


/**
 * Handles requests to unlock the device for development or debug through application of an unlock
 * policy.
 */
struct secure_device_unlock {
	/**
	 * Get an authorization token that can be used to unlock the device.  Only one authorization
	 * token will be valid at a time.  Requesting a new token will invalidate any previously
	 * requested token.
	 *
	 * @param unlock The device unlock handler to query.
	 * @param token Output buffer for the unlock authorization token.
	 * @param length Length of the token buffer.
	 *
	 * @return Length of the generated token or an error code.  Use ROT_IS_ERROR to check the return
	 * value.
	 */
	int (*get_unlock_token) (const struct secure_device_unlock *unlock, uint8_t *token,
		size_t length);

	/**
	 * Apply an authenticated unlock policy to a device.  The authenticated policy must include the
	 * current authorization token and be signed by a trusted key for it to be considered valid.
	 *
	 * @param unlock The device unlock handler for the unlock policy.
	 * @param policy The unlock policy that should be authenticated and applied.
	 * @param length Length of the unlock policy.
	 *
	 * @return 0 if the unlock policy was applied successfully or an error code.
	 */
	int (*apply_unlock_policy) (const struct secure_device_unlock *unlock, const uint8_t *policy,
		size_t length);

	/**
	 * Remove any existing unlock policy, whether the policy has taken full effect or not.
	 *
	 * @param unlock The device unlock handler for the unlock policy.
	 *
	 * @param 0 if the unlock policy has been cleared successfully or an error code.
	 */
	int (*clear_unlock_policy) (const struct secure_device_unlock *unlock);

	const struct debug_unlock_token *token;		/**< Token handler for authenticating unlock operations. */
	const struct security_manager *manager;		/**< Security manager for executing unlock operations. */
};


int secure_device_unlock_init (struct secure_device_unlock *unlock,
	const struct debug_unlock_token *token, const struct security_manager *manager);
void secure_device_unlock_release (const struct secure_device_unlock *unlock);


#define	SECURE_DEVICE_UNLOCK_ERROR(code)		ROT_ERROR (ROT_MODULE_SECURE_DEVICE_UNLOCK, code)

/**
 * Error codes that can be generated by a handler for unlock requests.
 */
enum {
	SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT = SECURE_DEVICE_UNLOCK_ERROR (0x00),		/**< Input parameter is null or not valid. */
	SECURE_DEVICE_UNLOCK_NO_MEMORY = SECURE_DEVICE_UNLOCK_ERROR (0x01),				/**< Memory allocation failed. */
	SECURE_DEVICE_UNLOCK_GET_TOKEN_FAILED = SECURE_DEVICE_UNLOCK_ERROR (0x02),		/**< Failed to get an unlock token. */
	SECURE_DEVICE_UNLOCK_APPLY_POLICY_FAILED = SECURE_DEVICE_UNLOCK_ERROR (0x03),	/**< Failed to apply an unlock policy. */
	SECURE_DEVICE_UNLOCK_CLEAR_POLICY_FAILED = SECURE_DEVICE_UNLOCK_ERROR (0x04),	/**< Failed to clear an unlock policy. */
	SECURE_DEVICE_UNLOCK_NOT_LOCKED = SECURE_DEVICE_UNLOCK_ERROR (0x05),			/**< Attempt to unlock an unlocked device. */
	SECURE_DEVICE_UNLOCK_COUNTER_EXHAUSTED = SECURE_DEVICE_UNLOCK_ERROR (0x06),		/**< The device unlock counter has reached the max value. */
};


#endif /* SECURE_DEVICE_UNLOCK_H_ */
