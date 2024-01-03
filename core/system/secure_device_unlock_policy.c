// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "secure_device_unlock_policy.h"
#include "common/common_math.h"
#include "common/unused.h"
#include "system/system_logging.h"


int secure_device_unlock_policy_get_unlock_token (const struct secure_device_unlock *unlock,
	uint8_t *token, size_t length)
{
	const struct secure_device_unlock_policy *dbg_unlock =
		(const struct secure_device_unlock_policy*) unlock;
	uint8_t *counter;
	int counter_length;
	int status;

	if ((dbg_unlock == NULL) || (token == NULL)) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	/* Get the current unlock counter value from the device. */
	counter_length = device_unlock_token_get_counter_length (dbg_unlock->token);
	counter = platform_malloc (counter_length);
	if (counter == NULL) {
		return SECURE_DEVICE_UNLOCK_NO_MEMORY;
	}

	counter_length = dbg_unlock->manager->get_unlock_counter (dbg_unlock->manager, counter,
		counter_length);
	if (ROT_IS_ERROR (counter_length)) {
		status = counter_length;
		goto exit;
	}

	/* Unlock tokens can only be retrieved from locked devices.  An odd number of bits in the unlock
	 * counter indicates an unlocked device.  If the device is locked, update the counter to
	 * represent an unlocked state for inclusion in the unlock token. */
	if ((common_math_get_num_contiguous_bits_set_in_array (counter, counter_length) & 0x1) != 0) {
		status = SECURE_DEVICE_UNLOCK_NOT_LOCKED;
		goto exit;
	}

	status = common_math_set_next_bit_in_array_odd_count (counter, counter_length);
	if (status == COMMON_MATH_OUT_OF_RANGE) {
		status = SECURE_DEVICE_UNLOCK_COUNTER_EXHAUSTED;
		goto exit;
	}

	status = device_unlock_token_generate (dbg_unlock->token, counter, counter_length, token,
		length);

exit:
	platform_free (counter);
	return status;
}

int secure_device_unlock_policy_apply_unlock_policy (const struct secure_device_unlock *unlock,
	const uint8_t *policy, size_t length)
{
	const struct secure_device_unlock_policy *dbg_unlock =
		(const struct secure_device_unlock_policy*) unlock;
	int status;

	if ((dbg_unlock == NULL) || (policy == NULL)) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	status = device_unlock_token_authenicate (dbg_unlock->token, policy, length);
	if (status != 0) {
		return status;
	}

	status = dbg_unlock->manager->unlock_device (dbg_unlock->manager, policy, length);
	if (status != 0) {
		return status;
	}

	status = device_unlock_token_invalidate (dbg_unlock->token);
	if (status != 0) {
		/* The device has already been unlocked, so the operation shouldn't report a failure when
		 * the unlock token couldn't be invalidated.  Just log the error.  The token will naturally
		 * invalidate itself over time or resets. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_WARNING, DEBUG_LOG_COMPONENT_SYSTEM,
			SYSTEM_LOGGING_TOKEN_INVALIDATE_FAIL, status, 0);
	}

	return 0;
}

int secure_device_unlock_policy_clear_unlock_policy (const struct secure_device_unlock *unlock)
{
	const struct secure_device_unlock_policy *dbg_unlock =
		(const struct secure_device_unlock_policy*) unlock;
	int status;

	if (dbg_unlock == NULL) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	/* Since the device state is being updated, invalidate any active unlock token.  Once there is
	 * no longer an active unlock token, put the device into a locked state. */
	status = device_unlock_token_invalidate (dbg_unlock->token);
	if (status != 0) {
		return status;
	}

	return dbg_unlock->manager->lock_device (dbg_unlock->manager);
}

/**
 * Initialize a handler for secure unlock flows.
 *
 * @param unlock The handler for unlock requests to initialize.
 * @param token Handler for unlock token generation and authentication.
 * @param manager The security manager for the device that will execute unlock operations.
 *
 * @return 0 if the unlock handler was initialized successfully or an error code.
 */
int secure_device_unlock_policy_init (struct secure_device_unlock_policy *unlock,
	const struct device_unlock_token *token, const struct security_manager *manager)
{
	if ((unlock == NULL) || (token == NULL) || (manager == NULL)) {
		return SECURE_DEVICE_UNLOCK_INVALID_ARGUMENT;
	}

	memset (unlock, 0, sizeof (struct secure_device_unlock_policy));

	unlock->base.get_unlock_token = secure_device_unlock_policy_get_unlock_token;
	unlock->base.apply_unlock_policy = secure_device_unlock_policy_apply_unlock_policy;
	unlock->base.clear_unlock_policy = secure_device_unlock_policy_clear_unlock_policy;

	unlock->token = token;
	unlock->manager = manager;

	return 0;
}

/**
 * Release the resources used by a secure unlock handler.
 *
 * @param unlock The unlock handler to release.
 */
void secure_device_unlock_policy_release (const struct secure_device_unlock_policy *unlock)
{
	UNUSED (unlock);
}
