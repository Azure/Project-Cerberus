// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "security_manager_no_unlock.h"
#include "common/unused.h"


int security_manager_no_unlock_lock_device (const struct security_manager *manager)
{
	if (manager == NULL) {
		return SECURITY_MANAGER_INVALID_ARGUMENT;
	}

	/* The device is always locked. */
	return 0;
}

int security_manager_no_unlock_unlock_device (const struct security_manager *manager,
	const uint8_t *policy, size_t length)
{
	UNUSED (manager);
	UNUSED (policy);
	UNUSED (length);

	return SECURITY_MANAGER_UNSUPPORTED;
}

int security_manager_no_unlock_get_unlock_counter (const struct security_manager *manager,
	uint8_t *counter, size_t length)
{
	if ((manager == NULL) || (counter == NULL)) {
		return SECURITY_MANAGER_INVALID_ARGUMENT;
	}

	if (length == 0) {
		return SECURITY_MANAGER_SMALL_COUNTER_BUFFER;
	}

	*counter = 0;

	return 1;
}

int security_manager_no_unlock_has_unlock_policy (const struct security_manager *manager)
{
	if (manager == NULL) {
		return SECURITY_MANAGER_INVALID_ARGUMENT;
	}

	/* There is never an unlock policy. */
	return 0;
}

int security_manager_no_unlock_load_security_policy (const struct security_manager *manager)
{
	if (manager == NULL) {
		return SECURITY_MANAGER_INVALID_ARGUMENT;
	}

	/* Nothing to do, so always successful. */
	return 0;
}

int security_manager_no_unlock_apply_device_config (const struct security_manager *manager)
{
	UNUSED (manager);

	return SECURITY_MANAGER_UNSUPPORTED;
}

int security_manager_no_unlock_get_security_policy (const struct security_manager *manager,
	const struct security_policy **policy)
{
	if ((manager == NULL) || (policy == NULL)) {
		return SECURITY_MANAGER_INVALID_ARGUMENT;
	}

	/* Always use the default security policy. */
	*policy = NULL;

	return 0;
}

/**
 * Initialize a security manager that does not support any unlock flows.
 *
 * @param manager The security manager to initialize.
 *
 * @return 0 if the manager was initialized successfully or an error code.
 */
int security_manager_no_unlock_init (struct security_manager_no_unlock *manager)
{
	if (manager == NULL) {
		return SECURITY_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct security_manager_no_unlock));

	manager->base.lock_device = security_manager_no_unlock_lock_device;
	manager->base.unlock_device = security_manager_no_unlock_unlock_device;
	manager->base.get_unlock_counter = security_manager_no_unlock_get_unlock_counter;
	manager->base.has_unlock_policy = security_manager_no_unlock_has_unlock_policy;
	manager->base.load_security_policy = security_manager_no_unlock_load_security_policy;
	manager->base.apply_device_config = security_manager_no_unlock_apply_device_config;

	manager->base.internal.get_security_policy = security_manager_no_unlock_get_security_policy;

	return 0;
}

/**
 * Release the resources used by a security manager without unlock support.
 *
 * @param manager The security manager to release.
 */
void security_manager_no_unlock_release (const struct security_manager_no_unlock *manager)
{
	UNUSED (manager);
}
