// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "manifest_manager.h"


/**
 * Set the port identifier for a manifest manager.
 *
 * @param host The manifest manager to configure.
 * @param port The port identifier to set.
 */
void manifest_manager_set_port (struct manifest_manager *manager, int port)
{
	if (manager) {
		manager->port = port;
	}
}

/**
 * Get the port identifier for a manifest manager.
 *
 * @param host The manifest manager instance to query.
 *
 * @return The port identifier or an error code.  Use ROT_IS_ERROR to check for errors.
 */
int manifest_manager_get_port (struct manifest_manager *manager)
{
	if (manager) {
		return manager->port;
	}
	else {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}
}
