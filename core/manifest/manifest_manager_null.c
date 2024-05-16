// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "manifest_manager_null.h"
#include "common/unused.h"


int manifest_manager_null_activate_pending_manifest (const struct manifest_manager *manager)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return 0;
}

int manifest_manager_null_clear_pending_region (const struct manifest_manager *manager, size_t size)
{
	UNUSED (size);

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return 0;
}

int manifest_manager_null_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	UNUSED (data);
	UNUSED (length);

	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return 0;
}

int manifest_manager_null_verify_pending_manifest (const struct manifest_manager *manager)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return 0;
}

int manifest_manager_null_clear_all_manifests (const struct manifest_manager *manager)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	return 0;
}

/**
 * Initialize the null object of manifest manager.
 *
 * @param manager The manager to initialize.
 *
 * @return 0 if the initialization was successful or an error code.
 */
int manifest_manager_null_init (struct manifest_manager_null *manager)
{
	if (manager == NULL) {
		return MANIFEST_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct manifest_manager_null));

	manager->base.activate_pending_manifest = manifest_manager_null_activate_pending_manifest;
	manager->base.clear_pending_region = manifest_manager_null_clear_pending_region;
	manager->base.write_pending_data = manifest_manager_null_write_pending_data;
	manager->base.verify_pending_manifest = manifest_manager_null_verify_pending_manifest;
	manager->base.clear_all_manifests = manifest_manager_null_clear_all_manifests;

	return 0;
}

/**
 * Release a null object of manifest manager.
 *
 * @param context The manifest manager handler to release.
 */
void manifest_manager_null_release (const struct manifest_manager_null *manager)
{
	UNUSED (manager);
}
