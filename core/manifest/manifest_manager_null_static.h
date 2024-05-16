// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MANAGER_NULL_STATIC_H_
#define MANIFEST_MANAGER_NULL_STATIC_H_

#include "manifest/manifest_manager_null.h"


/* Internal functions declared to allow for static initialization. */
int manifest_manager_null_activate_pending_manifest (const struct manifest_manager *manager);
int manifest_manager_null_clear_pending_region (const struct manifest_manager *manager,
	size_t size);
int manifest_manager_null_write_pending_data (const struct manifest_manager *manager,
	const uint8_t *data, size_t length);
int manifest_manager_null_verify_pending_manifest (const struct manifest_manager *manager);
int manifest_manager_null_clear_all_manifests (const struct manifest_manager *manager);


/**
 * Constant initializer for the manifest manager.
 */
#define	MANIFEST_MANAGER_NULL_INIT  { \
		.activate_pending_manifest = manifest_manager_null_activate_pending_manifest, \
		.clear_pending_region = manifest_manager_null_clear_pending_region, \
		.write_pending_data = manifest_manager_null_write_pending_data, \
		.verify_pending_manifest = manifest_manager_null_verify_pending_manifest, \
		.clear_all_manifests = manifest_manager_null_clear_all_manifests, \
		.hash = NULL \
	}


/**
 * Initialize a static instance of an null manifest manager.
 *
 * There is no validation done on the arguments.
 */
#define	manifest_manager_null_static_init	{ \
		.base = MANIFEST_MANAGER_NULL_INIT, \
	}


#endif	/* MANIFEST_MANAGER_NULL_STATIC_H_ */
