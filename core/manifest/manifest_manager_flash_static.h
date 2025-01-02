// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MANAGER_FLASH_STATIC_H_
#define MANIFEST_MANAGER_FLASH_STATIC_H_

#include "manifest/manifest_manager_flash.h"


/**
 * Initialize a static instance of a flash manifest manager.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for managing the manifests on flash.
 * @param base_ptr The base manager associated with this manager instance.
 * @param region1_ptr The manifest instance for the first flash region that can hold a manifest.
 * @param region2_ptr The manifest instance for the second flash region that can hold a manifest.
 * @param region1_flash_ptr Flash access for the region 1 manifest.
 * @param region2_flash_ptr Flash access for the region 2 manifest.
 * @param state_mgr_ptr The state information for manifest management.
 * @param hash_ptr The hash engine to be used for manifest validation.
 * @param verification_ptr The module to use for manifest verification.
 * @param manifest_index_arg State manager manifest index to use for maintaining active region
 * state.
 * @param sku_upgrade_permitted_arg Manifest permitted to upgrade from generic to SKU-specific.
 * @param post_verify_ptr Function pointer to use for additional manifest verification.  This can be
 * null if no additional verification is needed.
 */
#define	manifest_manager_flash_static_init(state_ptr, base_ptr, region1_ptr, region2_ptr, \
	region1_flash_ptr, region2_flash_ptr, state_mgr_ptr, hash_ptr, verification_ptr, \
	manifest_index_arg, sku_upgrade_permitted_arg, post_verify_ptr)	{ \
		.state = state_ptr, \
		.base = base_ptr, \
		.region1 = { \
			.manifest = region1_ptr, \
			.flash = region1_flash_ptr, \
			.state = &(state_ptr)->region1, \
		}, \
		.region2 = { \
			.manifest = region2_ptr, \
			.flash = region2_flash_ptr, \
			.state = &(state_ptr)->region2, \
		}, \
		.state_mgr = state_mgr_ptr, \
		.hash = hash_ptr, \
		.verification = verification_ptr, \
		.manifest_index = manifest_index_arg, \
		.sku_upgrade_permitted = sku_upgrade_permitted_arg, \
		.post_verify = post_verify_ptr, \
	}


#endif	/* MANIFEST_MANAGER_FLASH_STATIC_H_ */
