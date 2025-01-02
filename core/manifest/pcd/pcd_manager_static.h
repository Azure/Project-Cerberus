// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PCD_MANAGER_STATIC_H_
#define PCD_MANAGER_STATIC_H_

#include "pcd_manager.h"
#include "manifest/manifest_manager_static.h"


/**
 * Statically initialize a base PCD manager.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the PCD manager.
 * @param hash_ptr The hash engine to generate measurement data.
 * @param port_arg The port identifier to set.
 * @param activate_pending_manifest_func Implementation for the activate_pending_manifest API.
 * @param clear_pending_region_func Implementation for the clear_pending_region API.
 * @param write_pending_data_func Implementation for the write_pending_data API.
 * @param verify_pending_manifest_func Implementation for the verify_pending_manifest API.
 * @param clear_all_manifests_func Implementation for the clear_all_manifests API.
 * @param get_active_pcd_func Implementation for the get_active_pcd API.
 * @param free_pcd_func Implementation for the free_pcd API.
 */
#define	pcd_manager_static_init(state_ptr, hash_ptr, port_arg, activate_pending_manifest_func, \
	clear_pending_region_func, write_pending_data_func, verify_pending_manifest_func, \
	clear_all_manifests_func, get_active_pcd_func, free_pcd_func)	{ \
		.base = manifest_manager_static_init (activate_pending_manifest_func, \
			clear_pending_region_func, write_pending_data_func, verify_pending_manifest_func, \
			clear_all_manifests_func, hash_ptr, port_arg), \
		.get_active_pcd = get_active_pcd_func, \
		.free_pcd = free_pcd_func, \
		.state = state_ptr, \
	}


#endif	/* PCD_MANAGER_STATIC_H_ */
