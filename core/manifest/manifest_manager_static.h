// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MANIFEST_MANAGER_STATIC_H_
#define MANIFEST_MANAGER_STATIC_H_

#include "manifest_manager.h"


/**
 * Initialize a static instance for the common management of manifests.
 *
 * There is no validation done on the arguments.
 *
 * @param activate_pending_manifest_func Implementation for the activate_pending_manifest API.
 * @param clear_pending_region_func Implementation for the clear_pending_region API.
 * @param write_pending_data_func Implementation for the write_pending_data API.
 * @param verify_pending_manifest_func Implementation for the verify_pending_manifest API.
 * @param clear_all_manifests_func Implementation for the clear_all_manifests API.
 * @param hash_ptr The hash engine to generate measurement data.
 * @param port_arg The port identifier to set.
 */
#define	manifest_manager_static_init(activate_pending_manifest_func, clear_pending_region_func, \
	write_pending_data_func, verify_pending_manifest_func, clear_all_manifests_func, hash_ptr, \
	port_arg)	{ \
		.activate_pending_manifest = activate_pending_manifest_func, \
		.clear_pending_region = clear_pending_region_func, \
		.write_pending_data = write_pending_data_func, \
		.verify_pending_manifest = verify_pending_manifest_func, \
		.clear_all_manifests = clear_all_manifests_func, \
		.port = port_arg, \
		.hash = hash_ptr, \
	}


#endif	/* MANIFEST_MANAGER_STATIC_H_ */
