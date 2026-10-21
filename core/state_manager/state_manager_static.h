// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef STATE_MANAGER_STATIC_H_
#define STATE_MANAGER_STATIC_H_

#include "state_manager.h"


/**
 * Internal initializer for derived types to initialize a static instance of a manager for state
 * information.  This does not initialize the manager state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param save_active_manifest_func Function pointer for the save_active_manifest API.
 * @param get_active_manifest_func Function pointer for the get_active_manifest API.
 * @param restore_default_state_func Function pointer for the restore_default_state API.
 * @param is_manifest_valid_func Function pointer for the is_manifest_valid API.
 * @param state_ptr Variable context for the state manager.
 * @param state_flash_ptr The flash that contains the non-volatile state information.
 * @param store_addr_arg The starting address for state storage.  The state storage uses two
 * contiguous flash sectors.  The start address must be aligned to the start of a flash sector.
 *
 * @return 0 if the state manager was successfully initialized or an error code.
 */
#define	state_manager_static_init(save_active_manifest_func, get_active_manifest_func, \
	restore_default_state_func, is_manifest_valid_func, state_ptr, state_flash_ptr, \
	store_addr_arg) { \
		.save_active_manifest = save_active_manifest_func, \
		.get_active_manifest = get_active_manifest_func, \
		.restore_default_state = restore_default_state_func, \
		.is_manifest_valid = is_manifest_valid_func, \
		.state = state_ptr, \
		.nv_store = state_flash_ptr, \
		.base_addr = store_addr_arg, \
	}


#endif	/* STATE_MANAGER_STATIC_H_ */
