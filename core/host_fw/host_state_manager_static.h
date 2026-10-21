// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_MANAGER_STATIC_H_
#define HOST_STATE_MANAGER_STATIC_H_

#include "host_state_manager.h"
#include "state_manager/state_manager_static.h"


/* Internal functions declared to allow for static initialization. */
int host_state_manager_save_active_manifest (const struct state_manager *manager,
	uint8_t manifest_index, enum manifest_region active);
int host_state_manager_restore_default_state (const struct state_manager *manager);
int host_state_manager_is_manifest_valid (const struct state_manager *manager,
	uint8_t manifest_index);
enum manifest_region host_state_manager_get_active_manifest (
	const struct state_manager *manager, uint8_t manifest_index);


/**
 * Initialize a static instance of a manager for host state information.  This does not initialize
 * the manager state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for host state management.
 * @param state_flash_ptr The flash that contains the non-volatile state information.
 * @param store_addr_arg The starting address for state storage.  The state storage uses two
 * contiguous flash sectors.  The start address must be aligned to the start of a flash sector.
 */
#define	host_state_manager_static_init(state_ptr, state_flash_ptr, store_addr_arg)	{ \
		.base = state_manager_static_init (host_state_manager_save_active_manifest, \
			host_state_manager_get_active_manifest, host_state_manager_restore_default_state, \
			host_state_manager_is_manifest_valid, &(state_ptr)->base, state_flash_ptr, \
			store_addr_arg), \
		.state = state_ptr, \
	}


#endif	/* HOST_STATE_MANAGER_STATIC_H_ */
