// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SYSTEM_STATE_MANAGER_STATIC_H_
#define SYSTEM_STATE_MANAGER_STATIC_H_

#include "system_state_manager.h"
#include "state_manager/state_manager_static.h"


/* Internal functions declared to allow for static initialization. */
int system_state_manager_save_active_manifest (const struct state_manager *manager,
	uint8_t manifest_index, enum manifest_region active);
int system_state_manager_restore_default_state (const struct state_manager *manager);
int system_state_manager_is_manifest_valid (const struct state_manager *manager,
	uint8_t manifest_index);
enum manifest_region system_state_manager_get_active_manifest (
	const struct state_manager *manager, uint8_t manifest_index);


/**
 * Initialize a static instance of a manager for system state information.  This does not initialize
 * the manager state.  This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for system state management.
 * @param state_flash_ptr The flash that contains the non-volatile state information.
 * @param store_addr_arg The starting address for state storage.  The state storage uses two
 * contiguous flash sectors.  The start address must be aligned to the start of a flash sector.
 */
#define	system_state_manager_static_init(state_ptr, state_flash_ptr, store_addr_arg)    \
		state_manager_static_init (system_state_manager_save_active_manifest, \
			system_state_manager_get_active_manifest, system_state_manager_restore_default_state, \
			system_state_manager_is_manifest_valid, state_ptr, state_flash_ptr, store_addr_arg)


#endif	/* SYSTEM_STATE_MANAGER_STATIC_H_ */
