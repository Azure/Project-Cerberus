// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "system_state_manager.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/* Bitmasks for settings in non-volatile memory. */
#define	ACTIVE_CFM_MASK			(1U << 0)
#define	ACTIVE_PCD_MASK			(1U << 1)


static int system_state_manager_save_active_manifest (struct state_manager *manager,
	uint8_t manifest_index, enum manifest_region active)
{
	if (manifest_index == SYSTEM_STATE_MANIFEST_CFM) {
		return state_manager_save_active_manifest (manager, active, ACTIVE_CFM_MASK);
	}
	else if (manifest_index == SYSTEM_STATE_MANIFEST_PCD) {
		return state_manager_save_active_manifest (manager, active, ACTIVE_PCD_MASK);
	}
	else {
		return STATE_MANAGER_OUT_OF_RANGE;
	}
}

static enum manifest_region system_state_manager_get_active_manifest (struct state_manager *manager,
	uint8_t manifest_index)
{
	if (manifest_index == SYSTEM_STATE_MANIFEST_CFM) {
		return state_manager_get_active_manifest (manager, ACTIVE_CFM_MASK);
	}
	else if (manifest_index == SYSTEM_STATE_MANIFEST_PCD) {
		return state_manager_get_active_manifest (manager, ACTIVE_PCD_MASK);
	}
	else {
		return MANIFEST_REGION_1;
	}
}

static int system_state_manager_is_manifest_valid (struct state_manager *manager,
	uint8_t manifest_index)
{
	if ((manifest_index != SYSTEM_STATE_MANIFEST_CFM) &&
		(manifest_index != SYSTEM_STATE_MANIFEST_PCD)) {
		return STATE_MANAGER_OUT_OF_RANGE;
	}

	return 0;
}

static int system_state_manager_restore_default_state (struct state_manager *manager)
{
	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	manager->nv_state = 0xffff;

	platform_mutex_unlock (&manager->state_lock);
	return 0;
}

/**
 * Initialize the manager for system state information.
 *
 * @param manager The state manager to initialize.
 * @param state_flash The flash that contains the non-volatile state information.
 * @param store_addr The starting address for state storage. The state storage uses two contiguous
 * flash regions of FLASH_SECTOR_SIZE. The start address must be aligned to the start of a flash
 * sector.
 *
 * @return 0 if the state manager was successfully initialized or an error code.
 */
int system_state_manager_init (struct state_manager *manager, struct flash *state_flash,
	uint32_t store_addr)
{
	int status;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	status = state_manager_init (manager, state_flash, store_addr);

	if (status == 0) {
		manager->get_active_manifest = system_state_manager_get_active_manifest;
		manager->save_active_manifest = system_state_manager_save_active_manifest;
		manager->restore_default_state = system_state_manager_restore_default_state;
		manager->is_manifest_valid = system_state_manager_is_manifest_valid;
	}

	return status;
}

/**
 * Release the resources used by the host state manager.
 *
 * @param manager The state manager to release.
 */
void system_state_manager_release (struct state_manager *manager)
{
	state_manager_release (manager);
}
