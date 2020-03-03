// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_state_manager.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/* Bitmasks for settings in non-volatile memory. */
#define	READ_ONLY_FLASH_MASK		(1U << 0)
#define	INACTIVE_DIRTY_MASK			(1U << 1)
#define	ACTIVE_PFM_MASK				(1U << 2)
#define	ACTIVE_RECOVERY_IMAGE_MASK	(1U << 3)

/* Bitmasks for settings in volatile memory. */
#define	PFM_DIRTY_MASK			(1U << 0)
#define	RUN_TIME_MASK			(3U << 1)
#define	BYPASS_MASK				(1U << 3)
#define	BAD_FLASH_MASK			(1U << 4)


static int host_state_manager_save_active_manifest (struct state_manager *manager,
	uint8_t manifest_index, enum manifest_region active)
{
	return state_manager_save_active_manifest (manager, active, ACTIVE_PFM_MASK);
}

static enum manifest_region host_state_manager_get_active_manifest (struct state_manager *manager,
	uint8_t manifest_index)
{
	return state_manager_get_active_manifest (manager, ACTIVE_PFM_MASK);
}

static int host_state_manager_restore_default_state (struct state_manager *manager)
{
	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	manager->nv_state = 0xffff;
	manager->volatile_state &= ~RUN_TIME_MASK;
	manager->volatile_state |= PFM_DIRTY_MASK;

	platform_mutex_unlock (&manager->state_lock);
	return 0;
}

static int host_state_manager_is_manifest_valid (struct state_manager *manager,
	uint8_t manifest_index)
{
	return 0;
}

/**
 * Initialize the manager for host state information.
 *
 * @param manager The state manager to initialize.
 * @param state_flash The flash that contains the non-volatile state information.
 * @param store_addr The starting address for state storage.  The state storage uses two contiguous
 * flash regions of FLASH_SECTOR_SIZE.  The start address must be aligned to the start of a flash
 * sector.
 *
 * @return 0 if the state manager was successfully initialized or an error code.
 */
int host_state_manager_init (struct state_manager *manager, struct flash *state_flash,
	uint32_t store_addr)
{
	int status;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	status = state_manager_init (manager, state_flash, store_addr);
	if (status == 0) {
		manager->get_active_manifest = host_state_manager_get_active_manifest;
		manager->save_active_manifest = host_state_manager_save_active_manifest;
		manager->restore_default_state = host_state_manager_restore_default_state;
		manager->is_manifest_valid = host_state_manager_is_manifest_valid;

		manager->volatile_state |= PFM_DIRTY_MASK;
	}

	return status;
}

/**
 * Release the resources used by the host state manager.
 *
 * @param manager The state manager to release.
 */
void host_state_manager_release (struct state_manager *manager)
{
	state_manager_release (manager);
}

/**
 * Save the setting for the flash device that will be the flash device accessed by the host for
 * read-only data.  This setting will be stored in non-volatile memory on the next call to store
 * state.
 *
 * @param manager The host state to update.
 * @param ro The flash device to save as the read-only flash.
 *
 * @return 0 if the setting was saved or an error code if the setting was invalid.
 */
int host_state_manager_save_read_only_flash (struct state_manager *manager, spi_filter_cs ro)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	switch (ro) {
		case SPI_FILTER_CS_0:
			manager->nv_state = manager->nv_state | READ_ONLY_FLASH_MASK;
			break;

		case SPI_FILTER_CS_1:
			manager->nv_state = manager->nv_state & ~READ_ONLY_FLASH_MASK;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state_lock);
	return status;
}

/**
 * Get the current setting for the host's read-only flash device.
 *
 * @param manager The host state to query.
 *
 * @return The read-only flash device.
 */
spi_filter_cs host_state_manager_get_read_only_flash (struct state_manager *manager)
{
	if (manager == NULL) {
		return SPI_FILTER_CS_0;
	}

	return (manager->nv_state & READ_ONLY_FLASH_MASK) ? SPI_FILTER_CS_0 : SPI_FILTER_CS_1;
}

/**
 * Save the setting that indicates the read/write flash device has been written to in a read-only
 * region.  This setting will be stored in non-volatile memory on the next call to store state.
 *
 * @param manager The host state to update.
 * @param dirty true if the flash has been written to and is pending validation, false if validation
 * of the read/write flash is completed.
 *
 * @return 0 if the setting was saved or an error code if the manager instance is invalid.
 */
int host_state_manager_save_inactive_dirty (struct state_manager *manager, bool dirty)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	if (dirty) {
		manager->nv_state = manager->nv_state & ~INACTIVE_DIRTY_MASK;
		manager->volatile_state = manager->volatile_state & ~RUN_TIME_MASK;
	}
	else {
		manager->nv_state = manager->nv_state | INACTIVE_DIRTY_MASK;
	}

	platform_mutex_unlock (&manager->state_lock);
	return status;
}

/**
 * Get the current indication of whether the inactive read-only flash has been written or not.
 *
 * @param manager The host state to query.
 *
 * @return true if the inactive flash has been written and not validated or false otherwise.
 */
bool host_state_manager_is_inactive_dirty (struct state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !(manager->nv_state & INACTIVE_DIRTY_MASK);
}

/**
 * Save the setting that indicates the active recovery image region.  This setting will be stored
 * in non-volatile memory on the next call to store state.
 *
 * @param manager The host state to update.
 * @param active The recovery image region to save as the active region

 * @return 0 if the setting was saved or an error code.
 */
int host_state_manager_save_active_recovery_image (struct state_manager *manager,
	enum recovery_image_region active)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	switch (active) {
		case RECOVERY_IMAGE_REGION_1:
			manager->nv_state = manager->nv_state | ACTIVE_RECOVERY_IMAGE_MASK;
			break;

		case RECOVERY_IMAGE_REGION_2:
			manager->nv_state = manager->nv_state & ~ACTIVE_RECOVERY_IMAGE_MASK;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state_lock);

	return status;

}

/**
 * Get the current setting for the active recovery image region.
 *
 * @param manager The state manager to query.
 *
 * @return The active recovery image region.
 */
enum recovery_image_region host_state_manager_get_active_recovery_image (
	struct state_manager *manager)
{
	if (manager == NULL) {
		return RECOVERY_IMAGE_REGION_1;
	}

	return (manager->nv_state & ACTIVE_RECOVERY_IMAGE_MASK) ?
		RECOVERY_IMAGE_REGION_1 : RECOVERY_IMAGE_REGION_2;
}

/**
 * Set the state indicating if the pending PFM is dirty.  A dirty PFM is one for which flash
 * validation has not been attempted yet.  This state is volatile.
 *
 * @param manager The host state to update.
 * @param dirty The dirty state of the PFM.
 */
void host_state_manager_set_pfm_dirty (struct state_manager *manager, bool dirty)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state_lock);
		if (dirty) {
			manager->volatile_state |= PFM_DIRTY_MASK;
			if ((manager->volatile_state & RUN_TIME_MASK) ==
				HOST_STATE_PREVALIDATED_FLASH_AND_PFM) {
				manager->volatile_state &= ~RUN_TIME_MASK;
			}
		}
		else {
			manager->volatile_state &= ~PFM_DIRTY_MASK;
		}
		platform_mutex_unlock (&manager->state_lock);
	}
}

/**
 * Get the state indicating if the pending PFM is dirty.  A dirty PFM is one for which flash
 * validation has not been attempted yet.
 *
 * @param manager The host state to query.
 *
 * @return true if the pending PFM is dirty.
 */
bool host_state_manager_is_pfm_dirty (struct state_manager *manager)
{
	if (manager == NULL) {
		return true;
	}

	return !!(manager->volatile_state & PFM_DIRTY_MASK);
}

/**
 * Set the state indicating what run-time validation has been performed against host flash.  This
 * state is volatile.
 *
 * @param manager The host state to update.
 * @param state The run-time validation state for the host.
 */
void host_state_manager_set_run_time_validation (struct state_manager *manager,
	enum host_state_prevalidated state)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state_lock);
		manager->volatile_state &= ~RUN_TIME_MASK;
		manager->volatile_state |= state;
		platform_mutex_unlock (&manager->state_lock);
	}
}

/**
 * Get the state indicating what run-time validation has been performed against host flash.
 *
 * @param manager The host state to query.
 *
 * @return The run-time validation state for the host.
 */
enum host_state_prevalidated host_state_manager_get_run_time_validation (
	struct state_manager *manager)
{
	if (manager == NULL) {
		return HOST_STATE_PREVALIDATED_NONE;
	}

	return (enum host_state_prevalidated) (manager->volatile_state & RUN_TIME_MASK);
}

/**
 * Set the state indicating if the host is operating in bypass mode.  This state is volatile.
 *
 * @param manager The host state to update.
 * @param bypass The bypass state of the host.
 */
void host_state_manager_set_bypass_mode (struct state_manager *manager, bool bypass)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state_lock);
		if (bypass) {
			manager->volatile_state |= BYPASS_MASK;
		}
		else {
			manager->volatile_state &= ~BYPASS_MASK;
		}
		platform_mutex_unlock (&manager->state_lock);
	}
}

/**
 * Get the state indicating if the host is operating in bypass mode.
 *
 * @param manager The host state to query.
 *
 * @return true if the host is running in bypass mode.
 */
bool host_state_manager_is_bypass_mode (struct state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !!(manager->volatile_state & BYPASS_MASK);
}

/**
 * Set the state indicating if the host flash configuration is not supported by the SPI filter.
 *
 * @param manager The host state to update.
 * @param unsupported true to indicate an unsupported configuration.
 */
void host_state_manager_set_unsupported_flash (struct state_manager *manager, bool unsupported)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state_lock);
		if (unsupported) {
			manager->volatile_state |= BAD_FLASH_MASK;
		}
		else {
			manager->volatile_state &= ~BAD_FLASH_MASK;
		}
		platform_mutex_unlock (&manager->state_lock);
	}
}

/**
 * Indicate if the host flash configuration is supported by the SPI filter.
 *
 * @param manager The host state to query.
 *
 * @return true if the flash configuration is supported.
 */
bool host_state_manager_is_flash_supported (struct state_manager *manager)
{
	if (manager == NULL) {
		return true;
	}

	return !(manager->volatile_state & BAD_FLASH_MASK);
}
