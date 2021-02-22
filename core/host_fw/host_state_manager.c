// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_state_manager.h"
#include "host_state_observer.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/* Bitmasks for settings in non-volatile memory. */
#define	READ_ONLY_FLASH_MASK		(1U << 0)
#define	INACTIVE_DIRTY_MASK			(1U << 1)
#define	ACTIVE_PFM_MASK				(1U << 2)
#define	ACTIVE_RECOVERY_IMAGE_MASK	(1U << 3)

/* Bitmasks for settings in volatile memory. */
#define	PFM_DIRTY_MASK				(1U << 0)
#define	RUN_TIME_MASK				(3U << 1)
#define	BYPASS_MASK					(1U << 3)
#define	BAD_FLASH_MASK				(1U << 4)


static int host_state_manager_save_active_manifest (struct state_manager *manager,
	uint8_t manifest_index, enum manifest_region active)
{
	struct host_state_manager *host_state = (struct host_state_manager*) manager;
	int status;

	status = state_manager_save_active_manifest (manager, active, ACTIVE_PFM_MASK);
	if (status == 0) {
		if (status == 0) {
			observable_notify_observers_with_ptr (&host_state->observable,
				offsetof (struct host_state_observer, on_active_pfm), host_state);
		}
	}

	return status;
}

static enum manifest_region host_state_manager_get_active_manifest (struct state_manager *manager,
	uint8_t manifest_index)
{
	return state_manager_get_active_manifest (manager, ACTIVE_PFM_MASK);
}

static int host_state_manager_restore_default_state (struct state_manager *manager)
{
	struct host_state_manager *host_state = (struct host_state_manager*) manager;

	if (host_state == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state_lock);

	manager->nv_state = 0xffff;
	manager->volatile_state &= ~RUN_TIME_MASK;
	manager->volatile_state |= PFM_DIRTY_MASK;

	platform_mutex_unlock (&manager->state_lock);

	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_active_pfm), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_read_only_flash), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_inactive_dirty), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_active_recovery_image), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_pfm_dirty), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_run_time_validation), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_bypass_mode), host_state);
	observable_notify_observers_with_ptr (&host_state->observable,
		offsetof (struct host_state_observer, on_unsupported_flash), host_state);

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
int host_state_manager_init (struct host_state_manager *manager, struct flash *state_flash,
	uint32_t store_addr)
{
	int status;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct host_state_manager));

	status = state_manager_init (&manager->base, state_flash, store_addr);
	if (status != 0) {
		return status;
	}

	status = observable_init (&manager->observable);
	if (status != 0) {
		state_manager_release (&manager->base);
		return status;
	}

	manager->base.get_active_manifest = host_state_manager_get_active_manifest;
	manager->base.save_active_manifest = host_state_manager_save_active_manifest;
	manager->base.restore_default_state = host_state_manager_restore_default_state;
	manager->base.is_manifest_valid = host_state_manager_is_manifest_valid;

	manager->base.volatile_state |= PFM_DIRTY_MASK;

	return 0;
}

/**
 * Release the resources used by the host state manager.
 *
 * @param manager The state manager to release.
 */
void host_state_manager_release (struct host_state_manager *manager)
{
	if (manager) {
		state_manager_release (&manager->base);
		observable_release (&manager->observable);
	}
}

int host_state_manager_add_observer (struct host_state_manager *manager,
	struct host_state_observer *observer)
{
	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->observable, observer);
}

int host_state_manager_remove_observer (struct host_state_manager *manager,
	struct host_state_observer *observer)
{
	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->observable, observer);
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
int host_state_manager_save_read_only_flash (struct host_state_manager *manager, spi_filter_cs ro)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->base.state_lock);

	switch (ro) {
		case SPI_FILTER_CS_0:
			manager->base.nv_state = manager->base.nv_state | READ_ONLY_FLASH_MASK;
			break;

		case SPI_FILTER_CS_1:
			manager->base.nv_state = manager->base.nv_state & ~READ_ONLY_FLASH_MASK;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->base.state_lock);

	if (status == 0) {
		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_read_only_flash), manager);
	}

	return status;
}

/**
 * Get the current setting for the host's read-only flash device.
 *
 * @param manager The host state to query.
 *
 * @return The read-only flash device.
 */
spi_filter_cs host_state_manager_get_read_only_flash (struct host_state_manager *manager)
{
	if (manager == NULL) {
		return SPI_FILTER_CS_0;
	}

	return (manager->base.nv_state & READ_ONLY_FLASH_MASK) ? SPI_FILTER_CS_0 : SPI_FILTER_CS_1;
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
int host_state_manager_save_inactive_dirty (struct host_state_manager *manager, bool dirty)
{
	bool run_time;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->base.state_lock);

	if (dirty) {
		manager->base.nv_state = manager->base.nv_state & ~INACTIVE_DIRTY_MASK;

		run_time = !!(manager->base.volatile_state & RUN_TIME_MASK);
		manager->base.volatile_state = manager->base.volatile_state & ~RUN_TIME_MASK;
	}
	else {
		manager->base.nv_state = manager->base.nv_state | INACTIVE_DIRTY_MASK;
	}

	platform_mutex_unlock (&manager->base.state_lock);

	observable_notify_observers_with_ptr (&manager->observable,
		offsetof (struct host_state_observer, on_inactive_dirty), manager);
	if (dirty && run_time) {
		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_run_time_validation), manager);
	}

	return 0;
}

/**
 * Get the current indication of whether the inactive read-only flash has been written or not.
 *
 * @param manager The host state to query.
 *
 * @return true if the inactive flash has been written and not validated or false otherwise.
 */
bool host_state_manager_is_inactive_dirty (struct host_state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !(manager->base.nv_state & INACTIVE_DIRTY_MASK);
}

/**
 * Save the setting that indicates the active recovery image region.  This setting will be stored
 * in non-volatile memory on the next call to store state.
 *
 * @param manager The host state to update.
 * @param active The recovery image region to save as the active region

 * @return 0 if the setting was saved or an error code.
 */
int host_state_manager_save_active_recovery_image (struct host_state_manager *manager,
	enum recovery_image_region active)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->base.state_lock);

	switch (active) {
		case RECOVERY_IMAGE_REGION_1:
			manager->base.nv_state = manager->base.nv_state | ACTIVE_RECOVERY_IMAGE_MASK;
			break;

		case RECOVERY_IMAGE_REGION_2:
			manager->base.nv_state = manager->base.nv_state & ~ACTIVE_RECOVERY_IMAGE_MASK;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->base.state_lock);

	if (status == 0) {
		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_active_recovery_image), manager);
	}

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
	struct host_state_manager *manager)
{
	if (manager == NULL) {
		return RECOVERY_IMAGE_REGION_1;
	}

	return (manager->base.nv_state & ACTIVE_RECOVERY_IMAGE_MASK) ?
		RECOVERY_IMAGE_REGION_1 : RECOVERY_IMAGE_REGION_2;
}

/**
 * Set the state indicating if the pending PFM is dirty.  A dirty PFM is one for which flash
 * validation has not been attempted yet.  This state is volatile.
 *
 * @param manager The host state to update.
 * @param dirty The dirty state of the PFM.
 */
void host_state_manager_set_pfm_dirty (struct host_state_manager *manager, bool dirty)
{
	bool run_time = false;

	if (manager != NULL) {
		platform_mutex_lock (&manager->base.state_lock);
		if (dirty) {
			manager->base.volatile_state |= PFM_DIRTY_MASK;
			if ((manager->base.volatile_state & RUN_TIME_MASK) ==
				HOST_STATE_PREVALIDATED_FLASH_AND_PFM) {
				run_time = true;
				manager->base.volatile_state &= ~RUN_TIME_MASK;
			}
		}
		else {
			manager->base.volatile_state &= ~PFM_DIRTY_MASK;
		}
		platform_mutex_unlock (&manager->base.state_lock);

		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_pfm_dirty), manager);
		if (run_time) {
			observable_notify_observers_with_ptr (&manager->observable,
				offsetof (struct host_state_observer, on_run_time_validation), manager);
		}
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
bool host_state_manager_is_pfm_dirty (struct host_state_manager *manager)
{
	if (manager == NULL) {
		return true;
	}

	return !!(manager->base.volatile_state & PFM_DIRTY_MASK);
}

/**
 * Set the state indicating what run-time validation has been performed against host flash.  This
 * state is volatile.
 *
 * @param manager The host state to update.
 * @param state The run-time validation state for the host.
 */
void host_state_manager_set_run_time_validation (struct host_state_manager *manager,
	enum host_state_prevalidated state)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->base.state_lock);
		manager->base.volatile_state &= ~RUN_TIME_MASK;
		manager->base.volatile_state |= state;
		platform_mutex_unlock (&manager->base.state_lock);

		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_run_time_validation), manager);
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
	struct host_state_manager *manager)
{
	if (manager == NULL) {
		return HOST_STATE_PREVALIDATED_NONE;
	}

	return (enum host_state_prevalidated) (manager->base.volatile_state & RUN_TIME_MASK);
}

/**
 * Set the state indicating if the host is operating in bypass mode.  This state is volatile.
 *
 * @param manager The host state to update.
 * @param bypass The bypass state of the host.
 */
void host_state_manager_set_bypass_mode (struct host_state_manager *manager, bool bypass)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->base.state_lock);
		if (bypass) {
			manager->base.volatile_state |= BYPASS_MASK;
		}
		else {
			manager->base.volatile_state &= ~BYPASS_MASK;
		}
		platform_mutex_unlock (&manager->base.state_lock);

		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_bypass_mode), manager);
	}
}

/**
 * Get the state indicating if the host is operating in bypass mode.
 *
 * @param manager The host state to query.
 *
 * @return true if the host is running in bypass mode.
 */
bool host_state_manager_is_bypass_mode (struct host_state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !!(manager->base.volatile_state & BYPASS_MASK);
}

/**
 * Set the state indicating if the host flash configuration is not supported by the SPI filter.
 *
 * @param manager The host state to update.
 * @param unsupported true to indicate an unsupported configuration.
 */
void host_state_manager_set_unsupported_flash (struct host_state_manager *manager, bool unsupported)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->base.state_lock);
		if (unsupported) {
			manager->base.volatile_state |= BAD_FLASH_MASK;
		}
		else {
			manager->base.volatile_state &= ~BAD_FLASH_MASK;
		}
		platform_mutex_unlock (&manager->base.state_lock);

		observable_notify_observers_with_ptr (&manager->observable,
			offsetof (struct host_state_observer, on_unsupported_flash), manager);
	}
}

/**
 * Indicate if the host flash configuration is supported by the SPI filter.
 *
 * @param manager The host state to query.
 *
 * @return true if the flash configuration is supported.
 */
bool host_state_manager_is_flash_supported (struct host_state_manager *manager)
{
	if (manager == NULL) {
		return true;
	}

	return !(manager->base.volatile_state & BAD_FLASH_MASK);
}
