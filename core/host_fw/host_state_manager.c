// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_state_manager.h"
#include "host_state_observer.h"
#include "common/unused.h"
#include "flash/flash_common.h"
#include "flash/flash_util.h"


/* Bitmasks for settings in non-volatile memory. */

/**
 * Bit indicating which flash is designated as the read-only flash, CS0 or CS1.  This value is
 * inverted, since blank flash is 1.
 */
#define	READ_ONLY_FLASH_MASK		(1U << 0)

/**
 * Bit indicating a protected region of the host flash has been modified.  This value is inverted,
 * since blank flash is 1.
 */
#define	INACTIVE_DIRTY_MASK			(1U << 1)

/**
 * Bit indicating which PFM region contains the active PFM, region 0 or 1.  This value is inverted,
 * since blank flash is 1.
 */
#define	ACTIVE_PFM_MASK				(1U << 2)

/**
 * Bit indicating which recovery image region contains the active recovery image, region 0 or 1.
 * This value is inverted, since blank flash is 1.
 */
#define	ACTIVE_RECOVERY_IMAGE_MASK	(1U << 3)

/**
 * Bits indicating which host events can trigger a switch of read-only flash.  This will store an
 * enum host_read_only_activation value.
 */
#define	RO_FLASH_SWITCH_OFFSET		4
#define	RO_FLASH_SWITCH_MASK		(3U << RO_FLASH_SWITCH_OFFSET)

/* Bits 6 and 7 are used by the base state manager. */

/**
 * Bit indicating a flash device to temporarily use as the read-only flash, overriding the setting
 * stored at READ_ONLY_FLASH_MASK.  This value is inverted, since blank flash is 1.
 */
#define	OVERRIDE_RO_FLASH_MASK		(1U << 8)

/**
 * Bit indicating the read-only override is valid and should be used instead of the normal read-only
 * flash setting.  This value is inverted, since blank flash is 1.
 */
#define	OVERRIDE_RO_VALID_MASK		(1U << 9)


/* Bitmasks for settings in volatile memory. */

/**
 * Bit indicating the current pending PFM has not been checked against the current flash image.
 */
#define	PFM_DIRTY_MASK				(1U << 0)

/**
 * Bits indicating the results of any flash prevalidation that has been run.  This will store an
 * enum host_state_prevalidated value.
 */
#define	RUN_TIME_MASK				(3U << 1)

/**
 * Bit indicating the SPI filter is currently operating in bypass mode.
 */
#define	BYPASS_MASK					(1U << 3)

/**
 * Bit indicating the host flash configuration is unsupported.
 */
#define	BAD_FLASH_MASK				(1U << 4)


int host_state_manager_save_active_manifest (const struct state_manager *manager,
	uint8_t manifest_index, enum manifest_region active)
{
	const struct host_state_manager *host_state = (const struct host_state_manager*) manager;
	int status;

	UNUSED (manifest_index);

	status = state_manager_save_active_manifest (manager, active, ACTIVE_PFM_MASK);
	if (status == 0) {
		if (status == 0) {
			observable_notify_observers_with_ptr (&host_state->state->observable,
				offsetof (struct host_state_observer, on_active_pfm), (void*) host_state);
		}
	}

	return status;
}

enum manifest_region host_state_manager_get_active_manifest (const struct state_manager *manager,
	uint8_t manifest_index)
{
	UNUSED (manifest_index);

	return state_manager_get_active_manifest (manager, ACTIVE_PFM_MASK);
}

int host_state_manager_restore_default_state (const struct state_manager *manager)
{
	const struct host_state_manager *host_state = (const struct host_state_manager*) manager;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state->state_lock);

	manager->state->nv_state = 0xffff;
	manager->state->volatile_state &= ~RUN_TIME_MASK;
	manager->state->volatile_state |= PFM_DIRTY_MASK;

	platform_mutex_unlock (&manager->state->state_lock);

	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_active_pfm), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_read_only_flash), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_inactive_dirty), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_read_only_activation_events), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_active_recovery_image), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_pfm_dirty), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_run_time_validation), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_bypass_mode), (void*) host_state);
	observable_notify_observers_with_ptr (&host_state->state->observable,
		offsetof (struct host_state_observer, on_unsupported_flash), (void*) host_state);

	return 0;
}

int host_state_manager_is_manifest_valid (const struct state_manager *manager,
	uint8_t manifest_index)
{
	UNUSED (manager);
	UNUSED (manifest_index);

	return 0;
}

/**
 * Initialize the manager for host state information.
 *
 * @param manager The state manager to initialize.
 * @param state Variable const for host state management.  This must be uninitialized.
 * @param state_flash The flash that contains the non-volatile state information.
 * @param store_addr The starting address for state storage.  The state storage uses two contiguous
 * flash sectors.  The start address must be aligned to the start of a flash sector.
 *
 * @return 0 if the state manager was successfully initialized or an error code.
 */
int host_state_manager_init (struct host_state_manager *manager,
	struct host_state_manager_state *state, const struct flash *state_flash, uint32_t store_addr)
{
	int status;

	if ((manager == NULL) || (state == NULL)) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	memset (manager, 0, sizeof (struct host_state_manager));

	status = state_manager_init (&manager->base, &state->base, state_flash, store_addr);
	if (status != 0) {
		return status;
	}

	manager->state = state;

	status = observable_init (&manager->state->observable);
	if (status != 0) {
		state_manager_release (&manager->base);

		return status;
	}

	manager->base.get_active_manifest = host_state_manager_get_active_manifest;
	manager->base.save_active_manifest = host_state_manager_save_active_manifest;
	manager->base.restore_default_state = host_state_manager_restore_default_state;
	manager->base.is_manifest_valid = host_state_manager_is_manifest_valid;

	manager->state->base.volatile_state |= PFM_DIRTY_MASK;

	return 0;
}

/**
 * Initialize only the variable state of a manager for host state information.  The rest of the
 * instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param manager The state manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int host_state_manager_init_state (const struct host_state_manager *manager)
{
	int status;

	if ((manager == NULL) || (manager->state == NULL)) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	status = state_manager_init_state (&manager->base);
	if (status != 0) {
		return status;
	}

	status = observable_init (&manager->state->observable);
	if (status != 0) {
		state_manager_release (&manager->base);

		return status;
	}

	manager->state->base.volatile_state |= PFM_DIRTY_MASK;

	return 0;
}

/**
 * Release the resources used by the host state manager.
 *
 * @param manager The state manager to release.
 */
void host_state_manager_release (const struct host_state_manager *manager)
{
	if (manager) {
		state_manager_release (&manager->base);
		observable_release (&manager->state->observable);
	}
}

int host_state_manager_add_observer (const struct host_state_manager *manager,
	const struct host_state_observer *observer)
{
	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	return observable_add_observer (&manager->state->observable, (void*) observer);
}

int host_state_manager_remove_observer (const struct host_state_manager *manager,
	const struct host_state_observer *observer)
{
	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	return observable_remove_observer (&manager->state->observable, (void*) observer);
}

/**
 * Get the current setting for the host's read-only flash device, taking into account any active
 * override of the non-volatile setting.
 *
 * @param manager The host state to query.
 *
 * @return The read-only flash device.
 */
spi_filter_cs host_state_manager_get_read_only_flash (const struct host_state_manager *manager)
{
	if (host_state_manager_has_read_only_flash_override (manager)) {
		return (manager->state->base.nv_state & OVERRIDE_RO_FLASH_MASK) ?
				   SPI_FILTER_CS_0 : SPI_FILTER_CS_1;
	}
	else {
		return host_state_manager_get_read_only_flash_nv_config (manager);
	}
}

/**
 * Save the non-volatile setting for the flash device that will be the flash device accessed by the
 * host for read-only data.  This value will only get used when there is no active override of the
 * read-only flash device.  This setting will be stored in non-volatile memory on the next call to
 * store state.
 *
 * @param manager The host state to update.
 * @param ro The flash device to save as the read-only flash.
 *
 * @return 0 if the setting was saved or an error code.
 */
int host_state_manager_save_read_only_flash_nv_config (const struct host_state_manager *manager,
	spi_filter_cs ro)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state->base.state_lock);

	switch (ro) {
		case SPI_FILTER_CS_0:
			manager->state->base.nv_state |= READ_ONLY_FLASH_MASK;
			break;

		case SPI_FILTER_CS_1:
			manager->state->base.nv_state &= ~READ_ONLY_FLASH_MASK;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state->base.state_lock);

	if (status == 0) {
		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_read_only_flash), (void*) manager);
	}

	return status;
}

/**
 * Get the current non-volatile setting for the host's read-only flash device.  Any override of the
 * read-only flash setting will be ignored.
 *
 * @param manager The host state to query.
 *
 * @return The non-volatile value for the read-only flash device.
 */
spi_filter_cs host_state_manager_get_read_only_flash_nv_config (
	const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return SPI_FILTER_CS_0;
	}

	return (manager->state->base.nv_state & READ_ONLY_FLASH_MASK) ?
			   SPI_FILTER_CS_0 : SPI_FILTER_CS_1;
}

/**
 * Override the non-volatile configuration for the host's read-only flash device.  While this
 * override is in place, the non-volatile state will not be considered when reporting the current
 * read-only flash being used.  This setting will be stored in non-volatile memory on the next call
 * to store state.
 *
 * @param manager The host state to update.
 * @param ro The flash device to use as the read-only flash.
 *
 * @return 0 if the override was applied successfully or an error code.
 */
int host_state_manager_override_read_only_flash (const struct host_state_manager *manager,
	spi_filter_cs ro)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state->base.state_lock);

	switch (ro) {
		case SPI_FILTER_CS_0:
			manager->state->base.nv_state |= OVERRIDE_RO_FLASH_MASK;
			manager->state->base.nv_state &= ~OVERRIDE_RO_VALID_MASK;
			break;

		case SPI_FILTER_CS_1:
			manager->state->base.nv_state &= ~(OVERRIDE_RO_FLASH_MASK | OVERRIDE_RO_VALID_MASK);
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state->base.state_lock);

	if (status == 0) {
		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_read_only_flash), (void*) manager);
	}

	return status;
}

/**
 * Remove any override of the non-volatile read-only flash setting.  Once this is removed, future
 * calls to determine the read-only flash device will report the non-volatile setting.
 *
 * @param manager The host state to update.
 */
void host_state_manager_clear_read_only_flash_override (const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return;
	}

	platform_mutex_lock (&manager->state->base.state_lock);

	manager->state->base.nv_state |= (OVERRIDE_RO_FLASH_MASK | OVERRIDE_RO_VALID_MASK);

	platform_mutex_unlock (&manager->state->base.state_lock);

	observable_notify_observers_with_ptr (&manager->state->observable,
		offsetof (struct host_state_observer, on_read_only_flash), (void*) manager);
}

/**
 * Indicate if there is currently an override being applied to the host's read-only flash device
 * setting.
 *
 * @param manager The host state to query.
 *
 * @return true if there is an override being applied or false if not.
 */
bool host_state_manager_has_read_only_flash_override (const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !(manager->state->base.nv_state & OVERRIDE_RO_VALID_MASK);
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
int host_state_manager_save_inactive_dirty (const struct host_state_manager *manager, bool dirty)
{
	bool run_time;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state->base.state_lock);

	if (dirty) {
		manager->state->base.nv_state = manager->state->base.nv_state & ~INACTIVE_DIRTY_MASK;

		run_time = !!(manager->state->base.volatile_state & RUN_TIME_MASK);
		manager->state->base.volatile_state = manager->state->base.volatile_state & ~RUN_TIME_MASK;
	}
	else {
		manager->state->base.nv_state = manager->state->base.nv_state | INACTIVE_DIRTY_MASK;
	}

	platform_mutex_unlock (&manager->state->base.state_lock);

	observable_notify_observers_with_ptr (&manager->state->observable,
		offsetof (struct host_state_observer, on_inactive_dirty), (void*) manager);
	if (dirty && run_time) {
		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_run_time_validation), (void*) manager);
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
bool host_state_manager_is_inactive_dirty (const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !(manager->state->base.nv_state & INACTIVE_DIRTY_MASK);
}

/**
 * Save the setting that indicates what host events could trigger a swap of the read-only flash
 * device.  This setting will be stored in non-volatile memory on the next call to store state.
 *
 * @param manager The host state to update.
 * @param events The host events that can trigger the read-only flash to switch.
 *
 * @return 0 if the setting was saved or an error code.
 */
int host_state_manager_save_read_only_activation_events (const struct host_state_manager *manager,
	enum host_read_only_activation events)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state->base.state_lock);

	switch (events) {
		case HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY:
		case HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET:
		case HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME:
		case HOST_READ_ONLY_ACTIVATE_ON_ALL:
			manager->state->base.nv_state &= ~RO_FLASH_SWITCH_MASK;
			manager->state->base.nv_state |= (events << RO_FLASH_SWITCH_OFFSET);
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state->base.state_lock);

	if (status == 0) {
		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_read_only_activation_events), (void*) manager);
	}

	return status;
}

/**
 * Get the current setting for the host events that can trigger a swap of the read-only flash
 * device.
 *
 * @param manager The host state to query.
 *
 * @return The host events that can trigger the read-only flash to switch.
 */
enum host_read_only_activation host_state_manager_get_read_only_activation_events (
	const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return HOST_READ_ONLY_ACTIVATE_ON_ALL;
	}

	return ((manager->state->base.nv_state & RO_FLASH_SWITCH_MASK) >> RO_FLASH_SWITCH_OFFSET);
}

/**
 * Save the setting that indicates the active recovery image region.  This setting will be stored
 * in non-volatile memory on the next call to store state.
 *
 * @param manager The host state to update.
 * @param active The recovery image region to save as the active region

 * @return 0 if the setting was saved or an error code.
 */
int host_state_manager_save_active_recovery_image (const struct host_state_manager *manager,
	enum recovery_image_region active)
{
	int status = 0;

	if (manager == NULL) {
		return STATE_MANAGER_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&manager->state->base.state_lock);

	switch (active) {
		case RECOVERY_IMAGE_REGION_1:
			manager->state->base.nv_state = manager->state->base.nv_state |
				ACTIVE_RECOVERY_IMAGE_MASK;
			break;

		case RECOVERY_IMAGE_REGION_2:
			manager->state->base.nv_state = manager->state->base.nv_state &
				~ACTIVE_RECOVERY_IMAGE_MASK;
			break;

		default:
			status = STATE_MANAGER_INVALID_ARGUMENT;
			break;
	}

	platform_mutex_unlock (&manager->state->base.state_lock);

	if (status == 0) {
		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_active_recovery_image), (void*) manager);
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
	const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return RECOVERY_IMAGE_REGION_1;
	}

	return (manager->state->base.nv_state & ACTIVE_RECOVERY_IMAGE_MASK) ?
			   RECOVERY_IMAGE_REGION_1 : RECOVERY_IMAGE_REGION_2;
}

/**
 * Set the state indicating if the pending PFM is dirty.  A dirty PFM is one for which flash
 * validation has not been attempted yet.  This state is volatile.
 *
 * @param manager The host state to update.
 * @param dirty The dirty state of the PFM.
 */
void host_state_manager_set_pfm_dirty (const struct host_state_manager *manager, bool dirty)
{
	bool run_time = false;

	if (manager != NULL) {
		platform_mutex_lock (&manager->state->base.state_lock);
		if (dirty) {
			manager->state->base.volatile_state |= PFM_DIRTY_MASK;
			if ((manager->state->base.volatile_state & RUN_TIME_MASK) ==
				HOST_STATE_PREVALIDATED_FLASH_AND_PFM) {
				run_time = true;
				manager->state->base.volatile_state &= ~RUN_TIME_MASK;
			}
		}
		else {
			manager->state->base.volatile_state &= ~PFM_DIRTY_MASK;
		}
		platform_mutex_unlock (&manager->state->base.state_lock);

		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_pfm_dirty), (void*) manager);
		if (run_time) {
			observable_notify_observers_with_ptr (&manager->state->observable,
				offsetof (struct host_state_observer, on_run_time_validation), (void*) manager);
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
bool host_state_manager_is_pfm_dirty (const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return true;
	}

	return !!(manager->state->base.volatile_state & PFM_DIRTY_MASK);
}

/**
 * Set the state indicating what run-time validation has been performed against host flash.  This
 * state is volatile.
 *
 * @param manager The host state to update.
 * @param state The run-time validation state for the host.
 */
void host_state_manager_set_run_time_validation (const struct host_state_manager *manager,
	enum host_state_prevalidated state)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state->base.state_lock);
		manager->state->base.volatile_state &= ~RUN_TIME_MASK;
		manager->state->base.volatile_state |= state;
		platform_mutex_unlock (&manager->state->base.state_lock);

		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_run_time_validation), (void*) manager);
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
	const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return HOST_STATE_PREVALIDATED_NONE;
	}

	return (enum host_state_prevalidated) (manager->state->base.volatile_state & RUN_TIME_MASK);
}

/**
 * Set the state indicating if the host is operating in bypass mode.  This state is volatile.
 *
 * @param manager The host state to update.
 * @param bypass The bypass state of the host.
 */
void host_state_manager_set_bypass_mode (const struct host_state_manager *manager, bool bypass)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state->base.state_lock);
		if (bypass) {
			manager->state->base.volatile_state |= BYPASS_MASK;
		}
		else {
			manager->state->base.volatile_state &= ~BYPASS_MASK;
		}
		platform_mutex_unlock (&manager->state->base.state_lock);

		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_bypass_mode), (void*) manager);
	}
}

/**
 * Get the state indicating if the host is operating in bypass mode.
 *
 * @param manager The host state to query.
 *
 * @return true if the host is running in bypass mode.
 */
bool host_state_manager_is_bypass_mode (const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return false;
	}

	return !!(manager->state->base.volatile_state & BYPASS_MASK);
}

/**
 * Set the state indicating if the host flash configuration is not supported by the SPI filter.
 *
 * @param manager The host state to update.
 * @param unsupported true to indicate an unsupported configuration.
 */
void host_state_manager_set_unsupported_flash (const struct host_state_manager *manager,
	bool unsupported)
{
	if (manager != NULL) {
		platform_mutex_lock (&manager->state->base.state_lock);
		if (unsupported) {
			manager->state->base.volatile_state |= BAD_FLASH_MASK;
		}
		else {
			manager->state->base.volatile_state &= ~BAD_FLASH_MASK;
		}
		platform_mutex_unlock (&manager->state->base.state_lock);

		observable_notify_observers_with_ptr (&manager->state->observable,
			offsetof (struct host_state_observer, on_unsupported_flash), (void*) manager);
	}
}

/**
 * Indicate if the host flash configuration is supported by the SPI filter.
 *
 * @param manager The host state to query.
 *
 * @return true if the flash configuration is supported.
 */
bool host_state_manager_is_flash_supported (const struct host_state_manager *manager)
{
	if (manager == NULL) {
		return true;
	}

	return !(manager->state->base.volatile_state & BAD_FLASH_MASK);
}
