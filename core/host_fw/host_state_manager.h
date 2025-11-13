// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_MANAGER_H_
#define HOST_STATE_MANAGER_H_

#include <stdbool.h>
#include <stdint.h>
#include "common/observable.h"
#include "spi_filter/spi_filter_interface.h"
#include "state_manager/state_manager.h"


struct host_state_observer;

/**
 * Variable context for managing host state information.
 */
struct host_state_manager_state {
	struct state_manager_state base;	/**< Variable context for base state management. */
	struct observable observable;		/**< Observer manager for the state manager. */
};

/**
 * Manager for state information for a single host.
 */
struct host_state_manager {
	struct state_manager base;				/**< The base state manager. */
	struct host_state_manager_state *state;	/**< Variable context for host state management. */
};


int host_state_manager_init (struct host_state_manager *manager,
	struct host_state_manager_state *state, const struct flash *state_flash, uint32_t store_addr);
int host_state_manager_init_state (const struct host_state_manager *manager);
void host_state_manager_release (const struct host_state_manager *manager);

int host_state_manager_add_observer (const struct host_state_manager *manager,
	const struct host_state_observer *observer);
int host_state_manager_remove_observer (const struct host_state_manager *manager,
	const struct host_state_observer *observer);

/* Non-volatile state. */

spi_filter_cs host_state_manager_get_read_only_flash (const struct host_state_manager *manager);

int host_state_manager_save_read_only_flash_nv_config (const struct host_state_manager *manager,
	spi_filter_cs ro);
spi_filter_cs host_state_manager_get_read_only_flash_nv_config (
	const struct host_state_manager *manager);

int host_state_manager_override_read_only_flash (const struct host_state_manager *manager,
	spi_filter_cs ro);
void host_state_manager_clear_read_only_flash_override (const struct host_state_manager *manager);
bool host_state_manager_has_read_only_flash_override (const struct host_state_manager *manager);

int host_state_manager_save_inactive_dirty (const struct host_state_manager *manager, bool dirty);
bool host_state_manager_is_inactive_dirty (const struct host_state_manager *manager);

/**
 * Definitions to indicate which host events can trigger a switch of read-only flash.  This switch
 * can be due to dirty flash or removal of a temporary override.
 */
enum host_read_only_activation {
	/**
	 * Read-only flash is only switched during power-on reset flows.
	 */
	HOST_READ_ONLY_ACTIVATE_ON_POR_ONLY = 0,
	/**
	 * Read-only flash can be switched during host resets.
	 */
	HOST_READ_ONLY_ACTIVATE_ON_POR_AND_RESET = 1,
	/**
	 * Read-only flash can be switched during run-time verification.
	 */
	HOST_READ_ONLY_ACTIVATE_ON_POR_AND_AT_RUN_TIME = 2,
	/**
	 * Read-only flash can be switched on any host event.
	 */
	HOST_READ_ONLY_ACTIVATE_ON_ALL = 3,
};


int host_state_manager_save_read_only_activation_events (struct host_state_manager *manager,
	enum host_read_only_activation events);
enum host_read_only_activation host_state_manager_get_read_only_activation_events (
	struct host_state_manager *manager);

/**
 * Definitions to indicate which region of flash holds the active recovery image.
 */
enum recovery_image_region {
	RECOVERY_IMAGE_REGION_1,	/**< The primary recovery image region contains the active image. */
	RECOVERY_IMAGE_REGION_2,	/**< The secondary recovery image region contains the active image. */
};


int host_state_manager_save_active_recovery_image (const struct host_state_manager *manager,
	enum recovery_image_region active);
enum recovery_image_region host_state_manager_get_active_recovery_image (
	const struct host_state_manager *manager);


/* Volatile state */

void host_state_manager_set_pfm_dirty (const struct host_state_manager *manager, bool dirty);
bool host_state_manager_is_pfm_dirty (const struct host_state_manager *manager);

/**
 * States to indicate the level of run-time validation done for host flash.
 */
enum host_state_prevalidated {
	HOST_STATE_PREVALIDATED_NONE = 0,			/**< No run-time validation was performed. */
	HOST_STATE_PREVALIDATED_FLASH = 2,			/**< The R/W flash was been validated against the active PFM. */
	HOST_STATE_PREVALIDATED_FLASH_AND_PFM = 6,	/**< The R/W flash has been validated against the pending PFM. */
};


void host_state_manager_set_run_time_validation (const struct host_state_manager *manager,
	enum host_state_prevalidated state);
enum host_state_prevalidated host_state_manager_get_run_time_validation (
	const struct host_state_manager *manager);


void host_state_manager_set_bypass_mode (const struct host_state_manager *manager, bool bypass);
bool host_state_manager_is_bypass_mode (const struct host_state_manager *manager);

void host_state_manager_set_unsupported_flash (const struct host_state_manager *manager,
	bool unsupported);
bool host_state_manager_is_flash_supported (const struct host_state_manager *manager);


#endif	/* HOST_STATE_MANAGER_H_ */
