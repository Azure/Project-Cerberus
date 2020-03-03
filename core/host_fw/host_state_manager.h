// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_STATE_MANAGER_H_
#define HOST_STATE_MANAGER_H_

#include <stdint.h>
#include <stdbool.h>
#include "flash/flash.h"
#include "spi_filter/spi_filter_interface.h"
#include "state_manager/state_manager.h"


int host_state_manager_init (struct state_manager *manager, struct flash *state_flash,
	uint32_t store_addr);
void host_state_manager_release (struct state_manager *manager);

/* Non-volatile state. */

int host_state_manager_save_read_only_flash (struct state_manager *manager, spi_filter_cs ro);
spi_filter_cs host_state_manager_get_read_only_flash (struct state_manager *manager);

int host_state_manager_save_inactive_dirty (struct state_manager *manager, bool dirty);
bool host_state_manager_is_inactive_dirty (struct state_manager *manager);

/**
 * Definitions to indicate which region of flash holds the active recovery image.
 */
enum recovery_image_region {
	RECOVERY_IMAGE_REGION_1,			/**< The primary recovery image region contains the active image. */
	RECOVERY_IMAGE_REGION_2,			/**< The secondary recovery image region contains the active image. */
};

int host_state_manager_save_active_recovery_image (struct state_manager *manager,
	enum recovery_image_region active);
enum recovery_image_region host_state_manager_get_active_recovery_image (
	struct state_manager *manager);

/* Volatile state */

void host_state_manager_set_pfm_dirty (struct state_manager *manager, bool dirty);
bool host_state_manager_is_pfm_dirty (struct state_manager *manager);

/**
 * States to indicate the level of run-time validation done for host flash.
 */
enum host_state_prevalidated {
	HOST_STATE_PREVALIDATED_NONE = 0,			/**< No run-time validation was performed. */
	HOST_STATE_PREVALIDATED_FLASH = 2,			/**< The R/W flash was been validated against the active PFM. */
	HOST_STATE_PREVALIDATED_FLASH_AND_PFM = 6,	/**< The R/W flash has been validated against the pending PFM. */
};

void host_state_manager_set_run_time_validation (struct state_manager *manager,
	enum host_state_prevalidated state);
enum host_state_prevalidated host_state_manager_get_run_time_validation (
	struct state_manager *manager);

void host_state_manager_set_bypass_mode (struct state_manager *manager, bool bypass);
bool host_state_manager_is_bypass_mode (struct state_manager *manager);

void host_state_manager_set_unsupported_flash (struct state_manager *manager, bool unsupported);
bool host_state_manager_is_flash_supported (struct state_manager *manager);


#endif /* HOST_STATE_MANAGER_H_ */
