// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_LOGGING_H_
#define HOST_LOGGING_H_

#include "logging/debug_log.h"


/**
 * Logging messages for host firmware management.
 */
enum {
	HOST_LOGGING_PENDING_FAILED_FW_UPDATE,		/**< The pending PFM failed to enable a firmware update. */
	HOST_LOGGING_PENDING_FAILED_CURRENT,		/**< The pending PFM failed to enable the current firmware. */
	HOST_LOGGING_ACTIVE_FAILED_FW_UPDATE,		/**< The active PFM failed to enable a firmware update. */
	HOST_LOGGING_ROLLBACK_FAILED,				/**< A rollback attempt failed. */
	HOST_LOGGING_RECOVERY_IRQ,					/**< Failure to control BMC recovery IRQ generation. */
	HOST_LOGGING_SOFT_RESET,					/**< Error during soft reset processing. */
	HOST_LOGGING_PENDING_VERIFY_FW_UPDATE,		/**< Verifying a firmware update with the pending PFM. */
	HOST_LOGGING_PENDING_VERIFY_CURRENT,		/**< Verifying the current firmware with the pending PFM. */
	HOST_LOGGING_ACTIVE_VERIFY_FW_UPDATE,		/**< Verifying a firmware update with the active PFM. */
	HOST_LOGGING_ACTIVE_VERIFY_CURRENT,			/**< Verifying the current firmware with the active PFM. */
	HOST_LOGGING_ACTIVE_FAILED_CURRENT,			/**< The active PFM failed to enable the current firmware. */
	HOST_LOGGING_PENDING_ACTIVATE_FW_UPDATE,	/**< Activating a firmware update with the pending PFM. */
	HOST_LOGGING_ACTIVE_ACTIVATE_FW_UPDATE,		/**< Activating a firmware update with the active PFM. */
	HOST_LOGGING_ROLLBACK_STARTED,				/**< Host flash rollback has been triggered. */
	HOST_LOGGING_ROLLBACK_COMPLETED,			/**< Host flash rollback completed successfully. */
	HOST_LOGGING_PENDING_ROLLBACK_FAILED,		/**< A rollback attempt using the pending PFM failed. */
	HOST_LOGGING_PREPARE_UPDATE,				/**< Prepare host flash for a firmware update. */
	HOST_LOGGING_WRITE_UPDATE_FAILED,			/**< Failed to write firmware update data to host flash. */
	HOST_LOGGING_NOTIFICATION_ERROR,			/**< Unknown task action specified. */
	HOST_LOGGING_ENTER_RESET,					/**< Detected host reset. */
	HOST_LOGGING_EXIT_RESET,					/**< Detected host out of reset. */
	HOST_LOGGING_HOST_DOWN,						/**< Host down interrupt received. */
	HOST_LOGGING_HOST_UP,						/**< Host up interrupt received. */
	HOST_LOGGING_RECOVERY_STARTED,				/**< Recovery process has been triggered. */
	HOST_LOGGING_RECOVERY_COMPLETED,			/**< Recovery process completed successfully. */
	HOST_LOGGING_RECOVERY_FAILED,				/**< Recovery attempt failed. */
	HOST_LOGGING_HOST_FLASH_ACCESS_ERROR,		/**< Error giving the host SPI access. */
	HOST_LOGGING_HOST_FLASH_ACCESS_RETRIES,		/**< The number of attempts needed to give the host SPI access. */
	HOST_LOGGING_POWER_ON_RESET,				/**< Error during power-on reset processing. */
	HOST_LOGGING_BYPASS_MODE,					/**< Configuring host for unsecure boot. */
	HOST_LOGGING_ROT_FLASH_ACCESS_ERROR,		/**< Error setting RoT SPI access. */
	HOST_LOGGING_ROT_FLASH_ACCESS_RETRIES,		/**< The number of attempts needed to set RoT SPI access. */
	HOST_LOGGING_FILTER_FLASH_TYPE_ERROR,		/**< Error configuring the SPI filter for the flash devices. */
	HOST_LOGGING_FILTER_FLASH_TYPE_RETRIES,		/**< The number of attempts needed to configure the filter. */
	HOST_LOGGING_SWAP_FLASH_ERROR,				/**< Error swapping the flash devices. */
	HOST_LOGGING_SWAP_FLASH_RETRIES,			/**< The number of attempts needed to swap flash devices. */
	HOST_LOGGING_FILTER_RW_REGIONS_ERROR,		/**< Error configuring the SPI filter read/write regions. */
	HOST_LOGGING_FILTER_RW_REGIONS_RETRIES,		/**< The number of attempts needed to configure the filter regions. */
	HOST_LOGGING_INIT_PROTECTION_ERROR,			/**< Error initializing protection for host flash. */
	HOST_LOGGING_INIT_PROTECTION_RETRIES,		/**< The number of attempts needed to initialize flash protection. */
	HOST_LOGGING_CONFIG_FLASH_ERROR,			/**< Error configuring the flash roles. */
	HOST_LOGGING_CONFIG_FLASH_RETRIES,			/**< The number of attempts needed to configure the device roles. */
	HOST_LOGGING_BYPASS_MODE_ERROR,				/**< Error configuring the filter for bypass mode. */
	HOST_LOGGING_BYPASS_MODE_RETRIES,			/**< The number of attempts needed to configure the filter. */
	HOST_LOGGING_CLEAR_RW_REGIONS_ERROR,		/**< Error clearing the SPI filter read/write regions. */
	HOST_LOGGING_CLEAR_RW_REGIONS_RETRIES,		/**< The number of attempts needed to clear the filter regions. */
	HOST_LOGGING_PCR_UPDATE_ERROR,				/**< Error while updating a PCR entry. */
	HOST_LOGGING_BACKUP_FIRMWARE_STARTED,		/**< Start backup of active host firmware. */
	HOST_LOGGING_BACKUP_FIRMWARE_COMPLETED,		/**< Host active firmware backup has completed. */
	HOST_LOGGING_BMC_RECOVERY_DETECTED,			/**< Detected BMC recovery attempt. */
    HOST_LOGGING_RESET_COUNTER_UPDATE_FAILED,   /**< Reset counter update failed. */
	HOST_LOGGING_RW_RESTORE_START,				/**< Start condition for restoring active R/W regions. */
	HOST_LOGGING_RW_RESTORE_FINISH,				/**< End condition for active image R/W regions. */
	HOST_LOGGING_CHECK_PENDING_FAILED,			/**< Failed an empty check for a pending PFM. */
	HOST_LOGGING_CLEAR_PFMS,					/**< Clearing all PFMs to enable bypass mode. */
};


#endif /* HOST_LOGGING_H_ */
