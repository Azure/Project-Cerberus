// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_MANAGER_H_
#define HOST_FLASH_MANAGER_H_

#include <stdbool.h>
#include "status/rot_status.h"
#include "host_control.h"
#include "host_flash_initialization.h"
#include "state_manager/state_manager.h"
#include "flash/spi_flash.h"
#include "spi_filter/spi_filter_interface.h"
#include "spi_filter/flash_mfg_filter_handler.h"
#include "manifest/pfm/pfm.h"
#include "manifest/pfm/pfm_manager.h"
#include "crypto/hash.h"
#include "crypto/rsa.h"


/**
 * Manager for protected flash devices for a single host processor.
 */
struct host_flash_manager {
	/**
	 * Get the flash device that is currently configured as the flash device for reading static
	 * regions.
	 *
	 * @param manager The flash manager to query.
	 *
	 * @return The read-only flash device.
	 */
	struct spi_flash* (*get_read_only_flash) (struct host_flash_manager *manager);

	/**
	 * Get the flash device that is currently configured as the flash device for all writes and
	 * reads for dynamic regions.
	 *
	 * @param manager The flash manager to query.
	 *
	 * @return The read/write flash device.
	 */
	struct spi_flash* (*get_read_write_flash) (struct host_flash_manager *manager);

	/**
	 * Validate the read-only flash device.
	 *
	 * @param manager The flash manager to use for validation.
	 * @param pfm The PFM to validate the read-only flash against.
	 * @param good_pfm A PFM known to validate against the read-only flash that can be used to
	 * optimize verification with the target PFM.  Set this to null to bypass verification
	 * optimizations.
	 * @param hash The hash engine to use for validation.
	 * @param rsa The RSA engine to use for signature verification.
	 * @param full_validation Flag indicating if a full flash validation should be run.  If this
	 * flag is set, optimizations using good_pfm are always skipped.
	 * @param writable Output that will contain the list of read/write regions for the PFM entry
	 * that validated the flash.  This will be uninitialized if the validation failed.  On
	 * successful return, this structure must be freed through the PFM instance by the caller.
	 *
	 * @return 0 if the read-only flash was successfully validated or an error code.  Blank check
	 * failures will be reported with FLASH_UTIL_UNEXPECTED_VALUE.
	 */
	int (*validate_read_only_flash) (struct host_flash_manager *manager, struct pfm *pfm,
		struct pfm *good_pfm, struct hash_engine *hash, struct rsa_engine *rsa,
		bool full_validation, struct pfm_read_write_regions *writable);

	/**
	 * Validate the read/write flash device.
	 *
	 * @param manager The flash manager to use for validation.
	 * @param pfm The PFM to validate the read/write flash against.
	 * @param hash The hash engine to use for validation.
	 * @param rsa The RSA engine to use for signature verification.
	 * @param writable Output that will contain the list of read/write regions for the PFM entry
	 * that validated the flash.  This will be uninitialized if the validation failed.  On
	 * successful return, this structure must be freed through the PFM instance by the caller.
	 *
	 * @return 0 if the read/write flash was successfully validated or an error code.  Blank check
	 * failures will be reported with FLASH_UTIL_UNEXPECTED_VALUE.
	 */
	int (*validate_read_write_flash) (struct host_flash_manager *manager, struct pfm *pfm,
		struct hash_engine *hash, struct rsa_engine *rsa, struct pfm_read_write_regions *writable);

	/**
	 * Get the read/write regions defined in a PFM for the firmware on flash.  No validation of the
	 * flash will be performed other than what is necessary to determine the appropriate read/write
	 * regions.
	 *
	 * @param manager The flash manager to query.
	 * @param pfm The PFM that contains the read/write region definitions.
	 * @param rw_flash Flag indicating that the read/write flash should be checked.  The read-only
	 * flash will be checked if this flag is not set.
	 * @param writable Output that will contain the list of read/write regions for the PFM entry
	 * that matches the contents of flash.  This will be uninitialized on error.  On successful
	 * return, this structure must be freed through the PFM instance by the caller.
	 *
	 * @return 0 if the read/write regions were successfully retrieved or an error code.
	 */
	int (*get_flash_read_write_regions) (struct host_flash_manager *manager, struct pfm *pfm,
		bool rw_flash, struct pfm_read_write_regions *writable);

	/**
	 * Configure the SPI filter for the ID of the devices that are being protected.
	 *
	 * @param manager The flash manager to use for configuration.
	 *
	 * @return 0 if the SPI filter was successfully configured or an error code.
	 */
	int (*config_spi_filter_flash_type) (struct host_flash_manager *manager);

	/**
	 * Configure the SPI filter to use the appropriate read-only and read/write flash devices.
	 *
	 * @param manager The flash manager to use for configuration.
	 *
	 * @return 0 if the SPI filter was successfully configured or an error code.
	 */
	int (*config_spi_filter_flash_devices) (struct host_flash_manager *manager);

	/**
	 * Switch the read-only and read/write flashes.  This will update the read-only flash host
	 * setting and configure the SPI filter with the new configuration.
	 *
	 * The host inactive dirty state is cleared as part of the operation.
	 *
	 * @param manager The flash manager to update.
	 * @param writable The list of read/write regions that exist on the new read-only flash.  If
	 * this is null, no data migration will be performed as part of the swap.
	 * @param used_pending If a pending PFM was used to authenticate the device being made
	 * read-only, activate the PFM as part of the device swap.  Make this null if no pending PFM
	 * should be activated.
	 *
	 * @return 0 if the flashes were switched or an error code.
	 */
	int (*swap_flash_devices) (struct host_flash_manager *manager,
		struct pfm_read_write_regions *writable, struct pfm_manager *used_pending);

	/**
	 * Configure the system for first-time flash protection.  This should only be called once for
	 * any set of protected flashes, when filtering is being enabled for the first time.  The flash
	 * will be initialized to work with the filter and the SPI filter will be enabled.
	 *
	 * The host inactive dirty state is cleared as part of the operation.
	 *
	 * @param manager The manager for the flash to initialize.
	 * @param writable The list of read/write regions in the protected image.
	 *
	 * @return 0 if the flash was successfully initialized or an error code.
	 */
	int (*initialize_flash_protection) (struct host_flash_manager *manager,
		struct pfm_read_write_regions *writable);

	/**
	 * Configure the system for to allow RoT access to the protected flash devices.  This must be
	 * called prior to calling other flash management functions.
	 *
	 * @param manager The manager for the flash devices to access from the RoT.
	 * @param control The interface for hardware controls for flash access.
	 *
	 * @return 0 if the flash was successfully configured for RoT access or an error code.
	 */
	int (*set_flash_for_rot_access) (struct host_flash_manager *manager,
		struct host_control *control);

	/**
	 * Configure the system for to allow host processor access to the protected flash devices.
	 *
	 * @param manager The manager for the flash devices to access from the host processor.
	 * @param control The interface for hardware controls for flash access.
	 *
	 * @return 0 if the flash was successfully configured for host access or an error code.
	 */
	int (*set_flash_for_host_access) (struct host_flash_manager *manager,
		struct host_control *control);

	/**
	 * Check if the host has access to the protected flash devices.
	 *
	 * @param manager The manager for the flash devices to query.
	 * @param control The interface for hardware controls for flash access.
	 *
	 * @return 0 if the host doesn't if access, 1 if it does, or an error code.
	 */
	int (*host_has_flash_access) (struct host_flash_manager *manager,
		struct host_control *control);

	struct spi_flash *flash_cs0;					/**< The flash device connected to CS0. */
	struct spi_flash *flash_cs1;					/**< The flash device connected to CS1. */
	struct state_manager *host_state;				/**< State information for the host using the flash. */
	struct spi_filter_interface *filter;			/**< The SPI filter connected to the flash devices. */
	struct flash_mfg_filter_handler *mfg_handler;	/**< The filter handler for flash device types. */
	struct host_flash_initialization *flash_init;	/**< Host flash initialization manager. */
};


int host_flash_manager_init (struct host_flash_manager *manager, struct spi_flash *cs0,
	struct spi_flash *cs1, struct state_manager *host_state, struct spi_filter_interface *filter,
	struct flash_mfg_filter_handler *mfg_handler);
int host_flash_manager_init_with_managed_flash_initialization (struct host_flash_manager *manager,
	struct spi_flash *cs0, struct spi_flash *cs1, struct state_manager *host_state,
	struct spi_filter_interface *filter, struct flash_mfg_filter_handler *mfg_handler,
	struct host_flash_initialization *flash_init);
void host_flash_manager_release (struct host_flash_manager *manager);

/* Internal functions for use by derived types. */
int host_flash_manager_validate_flash (struct pfm *pfm, struct hash_engine *hash,
	struct rsa_engine *rsa, bool full_validation, struct spi_flash *flash,
	struct pfm_read_write_regions *writable);
int host_flash_manager_validate_offset_flash (struct pfm *pfm, struct hash_engine *hash,
	struct rsa_engine *rsa, bool full_validation, struct spi_flash *flash, uint32_t offset,
	struct pfm_read_write_regions *writable);
int host_flash_manager_validate_pfm (struct pfm *pfm, struct pfm *good_pfm,
	struct hash_engine *hash, struct rsa_engine *rsa, struct spi_flash *flash,
	struct pfm_read_write_regions *writable);

int host_flash_manager_configure_flash_for_rot_access (struct spi_flash *flash);


#define	HOST_FLASH_MGR_ERROR(code)		ROT_ERROR (ROT_MODULE_HOST_FLASH_MGR, code)

/**
 * Error codes that can be generated by a manager of host flash.
 */
enum {
	HOST_FLASH_MGR_INVALID_ARGUMENT = HOST_FLASH_MGR_ERROR (0x00),		/**< Input parameter is null or not valid. */
	HOST_FLASH_MGR_NO_MEMORY = HOST_FLASH_MGR_ERROR (0x01),				/**< Memory allocation failed. */
	HOST_FLASH_MGR_GET_RO_FAILED = HOST_FLASH_MGR_ERROR (0x02),			/**< Could not determine read-only flash. */
	HOST_FLASH_MGR_GET_RW_FAILED = HOST_FLASH_MGR_ERROR (0x03),			/**< Could not determine read-write flash. */
	HOST_FLASH_MGR_VALIDATE_RO_FAILED = HOST_FLASH_MGR_ERROR (0x04),	/**< An error unrelated to validation caused verification to fail. */
	HOST_FLASH_MGR_VALIDATE_RW_FAILED = HOST_FLASH_MGR_ERROR (0x05),	/**< An error unrelated to validation caused verification to fail. */
	HOST_FLASH_MGR_CONFIG_TYPE_FAILED = HOST_FLASH_MGR_ERROR (0x06),	/**< The flash type could not be configured. */
	HOST_FLASH_MGR_CONFIG_FILTER_FAILED = HOST_FLASH_MGR_ERROR (0x07),	/**< The device state could not be configured. */
	HOST_FLASH_MGR_SWAP_FAILED = HOST_FLASH_MGR_ERROR (0x08),			/**< The flash device roles were not swapped. */
	HOST_FLASH_MGR_INIT_PROTECT_FAILED = HOST_FLASH_MGR_ERROR (0x09),	/**< Flash protection was not initialized. */
	HOST_FLASH_MGR_ROT_ACCESS_FAILED = HOST_FLASH_MGR_ERROR (0x0a),		/**< Flash is not accessible by the RoT. */
	HOST_FLASH_MGR_HOST_ACCESS_FAILED = HOST_FLASH_MGR_ERROR (0x0b),	/**< Flash is not accessible by the host. */
	HOST_FLASH_MGR_MISMATCH_VENDOR = HOST_FLASH_MGR_ERROR (0x0c),		/**< The host flash devices are not from the same vendor. */
	HOST_FLASH_MGR_MISMATCH_DEVICE = HOST_FLASH_MGR_ERROR (0x0d),		/**< The host flash devices are not the same device type. */
	HOST_FLASH_MGR_INVALID_VENDOR = HOST_FLASH_MGR_ERROR (0x0e),		/**< The flash device reports an invalid vendor ID. */
	HOST_FLASH_MGR_RW_REGIONS_FAILED = HOST_FLASH_MGR_ERROR (0x0f),		/**< Could not determine read-write flash regions. */
	HOST_FLASH_MGR_CHECK_ACCESS_FAILED = HOST_FLASH_MGR_ERROR (0x10),	/**< Could not determine if the host has flash access. */
	HOST_FLASH_MGR_MISMATCH_SIZES = HOST_FLASH_MGR_ERROR (0x11),		/**< The host flash devices are not the same size. */
};


#endif /* HOST_FLASH_MANAGER_H_ */
