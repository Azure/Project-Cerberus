// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FILTER_INTERFACE_H_
#define SPI_FILTER_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"


/**
 * SPI filter chip selects
 */
typedef enum {
	SPI_FILTER_CS_0 = 0,				/**< SPI filter CS 0 */
	SPI_FILTER_CS_1,					/**< SPI filter CS 1 */
} spi_filter_cs;

/**
 * SPI filter address modes
 */
typedef enum {
	SPI_FILTER_ADDRESS_MODE_3 = 0,		/**< 3 byte address mode */
	SPI_FILTER_ADDRESS_MODE_4,			/**< 4 byte address mode */
} spi_filter_address_mode;

/**
 * SPI filter flash states
 */
typedef enum {
	SPI_FILTER_FLASH_STATE_NORMAL = 0,	/**< No writes directed to inactive flash */
	SPI_FILTER_FLASH_STATE_DIRTY,		/**< Writes to inactive flash detected */
} spi_filter_flash_state;

/**
 * Modes of operation for the SPI filter
 */
typedef enum {
	SPI_FILTER_FLASH_DUAL = 0,			/**< Normal operation in dual flash mode */
	SPI_FILTER_FLASH_BYPASS_CS0,		/**< Disable SPI filtering, direct commands to CS0 */
	SPI_FILTER_FLASH_BYPASS_CS1,		/**< Disable SPI filtering, direct commands to CS1 */
	SPI_FILTER_FLASH_SINGLE_CS0,		/**< Single flash operation to CS0 */
	SPI_FILTER_FLASH_SINGLE_CS1,		/**< Single flash operation to CS1 */
} spi_filter_flash_mode;

/**
 * Flash manufacturer IDs for the SPI filter.
 */
enum {
	SPI_FILTER_MFG_MACRONIX = 0,		/**< Macronix flash. */
	SPI_FILTER_MFG_WINBOND = 1,			/**< Winbond flash. */
	SPI_FILTER_MFG_MICRON = 2,			/**< Micron flash. */
};

/**
 * Value indicating that the SPI filter is supported the maximum sized flash device.
 */
#define	SPI_FILTER_MAX_FLASH_SIZE			0


/**
 * Defines the interface to a SPI filter
 */
struct spi_filter_interface {
	/**
	 * Get the port identifier of the SPI filter.
	 *
	 * @param filter The SPI filter to query.
	 *
	 * @return The port identifier or an error code.  Use ROT_IS_ERROR to check the return value.
	 */
	int (*get_port) (struct spi_filter_interface *filter);

	/**
	 * Get SPI filter manufacturer ID
	 *
	 * @param filter The SPI filter instance to use
	 * @param mfg_id ID buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_mfg_id) (struct spi_filter_interface *filter, uint8_t *mfg_id);

	/**
	 * Set SPI filter manufacturer ID
	 *
	 * @param filter The SPI filter instance to use
	 * @param mfg_id ID to set
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_mfg_id) (struct spi_filter_interface *filter, uint8_t mfg_id);

	/**
	 * Get the configured size of the flash device.
	 *
	 * @param filter The SPI filter to query.
	 * @param bytes Output for the size of the flash.  If the filter is configured for the maximum
	 * size, this value will be SPI_FILTER_MAX_FLASH_SIZE.
	 *
	 * @return 0 if the size was successfully queried or an error code.
	 */
	int (*get_flash_size) (struct spi_filter_interface *filter, uint32_t *bytes);

	/**
	 * Set the size of the flash device.
	 *
	 * @param filter The SPI filter to update.
	 * @param bytes The number of bytes available in the flash device.  Set this to
	 * SPI_FILTER_MAX_FLASH_SIZE to support the maximum sized device.
	 *
	 * @return 0 if the size was configured successfully or an error code.
	 */
	int (*set_flash_size) (struct spi_filter_interface *filter, uint32_t bytes);

	/**
	 * Get the flash management mode of the SPI filter.
	 *
	 * @param filter The SPI filter instance to use
	 * @param mode Output for the flash management mode.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_filter_mode) (struct spi_filter_interface *filter, spi_filter_flash_mode *mode);

	/**
	 * Set the flash management mode for the SPI  filter.
	 *
	 * @param filter The SPI filter instance to use
	 * @param mode The flash management mode
	 */
	int (*set_filter_mode) (struct spi_filter_interface *filter, spi_filter_flash_mode mode);

	/**
	 * Get the state of the SPI filter.
	 *
	 * @param filter The SPI filter to query.
	 * @param enabled Output indicating if the SPI filter is enabled or disabled.
	 *
	 * @return 0 if the status was successfully queried or an error code.
	 */
	int (*get_filter_enabled) (struct spi_filter_interface *filter, bool *enabled);

	/**
	 * Enable or disable the SPI filter.  A disabled SPI filter will block all access from the host
	 * to flash.
	 *
	 * @param filter The SPI filter to update.
	 * @param enable Flag indicating if the SPI filter should be enabled or disabled.
	 *
	 * @return 0 if the SPI filter was configured successfully or an error code.
	 */
	int (*enable_filter) (struct spi_filter_interface *filter, bool enable);

	/**
	 * Get SPI filter read-only select for dual flash operation.
	 *
	 * @param filter The SPI filter to query.
	 * @param act_sel Output for the current active RO CS.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_ro_cs) (struct spi_filter_interface *filter, spi_filter_cs *act_sel);

	/**
	 * Set SPI filter read-only select for dual flash operation.
	 *
	 * @param filter The SPI filter to update.
	 * @param act_sel The RO CS to set.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_ro_cs) (struct spi_filter_interface *filter, spi_filter_cs act_sel);

	/**
	 * Get the current SPI filter byte address mode.
	 *
	 * @param filter The SPI filter to query.
	 * @param mode Output for the current SPI filter address mode.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_addr_byte_mode) (struct spi_filter_interface *filter, spi_filter_address_mode *mode);

	/**
	 * Indicate if the SPI filter is configured to prevent address mode switching.
	 *
	 * @param filter The SPI filter to query.
	 * @param fixed Output boolean indicating if the address byte mode is fixed.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_fixed_addr_byte_mode) (struct spi_filter_interface *filter, bool *fixed);

	/**
	 * Set the current SPI filter byte address mode.  The flash can switch between 3-byte and 4-byte
	 * address modes and the filter will track the current address mode.
	 *
	 * @param filter The SPI filter to update.
	 * @param mode Address mode to set.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_addr_byte_mode) (struct spi_filter_interface *filter, spi_filter_address_mode mode);

	/**
	 * Set the current SPI filter byte address mode.  The flash cannot switch between 3-byte and
	 * 4-byte address modes and the filter byte adddress mode will be fixed.
	 *
	 * @param filter The SPI filter to update.
	 * @param mode Address mode to set.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_fixed_addr_byte_mode) (struct spi_filter_interface *filter,
		spi_filter_address_mode mode);

	/**
	 * Get the SPI filter mode that indicates if the write enable command is required to switch
	 * address modes
	 *
	 * @param filter The SPI filter to query.
	 * @param required Output boolean indicating if the write enable command is required to switch
	 * address modes.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_addr_byte_mode_write_enable_required) (struct spi_filter_interface *filter,
		bool *required);

	/**
	 * Set the SPI filter mode that indicates if the write enable command is required to switch
	 * address modes
	 *
	 * @param filter The SPI filter to update.
	 * @param require A boolean indicating whether or not the write enable command is required to
	 * switch address modes.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*require_addr_byte_mode_write_enable) (struct spi_filter_interface *filter, bool require);

	/**
	 * Get the SPI filter mode that indicates the address byte mode after device reset
	 *
	 * @param filter The SPI filter to query.
	 * @param mode Output for the address mode on reset.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_reset_addr_byte_mode) (struct spi_filter_interface *filter,
		spi_filter_address_mode *mode);

	/**
	 * Set the SPI filter mode that indicates the address mode after reset
	 *
	 * @param filter The SPI filter to update.
	 * @param mode The reset address mode to set.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_reset_addr_byte_mode) (struct spi_filter_interface *filter,
		spi_filter_address_mode mode);

	/**
	 * Indicate if writes are allowed to all regions of flash in single flash mode.  If they are not
	 * allowed, writes outside the read/write regions will be blocked.
	 *
	 * @param filter The SPI filter to query.
	 * @param allowed Output for the single flash write permissions.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*are_all_single_flash_writes_allowed) (struct spi_filter_interface *filter, bool *allowed);

	/**
	 * Configure the SPI filter to allow or block writes outside of the defined read/write regions
	 * while operating in single flash mode.
	 *
	 * @param filter The SPI filter to update.
	 * @param allowed Flag indicating if writes to read-only regions of flash should be allowed.
	 */
	int (*allow_all_single_flash_writes) (struct spi_filter_interface *filter, bool allowed);

	/**
	 * Get the SPI filter write enable command status.
	 *
	 * @param filter The SPI filter to query.
	 * @param detected Output indicating if the write enable command was detected.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_write_enable_detected) (struct spi_filter_interface *filter, bool *detected);

	/**
	 * Determine if protected flash has been updated.
	 *
	 * @param filter The SPI filter to query.
	 * @param state Output indicating the state of protected flash.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_flash_dirty_state) (struct spi_filter_interface *filter,
		spi_filter_flash_state *state);

	/**
	 * Clear the SPI filter flag indicating protected flash has been updated.
	 *
	 * @param filter The SPI filter to update.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*clear_flash_dirty_state) (struct spi_filter_interface *filter);

	/**
	 * Get a SPI filter read/write region.
	 *
	 * @param filter The SPI filter to query.
	 * @param region The filter region to select.  This is a region index, starting with 1.
	 * @param start_addr The first address in the filtered region.
	 * @param end_addr One past the last address in the filtered region.
	 *
	 * @return Completion status, 0 if success or an error code.  If the region specified is not
	 * supported by the filter, SPI_FILTER_UNSUPPORTED_RW_REGION will be returned.
	 */
	int (*get_filter_rw_region) (struct spi_filter_interface *filter, uint8_t region,
		uint32_t *start_addr, uint32_t *end_addr);

	/**
	 * Set a SPI filter read/write region.
	 *
	 * @param filter The SPI filter to update.
	 * @param region The filter region to modify.  This is a region index, starting with 1.
	 * @param start_addr The first address in the filtered region.
	 * @param end_addr One past the last address in the filtered region.
	 *
	 * @return Completion status, 0 if success or an error code.  If the region specified is not
	 * supported by the filter, SPI_FILTER_UNSUPPORTED_RW_REGION will be returned.
	 */
	int (*set_filter_rw_region) (struct spi_filter_interface *filter, uint8_t region,
		uint32_t start_addr, uint32_t end_addr);

	/**
	 * Clear all read/write regions configured in the SPI filter.
	 *
	 * @param filter The SPI filter to update.
	 *
	 * @return 0 if the regions were cleared successfully or an error code.
	 */
	int (*clear_filter_rw_regions) (struct spi_filter_interface *filter);
};


void spi_filter_log_configuration (struct spi_filter_interface *filter);
void spi_filter_log_filter_config (int port, uint8_t mfg, bool enabled, spi_filter_cs ro,
	spi_filter_address_mode mode, bool mode_fixed, spi_filter_address_mode mode_reset,
	bool mode_write_en, spi_filter_flash_state dirty, spi_filter_flash_mode flash_cfg,
	bool write_allow, uint32_t *region_start, uint32_t *region_end, int regions,
	uint32_t device_size);


#define	SPI_FILTER_ERROR(code)		ROT_ERROR (ROT_MODULE_SPI_FILTER, code)

/**
 * Error codes that can be generated by a SPI filter driver.
 *
 * Note: Commented error codes have been deprecated.
 */
enum {
	SPI_FILTER_INVALID_ARGUMENT = SPI_FILTER_ERROR (0x00),			/**< Input parameter is null or not valid. */
	SPI_FILTER_NO_MEMORY = SPI_FILTER_ERROR (0x01),					/**< Memory allocation failed. */
	SPI_FILTER_GET_MFG_FAILED = SPI_FILTER_ERROR (0x02),			/**< Failed to get the configured manufacturer ID. */
	SPI_FILTER_SET_MFG_FAILED = SPI_FILTER_ERROR (0x03),			/**< Failed to configure manufacturer ID. */
	SPI_FILTER_GET_ENABLED_FAILED = SPI_FILTER_ERROR (0x04),		/**< Could not determine if the filter is enabled. */
	SPI_FILTER_ENABLE_FAILED = SPI_FILTER_ERROR (0x05),				/**< The filter was not enabled. */
	SPI_FILTER_GET_RO_FAILED = SPI_FILTER_ERROR (0x06),				/**< Could not determine the configured RO chip select. */
	SPI_FILTER_SET_RO_FAILED = SPI_FILTER_ERROR (0x07),				/**< The RO chip select was not set. */
//	SPI_FILTER_GET_RO_READ_FAILED = SPI_FILTER_ERROR (0x08),		/**< Could not determine the configured RO read region. */
//	SPI_FILTER_SET_RO_READ_FAILED = SPI_FILTER_ERROR (0x09),		/**< The RO read region was not set. */
//	SPI_FILTER_GET_READ_SWITCH_FAILED = SPI_FILTER_ERROR (0x0a),	/**< Could not determine if switching the RO read region is allowed. */
//	SPI_FILTER_ENABLE_SWITCH_FAILED = SPI_FILTER_ERROR (0x0b),		/**< RO read switch was not enabled/disabled. */
	SPI_FILTER_GET_ADDR_MODE_FAILED = SPI_FILTER_ERROR (0x0c),		/**< Could not determine the filter address mode. */
	SPI_FILTER_SET_ADDR_MODE_FAILED = SPI_FILTER_ERROR (0x0d),		/**< The filter address mode was not set. */
	SPI_FILTER_GET_DIRTY_FAILED = SPI_FILTER_ERROR (0x0e),			/**< Could not determine the filter dirty state. */
	SPI_FILTER_CLEAR_DIRTY_FAILED = SPI_FILTER_ERROR (0x0f),		/**< The dirty bit was not cleared. */
//	SPI_FILTER_GET_BYPASS_FAILED = SPI_FILTER_ERROR (0x10),			/**< Could not determine the filter bypass mode. */
//	SPI_FILTER_SET_BYPASS_FAILED = SPI_FILTER_ERROR (0x11),			/**< The bypass mode was not set. */
	SPI_FILTER_GET_RW_FAILED = SPI_FILTER_ERROR (0x12),				/**< Could not get the configured RW filter. */
	SPI_FILTER_SET_RW_FAILED = SPI_FILTER_ERROR (0x13),				/**< The RW filter was not set. */
	SPI_FILTER_CLEAR_RW_FAILED = SPI_FILTER_ERROR (0x14),			/**< The RW filters were not cleared. */
	SPI_FILTER_UNSUPPORTED_RW_REGION = SPI_FILTER_ERROR (0x15),		/**< The specified R/W region is not supported by the filter. */
	SPI_FILTER_MISALIGNED_ADDRESS = SPI_FILTER_ERROR (0x16),		/**< A filter address was not aligned properly. */
	SPI_FILTER_UNSUPPORTED_PORT = SPI_FILTER_ERROR (0x17),			/**< The port identifier is not supported by the filter. */
	SPI_FILTER_UNKNOWN_VERSION = SPI_FILTER_ERROR (0x18),			/**< The filter version could not be determined. */
	SPI_FILTER_GET_SIZE_FAILED = SPI_FILTER_ERROR (0x19),			/**< Failed to get the configured filter device size. */
	SPI_FILTER_SET_SIZE_FAILED = SPI_FILTER_ERROR (0x1a),			/**< The filer device size was not configured. */
	SPI_FILTER_UNSUPPORTED_OPERATION = SPI_FILTER_ERROR (0x1b),		/**< The requested operation is not supported by the filter. */
	SPI_FILTER_GET_WREN_REQ_FAILED = SPI_FILTER_ERROR (0x1c),		/**< Failed to get the required write enable configuration. */
	SPI_FILTER_SET_WREN_REQ_FAILED = SPI_FILTER_ERROR (0x1d),		/**< The write enable requirement was not configured. */
	SPI_FILTER_GET_FIXED_ADDR_FAILED = SPI_FILTER_ERROR (0x1e),		/**< Failed to get the fixed address mode configuration. */
	SPI_FILTER_SET_FIXED_ADDR_FAILED = SPI_FILTER_ERROR (0x1f),		/**< The fixed address mode setting was not configured. */
	SPI_FILTER_GET_RESET_ADDR_FAILED = SPI_FILTER_ERROR (0x20),		/**< Failed to get the configured address mode on reset. */
	SPI_FILTER_SET_RESET_ADDR_FAILED = SPI_FILTER_ERROR (0x21),		/**< The address mode on reset was not configured. */
	SPI_FILTER_GET_WREN_DETECT_FAILED = SPI_FILTER_ERROR (0x22),	/**< Could not determine the detected write enable state. */
	SPI_FILTER_GET_FILTER_MODE_FAILED = SPI_FILTER_ERROR (0x23),	/**< Could not determine the filter operational mode. */
	SPI_FILTER_SET_FILTER_MODE_FAILED = SPI_FILTER_ERROR (0x24),	/**< Failed to set the filter operational mode. */
	SPI_FILTER_GET_ALLOW_WRITE_FAILED = SPI_FILTER_ERROR (0x25),	/**< Could not got the write permissions for single chip. */
	SPI_FILTER_SET_ALLOW_WRITE_FAILED = SPI_FILTER_ERROR (0x26),	/**< Failed to set single chip write permissions. */
};


#endif /* SPI_FILTER_INTERFACE_H_ */
