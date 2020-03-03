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
	SPI_FILTER_CS_0 = 0,				/**< SPI filter CS 0*/
	SPI_FILTER_CS_1,					/**< SPI filter CS 1*/
	NUM_SPI_FILTER_CS					/**< Number of SPI filter CS controlled*/
} spi_filter_cs;

/**
 * SPI filter device selects
 */
typedef enum {
	SPI_FILTER_DEVICE_ACTIVE = 0,		/**< SPI filter active flash*/
	SPI_FILTER_DEVICE_INACTIVE,			/**< SPI filter inactive flash*/
	NUM_SPI_FILTER_DEVICE				/**< Number of SPI filter flash devices*/
} spi_filter_device;

/**
 * SPI filter address modes
 */
typedef enum {
	SPI_FILTER_ADDRESS_MODE_3 = 0,		/**< 3 byte address mode*/
	SPI_FILTER_ADDRESS_MODE_4,			/**< 4 byte address mode*/
	NUM_SPI_FILTER_ADDRESS_MODE			/**< Number of SPI flash address modes*/
} spi_filter_address_mode;

/**
 * SPI filter flash states
 */
typedef enum {
	SPI_FILTER_FLASH_STATE_NORMAL = 0,	/**< No writes directed to inactive flash*/
	SPI_FILTER_FLASH_STATE_DIRTY,		/**< Writes to inactive flash detected*/
	NUM_SPI_FILTER_FLASH_STATE			/**< Number of inactive flash states*/
} spi_filter_flash_state;

/**
 * SPI filter bypass modes
 */
typedef enum {
	SPI_FILTER_OPERATE = 0,				/**< Normal SPI filtering operation*/
	SPI_FILTER_BYPASS_CS0,				/**< Disable SPI filtering, direct commands to CS0*/
	SPI_FILTER_BYPASS_CS1,				/**< Disable SPI filtering, direct commands to CS1*/
	NUM_SPI_FILTER_BYPASS				/**< Number of SPI filter bypass modes*/
} spi_filter_bypass_mode;

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
	 * Get SPI filter read-only select
	 *
	 * @param filter The SPI filter instance to use
	 * @param act_sel Active RO CS buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_ro_cs) (struct spi_filter_interface *filter, spi_filter_cs *act_sel);

	/**
	 * Set SPI filter read-only select
	 *
	 * @param filter The SPI filter instance to use
	 * @param act_sel Active RO CS to write
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_ro_cs) (struct spi_filter_interface *filter, spi_filter_cs act_sel);

#ifdef SPI_FILTER_SUPPORT_RO_READ_SWITCH
	/**
	 * Get SPI filter RO read region
	 *
	 * @param filter The SPI filter instance to use
	 * @param act_device Active device buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_ro_read_region) (struct spi_filter_interface *filter, spi_filter_device *act_device);

	/**
	 * Set SPI filter RO read region
	 *
	 * @param filter The SPI filter instance to use
	 * @param act_device Active device to direct writes to
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_ro_read_region) (struct spi_filter_interface *filter, spi_filter_device act_device);

	/**
	 * Return whether the SPI filter RO read region switch is enabled
	 *
	 * @param filter The SPI filter instance to use
	 * @param enabled Enabled buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_ro_read_region_switch_enabled) (struct spi_filter_interface *filter, bool *enabled);

	/**
	 * Control the SPI filter RO read region switch
	 *
	 * @param filter The SPI filter instance to use
	 * @param enable A boolean indicating whether to enable/disable the the RO read region switch
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*enable_ro_read_region_switch) (struct spi_filter_interface *filter, bool enable);
#endif

	/**
	 * Get SPI filter byte address mode
	 *
	 * @param filter The SPI filter instance to use
	 * @param mode Address mode buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_addr_byte_mode) (struct spi_filter_interface *filter, spi_filter_address_mode *mode);

	/**
	 * Set SPI filter byte address mode
	 *
	 * @param filter The SPI filter instance to use
	 * @param mode Address mode to set
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_addr_byte_mode) (struct spi_filter_interface *filter, spi_filter_address_mode mode);

	/**
	 * Get SPI filter active flash state
	 *
	 * @param filter The SPI filter instance to use
	 * @param state Active flash state buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_flash_dirty_state) (struct spi_filter_interface *filter,
		spi_filter_flash_state *state);

	/**
	 * Clear SPI filter active flash state
	 *
	 * @param filter The SPI filter instance to use
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*clear_flash_dirty_state) (struct spi_filter_interface *filter);

	/**
	 * Get SPI filter bypass mode
	 *
	 * @param filter The SPI filter instance to use
	 * @param bypass Bypass mode buffer to fill
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_bypass_mode) (struct spi_filter_interface *filter, spi_filter_bypass_mode *bypass);

	/**
	 * Set SPI filter bypass mode
	 *
	 * @param filter The SPI filter instance to use
	 * @param bypass Bypass mode setting to use
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_bypass_mode) (struct spi_filter_interface *filter, spi_filter_bypass_mode bypass);

	/**
	 * Get SPI filter RW region range
	 *
	 * @param filter The SPI filter instance to use
	 * @param region The filter region to select
	 * @param start_addr The first address in the filtered region.
	 * @param end_addr One past the last address in the filtered region.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*get_filter_rw_region) (struct spi_filter_interface *filter, uint8_t region,
		uint32_t *start_addr, uint32_t *end_addr);

	/**
	 * Set SPI filter RW region range
	 *
	 * @param filter The SPI filter instance to use
	 * @param region The filter region to modify
	 * @param start_addr The first address in the filtered region.
	 * @param end_addr One past the last address in the filtered region.
	 *
	 * @return Completion status, 0 if success or an error code.
	 */
	int (*set_filter_rw_region) (struct spi_filter_interface *filter, uint8_t region,
		uint32_t start_addr, uint32_t end_addr);

	/**
	 * Clear all RW regions configured in the SPI filter.
	 *
	 * @param filter The SPI filter to update.
	 *
	 * @return 0 if the regions were cleared successfully or an error code.
	 */
	int (*clear_filter_rw_regions) (struct spi_filter_interface *filter);
};


void spi_filter_log_configuration (struct spi_filter_interface *filter);
void spi_filter_log_filter_config (int port, uint8_t mfg, bool enabled, spi_filter_cs ro,
	spi_filter_address_mode mode, spi_filter_flash_state dirty, spi_filter_bypass_mode bypass,
	uint32_t *region_start, uint32_t *region_end, int regions, uint32_t device_size);


#define	SPI_FILTER_ERROR(code)		ROT_ERROR (ROT_MODULE_SPI_FILTER, code)

/**
 * Error codes that can be generated by a SPI filter driver.
 */
enum {
	SPI_FILTER_INVALID_ARGUMENT = SPI_FILTER_ERROR (0),			/**< Input parameter is null or not valid. */
	SPI_FILTER_NO_MEMORY = SPI_FILTER_ERROR (1),				/**< Memory allocation failed. */
	SPI_FILTER_GET_MFG_FAILED = SPI_FILTER_ERROR (2),			/**< Failed to get the configured manufacturer ID. */
	SPI_FILTER_SET_MFG_FAILED = SPI_FILTER_ERROR (3),			/**< Failed to configure manufacturer ID. */
	SPI_FILTER_GET_ENABLED_FAILED = SPI_FILTER_ERROR (4),		/**< Could not determine if the filter is enabled. */
	SPI_FILTER_ENABLE_FAILED = SPI_FILTER_ERROR (5),			/**< The filter was not enabled. */
	SPI_FILTER_GET_RO_FAILED = SPI_FILTER_ERROR (6),			/**< Could not determine the configured RO chip select. */
	SPI_FILTER_SET_RO_FAILED = SPI_FILTER_ERROR (7),			/**< The RO chip select was not set. */
	SPI_FILTER_GET_RO_READ_FAILED = SPI_FILTER_ERROR (8),		/**< Could not determine the configured RO read region. */
	SPI_FILTER_SET_RO_READ_FAILED = SPI_FILTER_ERROR (9),		/**< The RO read region was not set. */
	SPI_FILTER_GET_READ_SWITCH_FAILED = SPI_FILTER_ERROR (10),	/**< Could not determine if switching the RO read region is allowed. */
	SPI_FILTER_ENABLE_SWITCH_FAILED = SPI_FILTER_ERROR (11),	/**< RO read switch was not enabled/disabled. */
	SPI_FILTER_GET_ADDR_MODE_FAILED = SPI_FILTER_ERROR (12),	/**< Could not determine the filter address mode. */
	SPI_FILTER_SET_ADDR_MODE_FAILED = SPI_FILTER_ERROR (13),	/**< The filter address mode was not set. */
	SPI_FILTER_GET_DIRTY_FAILED = SPI_FILTER_ERROR (14),		/**< Could not determine the filter dirty state. */
	SPI_FILTER_CLEAR_DIRTY_FAILED = SPI_FILTER_ERROR (15),		/**< The dirty bit was not cleared. */
	SPI_FILTER_GET_BYPASS_FAILED = SPI_FILTER_ERROR (16),		/**< Could not determine the filter bypass mode. */
	SPI_FILTER_SET_BYPASS_FAILED = SPI_FILTER_ERROR (17),		/**< The bypass mode was not set. */
	SPI_FILTER_GET_RW_FAILED = SPI_FILTER_ERROR (18),			/**< Could not get the configured RW filter. */
	SPI_FILTER_SET_RW_FAILED = SPI_FILTER_ERROR (19),			/**< The RW filter was not set. */
	SPI_FILTER_CLEAR_RW_FAILED = SPI_FILTER_ERROR (20),			/**< The RW filters were not cleared. */
	SPI_FILTER_UNSUPPORTED_RW_FILTER = SPI_FILTER_ERROR (21),	/**< The specified RW filter is not supported by the filter. */
	SPI_FILTER_MISALIGNED_ADDRESS = SPI_FILTER_ERROR (22),		/**< A filter address was not aligned properly. */
	SPI_FILTER_UNSUPPORTED_PORT = SPI_FILTER_ERROR (23),		/**< The port identifier is not supported by the filter. */
	SPI_FILTER_UNKNOWN_VERSION = SPI_FILTER_ERROR (24),			/**< The filter version could not be determined. */
	SPI_FILTER_GET_SIZE_FAILED = SPI_FILTER_ERROR (25),			/**< Failed to get the configured filter device size. */
	SPI_FILTER_SET_SIZE_FAILED = SPI_FILTER_ERROR (26),			/**< The filer device size was not configured. */
	SPI_FILTER_UNSUPPORTED_OPERATION = SPI_FILTER_ERROR (27),	/**< The requested operation is not supported by the filter. */
};


#endif /* SPI_FILTER_INTERFACE_H_ */
