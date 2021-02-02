// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "spi_filter_interface.h"
#include "spi_filter_logging.h"


/**
 * Get the SPI filter configuration and log the information.
 *
 * @param filter The SPI filter to query.
 */
void spi_filter_log_configuration (struct spi_filter_interface *filter)
{
	int port;
	uint8_t mfg;
	bool enabled;
	spi_filter_cs ro;
	spi_filter_address_mode addr;
	bool addr_fixed;
	spi_filter_address_mode addr_reset = SPI_FILTER_ADDRESS_MODE_3;
	bool write_en = false;
	spi_filter_flash_state dirty;
	spi_filter_flash_mode mode;
	bool write_allow = false;
	uint32_t region_start[6] = {0};
	uint32_t region_end[6] = {0};
	uint32_t device_size = 0;
	int i;

	if (filter) {
		port = filter->get_port (filter);

		/* TODO: Error checking on these calls would probably be good.  Otherwise, the log output
		 * will probably not make sense on an error, due to uninitialized variables. */

		filter->get_mfg_id (filter, &mfg);
		filter->get_flash_size (filter, &device_size);
		filter->get_filter_mode (filter, &mode);
		filter->get_filter_enabled (filter, &enabled);
		filter->get_ro_cs (filter, &ro);
		filter->get_addr_byte_mode (filter, &addr);
		filter->get_fixed_addr_byte_mode (filter, &addr_fixed);
		filter->get_reset_addr_byte_mode (filter, &addr_reset);
		filter->get_addr_byte_mode_write_enable_required (filter, &write_en);
		filter->get_flash_dirty_state (filter, &dirty);
		filter->are_all_single_flash_writes_allowed (filter, &write_allow);

		for (i = 0; i < 6; i++) {
			filter->get_filter_rw_region (filter, i + 1, &region_start[i], &region_end[i]);
		}

		spi_filter_log_filter_config (port, mfg, enabled, ro, addr, addr_fixed, addr_reset,
			write_en, dirty, mode, write_allow, region_start, region_end, 6, device_size);
	}
}

/**
 * Create log entries for the provided filter configuration.
 *
 * @param port Identifier for the filter port.
 * @param mfg Manufacturer ID for the flash device.
 * @param enabled Flag indicating if the filter is enabled.
 * @param ro The flash chip select that is the RO flash.
 * @param mode The address mode of the filter.
 * @param mode_fixed Indicator if the address mode is fixed.
 * @param mode_reset The address mode of the filter on device reset.
 * @param mode_write_en Indicator if address mode switching requires write enable.
 * @param dirty Indicating if RO flash has been written.
 * @param flash_cfg Operational mode of the SPI filter.
 * @param write_allow Configuration for single chip write permissions.
 * @param region_start List of starting addresses for R/W regions.
 * @param region_end List of ending addresses for R/W regions.
 * @param regions Number of R/W regions in the lists.
 * @param device_size The size of the flash device connected to the filter.
 */
void spi_filter_log_filter_config (int port, uint8_t mfg, bool enabled, spi_filter_cs ro,
	spi_filter_address_mode mode, bool mode_fixed, spi_filter_address_mode mode_reset,
	bool mode_write_en, spi_filter_flash_state dirty, spi_filter_flash_mode flash_cfg,
	bool write_allow, uint32_t *region_start, uint32_t *region_end, int regions,
	uint32_t device_size)
{
	bool full_rw = false;
	uint8_t bypass;
	int i;

	for (i = 0; i < regions; i++) {
		if ((region_start[i] == 0) && (region_end[i] == 0xffff0000)) {
			full_rw = true;
		}
	}

	switch (flash_cfg) {
		case SPI_FILTER_FLASH_BYPASS_CS0:
		case SPI_FILTER_FLASH_BYPASS_CS1:
			bypass = flash_cfg;
			break;

		default:
			bypass = 0;
			break;
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_SPI_FILTER,
		SPI_FILTER_LOGGING_FILTER_CONFIG, port, (mfg | (enabled << 8) | (ro << 9) |
			(mode << 10) | (dirty << 11) | (bypass << 12) | (full_rw << 14) | (mode_fixed << 15) |
			(mode_reset << 16) | (mode_write_en << 17) | (flash_cfg << 18) | (write_allow << 21)));

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_SPI_FILTER,
		SPI_FILTER_LOGGING_DEVICE_SIZE, port, device_size);

	for (i = 0; i < regions; i++) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_SPI_FILTER,
			SPI_FILTER_LOGGING_FILTER_REGION, ((port << 24) | (region_start[i] >> 8)),
			(((i + 1) << 24) | (region_end[i] >> 8)));
	}
}
