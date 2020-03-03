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
	spi_filter_flash_state dirty;
	spi_filter_bypass_mode bypass;
	uint32_t region_start[3];
	uint32_t region_end[3];
	uint32_t device_size;
	int i;

	if (filter) {
		port = filter->get_port (filter);

		/* TODO: Error checking on these calls would probably be good.  Otherwise, the log output
		 * will probably not make sense on an error, due to uninitialized variables. */

		filter->get_mfg_id (filter, &mfg);
		filter->get_flash_size (filter, &device_size);
		filter->get_filter_enabled (filter, &enabled);
		filter->get_ro_cs (filter, &ro);
		filter->get_addr_byte_mode (filter, &addr);
		filter->get_flash_dirty_state (filter, &dirty);
		filter->get_bypass_mode (filter, &bypass);

		for (i = 0; i < 3; i++) {
			filter->get_filter_rw_region (filter, i + 1, &region_start[i], &region_end[i]);
		}

		spi_filter_log_filter_config (port, mfg, enabled, ro, addr, dirty, bypass, region_start,
			region_end, 3, device_size);
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
 * @param dirty Indicating if RO flash has been written.
 * @param bypass Bypass state of the filter.
 * @param region_start List of starting addresses for R/W regions.
 * @param region_end List of ending addresses for R/W regions.
 * @param regions Number of R/W regions in the lists.
 * @param device_size The size of the flash device connected to the filter.
 */
void spi_filter_log_filter_config (int port, uint8_t mfg, bool enabled, spi_filter_cs ro,
	spi_filter_address_mode mode, spi_filter_flash_state dirty, spi_filter_bypass_mode bypass,
	uint32_t *region_start, uint32_t *region_end, int regions, uint32_t device_size)
{
	bool full_rw = false;
	int i;

	for (i = 0; i < regions; i++) {
		if ((region_start[i] == 0) && (region_end[i] == 0xffff0000)) {
			full_rw = true;
		}
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_SPI_FILTER,
		SPI_FILTER_LOGGING_FILTER_CONFIG, port, (mfg | (enabled << 8) | (ro << 9) |
			(mode << 10) | (dirty << 11) | (bypass << 12) | (full_rw << 14)));

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_SPI_FILTER,
		SPI_FILTER_LOGGING_DEVICE_SIZE, port, device_size);

	for (i = 0; i < regions; i++) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_SPI_FILTER,
			SPI_FILTER_LOGGING_FILTER_REGION, ((port << 24) | (region_start[i] >> 8)),
			(((i + 1) << 24) | (region_end[i] >> 8)));
	}
}
