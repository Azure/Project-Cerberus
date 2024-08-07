// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_MFG_FILTER_HANDLER_H_
#define FLASH_MFG_FILTER_HANDLER_H_

#include <stdint.h>
#include "status/rot_status.h"


/**
 * A platform-independent API for handling flash device manufacturer dependencies of the SPI filter.
 */
struct flash_mfg_filter_handler {
	/**
	 * Configure the SPI filter with the necessary settings for a specific flash device.
	 *
	 * @param handler The handler instance that will configure the SPI filter.
	 * @param vendor The JEDEC vendor ID of the SPI flash device.
	 * @param device The device identifier for the SPI flash device.
	 *
	 * @return 0 if the SPI filter was configured successfully or an error code.
	 */
	int (*set_flash_manufacturer) (const struct flash_mfg_filter_handler *handler, uint8_t vendor,
		uint16_t device);
};


#define	MFG_FILTER_HANDLER_ERROR(code)		ROT_ERROR (ROT_MODULE_MFG_FILTER_HANDLER, code)

/**
 * Error codes that can be generated by a handler for setting the flash manufacturer for a SPI
 * filter.
 */
enum {
	MFG_FILTER_HANDLER_INVALID_ARGUMENT = MFG_FILTER_HANDLER_ERROR (0x00),		/**< Input parameter is null or not valid. */
	MFG_FILTER_HANDLER_NO_MEMORY = MFG_FILTER_HANDLER_ERROR (0x01),				/**< Memory allocation failed. */
	MFG_FILTER_HANDLER_SET_MFG_FAILED = MFG_FILTER_HANDLER_ERROR (0x02),		/**< The filter was not configured for the flash device. */
	MFG_FILTER_HANDLER_UNSUPPORTED_VENDOR = MFG_FILTER_HANDLER_ERROR (0x03),	/**< The flash vendor is not supported by the SPI filter. */
	MFG_FILTER_HANDLER_UNSUPPORTED_DEVICE = MFG_FILTER_HANDLER_ERROR (0x04),	/**< The vendor's flash device is not supported by the SPI filter. */
};


#endif	/* FLASH_MFG_FILTER_HANDLER_H_ */
