// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HOST_FLASH_INITIALIZATION_STATIC_H_
#define HOST_FLASH_INITIALIZATION_STATIC_H_

#include "host_flash_initialization.h"


/**
 * Initialize a static instance of the manager for delayed host flash initialization.
 *
 * There is no validation done on the arguments.
 *
 * NOTE: The SPI flash interfaces provided here must also be statically initialized instances, or be
 * dynamically initialized with a call to spi_flash_init_api() prior to run-time initialization of
 * the flash initialization manager instance.  It is important that the SPI flash interfaces
 * provided here NOT be initialized in any other way.  Additional initialization of these instances
 * MUST be done through this module.
 *
 * @param state_ptr Variable context for managing flash initialization.
 * @param flash_cs0_ptr The SPI flash interface for the device on CS0.  This must be statically
 * initialized.
 * @param flash_cs1_ptr The SPI flash interface for the device on CS1.  This must be statically
 * initialized.
 * @param fast_read_arg Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength_arg Flag to indicate if the device drive strength should be configured.
 */
#define	host_flash_initialization_static_init(state_ptr, flash_cs0_ptr, flash_cs1_ptr, \
	fast_read_arg, drive_strength_arg)	{ \
		.state = state_ptr, \
		.flash_cs0 = flash_cs0_ptr, \
		.flash_cs1 = flash_cs1_ptr, \
		.dual_flash = true, \
		.fast_read = fast_read_arg, \
		.drive_strength = drive_strength_arg, \
	}

/**
 * Initialize a static instance of the manager for delayed host flash initialization with a single
 * flash.
 *
 * There is no validation done on the arguments.
 *
 * NOTE: The SPI flash interface provided here must also be a statically initialized instance, or be
 * dynamically initialized with a call to spi_flash_init_api() prior to run-time initialization of
 * the flash initialization manager instance.  It is important that the SPI flash interface
 * provided here NOT be initialized in any other way.  Additional initialization of this instance
 * MUST be done through this module.
 *
 * @param state_ptr Variable context for managing flash initialization.
 * @param flash_ptr The SPI flash interface for the device on CS0.  This must be statically
 * initialized.
 * @param fast_read_arg Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength_arg Flag to indicate if the device drive strength should be configured.
 */
#define	host_flash_initialization_static_init_single_flash(state_ptr, flash_ptr, fast_read_arg, \
	drive_strength_arg)	{ \
		.state = state_ptr, \
		.flash_cs0 = flash_ptr, \
		.flash_cs1 = NULL, \
		.dual_flash = false, \
		.fast_read = fast_read_arg, \
		.drive_strength = drive_strength_arg, \
	}


#endif	/* HOST_FLASH_INITIALIZATION_STATIC_H_ */
