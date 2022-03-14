// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_flash_initialization.h"


/**
 * Initialize the manager for delayed host flash initialization.  The host flash interfaces
 * themselves will not be initialized or accessed.
 *
 * @param init The initialization manager to initialize.
 * @param flash_cs0 The SPI flash interface for the device on CS0.
 * @param state_cs0 Variable context for the SPI flash on CS0.
 * @param spi_cs0 The SPI master for the CS0 flash.
 * @param flash_cs1 The SPI flash interface for the device on CS1.  Set to null for single flash.
 * @param state_cs1 Variable context for the SPI flash on CS1.  Set to null for single flash.
 * @param spi_cs1 The SPI master for the CS1 flash.  Set to null for single flash.
 * @param fast_read Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength Flag to indicate if the device drive strength should be configured.
 *
 * @return 0 if the initialization manager was successfully initialized or an error code.
 */
int host_flash_initialization_init_internal (struct host_flash_initialization *init,
	struct spi_flash *flash_cs0, struct spi_flash_state *state_cs0,
	const struct flash_master *spi_cs0, struct spi_flash *flash_cs1,
	struct spi_flash_state *state_cs1, const struct flash_master *spi_cs1, bool fast_read,
	bool drive_strength)
{
	int status;

	memset (init, 0, sizeof (struct host_flash_initialization));

	status = platform_mutex_init (&init->lock);
	if (status != 0) {
		return status;
	}

	init->flash_cs0 = flash_cs0;
	init->state_cs0 = state_cs0;
	init->spi_cs0 = spi_cs0;
	init->flash_cs1 = flash_cs1;
	init->state_cs1 = state_cs1;
	init->spi_cs1 = spi_cs1;
	init->fast_read = fast_read;
	init->drive_strength = drive_strength;

	if (!flash_cs1 || !state_cs1 || !spi_cs1) {
		init->is_init1 = true;
	}

	return 0;
}

/**
 * Initialize the manager for delayed host flash initialization.  The host flash interfaces
 * themselves will not be initialized or accessed.
 *
 * NOTE: It is important that the SPI interfaces provided here NOT be initialized.  Initialization
 * of these instances MUST be done through this module.
 *
 * @param init The initialization manager to initialize.
 * @param flash_cs0 The SPI flash interface for the device on CS0.
 * @param state_cs0 Variable context for the SPI flash on CS0.
 * @param spi_cs0 The SPI master for the CS0 flash.
 * @param flash_cs1 The SPI flash interface for the device on CS1.
 * @param state_cs1 Variable context for the SPI flash on CS1.
 * @param spi_cs1 The SPI master for the CS1 flash.
 * @param fast_read Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength Flag to indicate if the device drive strength should be configured.
 *
 * @return 0 if the initialization manager was successfully initialized or an error code.
 */
int host_flash_initialization_init (struct host_flash_initialization *init,
	struct spi_flash *flash_cs0, struct spi_flash_state *state_cs0,
	const struct flash_master *spi_cs0, struct spi_flash *flash_cs1,
	struct spi_flash_state *state_cs1, const struct flash_master *spi_cs1, bool fast_read,
	bool drive_strength)
{
	if ((init == NULL) || (flash_cs0 == NULL) || (state_cs0 == NULL) || (spi_cs0 == NULL) ||
		(flash_cs1 == NULL) || (state_cs1 == NULL) || (spi_cs1 == NULL)) {
		return HOST_FLASH_INIT_INVALID_ARGUMENT;
	}

	return host_flash_initialization_init_internal (init, flash_cs0, state_cs0, spi_cs0, flash_cs1,
		state_cs1, spi_cs1, fast_read, drive_strength);
}

/**
 * Initialize the manager for delayed host flash initialization with a single flash.  The host flash
 * interface itself will not be initialized or accessed.
 *
 * NOTE: It is important that the SPI interface provided here NOT be initialized.  Initialization
 * of this instance MUST be done through this module.
 *
 * @param init The initialization manager to initialize.
 * @param flash The SPI flash interface for the device on CS0.
 * @param state Variable context for the SPI flash on CS0.
 * @param spi The SPI master for the CS0 flash.
 * @param fast_read Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength Flag to indicate if the device drive strength should be configured.
 *
 * @return 0 if the initialization manager was successfully initialized or an error code.
 */
int host_flash_initialization_init_single_flash (struct host_flash_initialization *init,
	struct spi_flash *flash, struct spi_flash_state *state, const struct flash_master *spi,
	bool fast_read, bool drive_strength)
{
	if ((init == NULL) || (state == NULL) || (flash == NULL) || (spi == NULL)) {
		return HOST_FLASH_INIT_INVALID_ARGUMENT;
	}

	return host_flash_initialization_init_internal (init, flash, state, spi, NULL, NULL, NULL,
		fast_read, drive_strength);
}

/**
 * Release the resources used by the flash initialization manager.
 *
 * @param init The initialization manager to release.
 */
void host_flash_initialization_release (struct host_flash_initialization *init)
{
	if (init) {
		platform_mutex_free (&init->lock);
	}
}

/**
 * Initialize the host SPI flash devices.
 *
 * @param init The initialization manager to execute.
 *
 * @return 0 if flash initialization was successful or an error code.
 */
int host_flash_initialization_initialize_flash (struct host_flash_initialization *init)
{
	int status = 0;

	if (init == NULL) {
		return HOST_FLASH_INIT_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&init->lock);

	if (!init->is_init0) {
		status = spi_flash_initialize_device (init->flash_cs0, init->state_cs0, init->spi_cs0,
			init->fast_read, false, false, init->drive_strength);
		if (status != 0) {
			goto exit;
		}

		init->is_init0 = true;
	}

	if (!init->is_init1) {
		status = spi_flash_initialize_device (init->flash_cs1, init->state_cs1, init->spi_cs1,
			init->fast_read, false, false, init->drive_strength);
		if (status != 0) {
			goto exit;
		}

		init->is_init1 = true;
	}

exit:
	platform_mutex_unlock (&init->lock);
	return status;
}
