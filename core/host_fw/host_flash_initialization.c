// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_flash_initialization.h"


/**
 * Initialize the manager for delayed host flash initialization.  The host flash interfaces
 * themselves will not be initialized or accessed.
 *
 * @param init The initialization manager to initialize.
 * @param state Variable context for managing flash initialization.  This must be uninitialized.
 * @param flash_cs0 The SPI flash interface for the device on CS0.
 * @param state_cs0 Variable context for the SPI flash on CS0.
 * @param spi_cs0 The SPI master for the CS0 flash.
 * @param flash_cs1 The SPI flash interface for the device on CS1.  Set to null for single flash.
 * @param state_cs1 Variable context for the SPI flash on CS1.  Set to null for single flash.
 * @param spi_cs1 The SPI master for the CS1 flash.  Set to null for single flash.
 * @param dual_flash Flag to indicate if there are two flash devices being managed.
 * @param fast_read Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength Flag to indicate if the device drive strength should be configured.
 *
 * @return 0 if the initialization manager was successfully initialized or an error code.
 */
int host_flash_initialization_init_internal (struct host_flash_initialization *init,
	struct host_flash_initialization_state *state, struct spi_flash *flash_cs0,
	struct spi_flash_state *state_cs0, const struct flash_master *spi_cs0,
	struct spi_flash *flash_cs1, struct spi_flash_state *state_cs1,
	const struct flash_master *spi_cs1, bool dual_flash, bool fast_read, bool drive_strength)
{
	int status;

	if (init == NULL) {
		return HOST_FLASH_INIT_INVALID_ARGUMENT;
	}

	status = spi_flash_init_api (flash_cs0, state_cs0, spi_cs0);
	if (status != 0) {
		return status;
	}

	if (dual_flash) {
		status = spi_flash_init_api (flash_cs1, state_cs1, spi_cs1);
		if (status != 0) {
			return status;
		}
	}

	memset (init, 0, sizeof (struct host_flash_initialization));

	init->state = state;
	init->flash_cs0 = flash_cs0;
	init->flash_cs1 = flash_cs1;
	init->dual_flash = dual_flash;
	init->fast_read = fast_read;
	init->drive_strength = drive_strength;

	return host_flash_initialization_init_state (init);
}

/**
 * Initialize the manager for delayed host flash initialization.  The host flash interfaces
 * themselves will not be initialized or accessed.
 *
 * NOTE: It is important that the SPI flash interfaces provided here NOT be initialized.
 * Initialization of these instances MUST be done through this module.
 *
 * @param init The initialization manager to initialize.
 * @param state Variable context for managing flash initialization.  This must be uninitialized.
 * @param flash_cs0 The SPI flash interface for the device on CS0.  This must be uninitialized.
 * @param state_cs0 Variable context for the SPI flash on CS0.
 * @param spi_cs0 The SPI master for the CS0 flash.
 * @param flash_cs1 The SPI flash interface for the device on CS1.  This must be uninitialized.
 * @param state_cs1 Variable context for the SPI flash on CS1.
 * @param spi_cs1 The SPI master for the CS1 flash.
 * @param fast_read Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength Flag to indicate if the device drive strength should be configured.
 *
 * @return 0 if the initialization manager was successfully initialized or an error code.
 */
int host_flash_initialization_init (struct host_flash_initialization *init,
	struct host_flash_initialization_state *state, struct spi_flash *flash_cs0,
	struct spi_flash_state *state_cs0, const struct flash_master *spi_cs0,
	struct spi_flash *flash_cs1, struct spi_flash_state *state_cs1,
	const struct flash_master *spi_cs1, bool fast_read, bool drive_strength)
{
	return host_flash_initialization_init_internal (init, state, flash_cs0, state_cs0, spi_cs0,
		flash_cs1, state_cs1, spi_cs1, true, fast_read, drive_strength);
}

/**
 * Initialize the manager for delayed host flash initialization with a single flash.  The host flash
 * interface itself will not be initialized or accessed.
 *
 * NOTE: It is important that the SPI flash interface provided here NOT be initialized.
 * Initialization of this instance MUST be done through this module.
 *
 * @param init The initialization manager to initialize.
 * @param state Variable context for managing flash initialization.  This must be uninitialized.
 * @param flash The SPI flash interface for the device on CS0.  This must be uninitialized.
 * @param state Variable context for the SPI flash on CS0.
 * @param spi The SPI master for the CS0 flash.
 * @param fast_read Flag to indicate if the SPI flash interface should use fast read commands.
 * @param drive_strength Flag to indicate if the device drive strength should be configured.
 *
 * @return 0 if the initialization manager was successfully initialized or an error code.
 */
int host_flash_initialization_init_single_flash (struct host_flash_initialization *init,
	struct host_flash_initialization_state *state, struct spi_flash *flash,
	struct spi_flash_state *state_flash, const struct flash_master *spi, bool fast_read,
	bool drive_strength)
{
	return host_flash_initialization_init_internal (init, state, flash, state_flash, spi, NULL,
		NULL, NULL, false, fast_read, drive_strength);
}

/**
 * Initialize only the variable state of a manager for delayed host flash initialization.  The rest
 * of the instance is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param init The initialization manager that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int host_flash_initialization_init_state (const struct host_flash_initialization *init)
{
	if ((init == NULL) || (init->state == NULL) || (init->flash_cs0 == NULL) ||
		(init->dual_flash && (init->flash_cs1 == NULL))) {
		return HOST_FLASH_INIT_INVALID_ARGUMENT;
	}

	memset (init->state, 0, sizeof (*init->state));

	return platform_mutex_init (&init->state->lock);
}

/**
 * Release the resources used by the flash initialization manager.
 *
 * @param init The initialization manager to release.
 */
void host_flash_initialization_release (const struct host_flash_initialization *init)
{
	if (init) {
		platform_mutex_free (&init->state->lock);
	}
}

/**
 * Initialize the host SPI flash devices.
 *
 * @param init The initialization manager to execute.
 *
 * @return 0 if flash initialization was successful or an error code.
 */
int host_flash_initialization_initialize_flash (const struct host_flash_initialization *init)
{
	int status = 0;

	if (init == NULL) {
		return HOST_FLASH_INIT_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&init->state->lock);

	if (!init->state->is_init0) {
		status = spi_flash_initialize_device_state (init->flash_cs0, init->fast_read, false,
			SPI_FLASH_RESET_NONE, init->drive_strength);
		if (status != 0) {
			goto exit;
		}

		init->state->is_init0 = true;
	}

	if (init->dual_flash && !init->state->is_init1) {
		status = spi_flash_initialize_device_state (init->flash_cs1, init->fast_read, false,
			SPI_FLASH_RESET_NONE, init->drive_strength);
		if (status != 0) {
			goto exit;
		}

		init->state->is_init1 = true;
	}

exit:
	platform_mutex_unlock (&init->state->lock);

	return status;
}
