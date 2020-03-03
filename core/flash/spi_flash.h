// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FLASH_H_
#define SPI_FLASH_H_

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "flash.h"
#include "flash_master.h"
#include "spi_flash_sfdp.h"
#include "platform.h"


/**
 * Flash command codes to use for different operations.
 */
struct spi_flash_commands {
	uint8_t read;						/**< The command code to read data from flash. */
	uint8_t read_dummy;					/**< The number of read dummy bytes. */
	uint8_t read_mode;					/**< The number of read mode bytes. */
	uint16_t read_flags;				/**< Transfer flags for read requests. */
	uint8_t write;						/**< The command code to write data to flash. */
	uint16_t write_flags;				/**< Transfer flags for write requests. */
	uint8_t erase_sector;				/**< The command to erase a 4kB sector. */
	uint16_t sector_flags;				/**< Transfer flags for sector erase requests. */
	uint8_t erase_block;				/**< The command to erase a 64kB block. */
	uint16_t block_flags;				/**< Transfer flags for block erase requests. */
};

/**
 * Interface to a single SPI flash.
 */
struct spi_flash {
	struct flash base;					/**< Base flash instance. */
	struct flash_master *spi;			/**< The SPI master connected to the flash device. */
	platform_mutex lock;				/**< Synchronization lock for accessing the flash. */
	uint16_t addr_mode;					/**< The current address mode of the SPI flash device. */
	uint8_t device_id[3];				/**< Device identification data. */
	uint32_t device_size;				/**< The total capacity of the flash device. */
	struct spi_flash_commands command;	/**< Commands to use with the flash device. */
	uint32_t capabilities;				/**< Capabilities of the flash device. */
	bool use_fast_read;					/**< Flag to use fast read for SPI reads. */
};

/**
 * Version number of the device info context.
 */
#define	SPI_FLASH_DEVICE_INFO_VERSION	0

/**
 * Context for saving and restoring a SPI flash device interface.
 */
struct spi_flash_device_info {
	uint8_t version;					/**< Version of the context structure. */
	uint8_t device_id[3];				/**< The device and vendor identifiers. */
	uint32_t device_size;				/**< The total capacity of the flash device. */
	uint32_t capabilities;				/**< Negotiated capabilities of the device. */
	uint8_t use_fast_read;				/**< Setting for FAST_READ for SPI reads. */
	uint8_t read_opcode;				/**< Opcode to use for SPI reads. */
	uint8_t read_dummy;					/**< Number of dummy bytes for SPI reads. */
	uint8_t read_mode;					/**< Number of mode bytes for SPI reads. */
	uint16_t read_flags;				/**< Transfer flags for SPI reads. */
} __attribute__((__packed__));


int spi_flash_initialize_device (struct spi_flash *flash, struct flash_master *spi, bool fast_read,
	bool wake_device, bool reset_device, bool drive_strength);
int spi_flash_restore_device (struct spi_flash *flash, struct flash_master *spi,
	struct spi_flash_device_info *info);

int spi_flash_init (struct spi_flash *flash, struct flash_master *spi);
int spi_flash_init_fast_read (struct spi_flash *flash, struct flash_master *spi);
void spi_flash_release (struct spi_flash *flash);

int spi_flash_save_device_info (struct spi_flash *flash, struct spi_flash_device_info *info);

int spi_flash_discover_device_properties (struct spi_flash *flash, struct spi_flash_sfdp *sfdp);
int spi_flash_set_device_size (struct spi_flash *flash, uint32_t bytes);

int spi_flash_get_device_id (struct spi_flash *flash, uint8_t *vendor, uint16_t *device);
int spi_flash_get_device_size (struct spi_flash *flash, uint32_t *bytes);

int spi_flash_reset_device (struct spi_flash *flash);
int spi_flash_clear_block_protect (struct spi_flash *flash);
int spi_flash_deep_power_down (struct spi_flash *flash, uint8_t enable);

int spi_flash_enable_4byte_address_mode (struct spi_flash *flash, uint8_t enable);
int spi_flash_is_4byte_address_mode (struct spi_flash *flash);
int spi_flash_detect_4byte_address_mode (struct spi_flash *flash);
int spi_flash_force_4byte_address_mode (struct spi_flash *flash, uint8_t enable);

int spi_flash_enable_quad_spi (struct spi_flash *flash, uint8_t enable);
int spi_flash_is_quad_spi_enabled (struct spi_flash *flash);

int spi_flash_configure_drive_strength (struct spi_flash *flash);

int spi_flash_read (struct spi_flash *flash, uint32_t address, uint8_t *data, size_t length);

int spi_flash_get_page_size (struct spi_flash *flash, uint32_t *bytes);
int spi_flash_minimum_write_per_page (struct spi_flash *flash, uint32_t *bytes);
int spi_flash_write (struct spi_flash *flash, uint32_t address, const uint8_t *data, size_t length);

int spi_flash_get_sector_size (struct spi_flash *flash, uint32_t *bytes);
int spi_flash_sector_erase (struct spi_flash *flash, uint32_t sector_addr);

int spi_flash_get_block_size (struct spi_flash *flash, uint32_t *bytes);
int spi_flash_block_erase (struct spi_flash *flash, uint32_t block_addr);

int spi_flash_chip_erase (struct spi_flash *flash);

int spi_flash_is_write_in_progress (struct spi_flash *flash);
int spi_flash_wait_for_write (struct spi_flash *flash, int32_t timeout);


#define	SPI_FLASH_ERROR(code)		ROT_ERROR (ROT_MODULE_SPI_FLASH, code)

/**
 * Error codes that can be generated by the SPI flash interface.
 */
enum {
	SPI_FLASH_INVALID_ARGUMENT = SPI_FLASH_ERROR (0x00),		/**< Input parameter is null or not valid. */
	SPI_FLASH_NO_MEMORY = SPI_FLASH_ERROR (0x01),				/**< Memory allocation failed. */
	SPI_FLASH_WIP_TIMEOUT = SPI_FLASH_ERROR (0x02),				/**< The write operation did not complete within the expected time. */
	SPI_FLASH_WRITE_IN_PROGRESS = SPI_FLASH_ERROR (0x03),		/**< An operation couldn't be executed because the flash is processing a write. */
	SPI_FLASH_UNSUPPORTED_DEVICE = SPI_FLASH_ERROR (0x04),		/**< The flash device is not supported. */
	SPI_FLASH_ADDRESS_OUT_OF_RANGE = SPI_FLASH_ERROR (0x05),	/**< A supplied address is out of range for the device. */
	SPI_FLASH_OPERATION_OUT_OF_RANGE = SPI_FLASH_ERROR (0x06),	/**< An operation would exceed the storage capacity of the device. */
	SPI_FLASH_UNSUPPORTED_ADDR_MODE = SPI_FLASH_ERROR (0x07),	/**< The address mode is not supported by the device. */
	SPI_FLASH_ADDR_MODE_FIXED = SPI_FLASH_ERROR (0x08),			/**< The address mode of the device is fixed. */
	SPI_FLASH_INCOMPATIBLE_SPI_MASTER = SPI_FLASH_ERROR (0x09),	/**< The SPI master is not compatible with the flash device. */
	SPI_FLASH_NO_DEVICE = SPI_FLASH_ERROR (0x0a),				/**< There is no flash device responding on the SPI bus. */
	SPI_FLASH_CONFIG_FAILURE = SPI_FLASH_ERROR (0x0b),			/**< Configuration did not get set properly. */
};


#endif /* SPI_FLASH_H_ */
