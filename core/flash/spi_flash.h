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
	uint8_t reset;						/**< The command to soft reset the device. */
	uint8_t enter_pwrdown;				/**< The command to enter deep power down. */
	uint8_t release_pwrdown;			/**< The command to release deep power down. */
};

/**
 * Variable context for a SPI flash driver instance.
 */
struct spi_flash_state {
	platform_mutex lock;								/**< Synchronization lock for accessing the flash. */
	uint16_t addr_mode;									/**< The current address mode of the SPI flash device. */
	uint8_t device_id[3];								/**< Device identification data. */
	uint32_t device_size;								/**< The total capacity of the flash device. */
	struct spi_flash_commands command;					/**< Commands to use with the flash device. */
	uint32_t capabilities;								/**< Capabilities of the flash device. */
	bool use_fast_read;									/**< Flag to use fast read for SPI reads. */
	bool use_busy_flag;									/**< Flag to use the busy status instead of WIP. */
	enum spi_flash_sfdp_4byte_addressing switch_4byte;	/**< Method for switching address mode. */
	bool reset_3byte;									/**< Flag to switch to 3-byte mode on reset. */
	enum spi_flash_sfdp_quad_enable quad_enable;		/**< Method to enable QSPI. */
	bool sr1_volatile;									/**< Flag to use volatile write enable for status register 1. */
};

/**
 * Interface to a single SPI flash.
 */
struct spi_flash {
	struct flash base;									/**< Base flash instance. */
	struct spi_flash_state *state;						/**< Variable context for the flash instance. */
	const struct flash_master *spi;						/**< The SPI master connected to the flash device. */
};

/**
 * Version number of the device info context.
 */
#define	SPI_FLASH_DEVICE_INFO_VERSION	1

#pragma pack(push,1)
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
	uint8_t reset_opcode;				/**< Opcode for soft resetting the device. */
	uint8_t enter_pwrdown;				/**< Opcode for entering deep power down. */
	uint8_t release_pwrdown;			/**< Opcode for releasing deep power down. */
	uint8_t switch_4byte;				/**< Method for switching to 4-byte addressing. */
	uint8_t quad_enable;				/**< Method to enable QSPI. */
	uint8_t flags;						/**< Misc behavior flags. */
};
#pragma pack(pop)

/* Flags in the device info structure. */
#define	SPI_FLASH_DEVICE_INFO_BUSY_FLAG			(1U << 0)
#define	SPI_FLASH_DEVICE_INFO_RESET_3BYTE		(1U << 1)
#define	SPI_FLASH_DEVICE_INFO_SR1_VOLATILE		(1U << 2)


int spi_flash_initialize_device (struct spi_flash *flash, struct spi_flash_state *state,
	const struct flash_master *spi, bool fast_read, bool wake_device, bool reset_device,
	bool drive_strength);
int spi_flash_initialize_device_state (const struct spi_flash *flash, bool fast_read,
	bool wake_device, bool reset_device, bool drive_strength);
int spi_flash_restore_device (struct spi_flash *flash, struct spi_flash_state *state,
	const struct flash_master *spi, const struct spi_flash_device_info *info);
int spi_flash_restore_device_state (const struct spi_flash *flash,
	const struct spi_flash_device_info *info);

int spi_flash_init (struct spi_flash *flash, struct spi_flash_state *state,
	const struct flash_master *spi);
int spi_flash_init_fast_read (struct spi_flash *flash, struct spi_flash_state *state,
	const struct flash_master *spi);
int spi_flash_init_state (const struct spi_flash *flash);
int spi_flash_init_state_fast_read (const struct spi_flash *flash);
void spi_flash_release (const struct spi_flash *flash);

int spi_flash_save_device_info (const struct spi_flash *flash, struct spi_flash_device_info *info);

int spi_flash_discover_device_properties (const struct spi_flash *flash,
	const struct spi_flash_sfdp *sfdp);
int spi_flash_set_device_size (const struct spi_flash *flash, uint32_t bytes);
int spi_flash_set_read_command (const struct spi_flash *flash,
	const struct spi_flash_sfdp_read_cmd *command, uint16_t flags);
int spi_flash_set_write_command (const struct spi_flash *flash, uint8_t opcode, uint16_t flags);

int spi_flash_get_device_id (const struct spi_flash *flash, uint8_t *vendor, uint16_t *device);
int spi_flash_get_device_size (const struct spi_flash *flash, uint32_t *bytes);

int spi_flash_reset_device (const struct spi_flash *flash);
int spi_flash_clear_block_protect (const struct spi_flash *flash);
int spi_flash_deep_power_down (const struct spi_flash *flash, uint8_t enable);

int spi_flash_is_address_mode_fixed (const struct spi_flash *flash);
int spi_flash_address_mode_requires_write_enable (const struct spi_flash *flash);
int spi_flash_is_4byte_address_mode_on_reset (const struct spi_flash *flash);

int spi_flash_enable_4byte_address_mode (const struct spi_flash *flash, uint8_t enable);
int spi_flash_is_4byte_address_mode (const struct spi_flash *flash);
int spi_flash_detect_4byte_address_mode (const struct spi_flash *flash);
int spi_flash_force_4byte_address_mode (const struct spi_flash *flash, uint8_t enable);

int spi_flash_enable_quad_spi (const struct spi_flash *flash, uint8_t enable);
int spi_flash_is_quad_spi_enabled (const struct spi_flash *flash);

int spi_flash_configure_drive_strength (const struct spi_flash *flash);

int spi_flash_read (const struct spi_flash *flash, uint32_t address, uint8_t *data, size_t length);

int spi_flash_get_page_size (const struct spi_flash *flash, uint32_t *bytes);
int spi_flash_minimum_write_per_page (const struct spi_flash *flash, uint32_t *bytes);
int spi_flash_write (const struct spi_flash *flash, uint32_t address, const uint8_t *data,
	size_t length);

int spi_flash_get_sector_size (const struct spi_flash *flash, uint32_t *bytes);
int spi_flash_sector_erase (const struct spi_flash *flash, uint32_t sector_addr);

int spi_flash_get_block_size (const struct spi_flash *flash, uint32_t *bytes);
int spi_flash_block_erase (const struct spi_flash *flash, uint32_t block_addr);

int spi_flash_chip_erase (const struct spi_flash *flash);

int spi_flash_is_write_in_progress (const struct spi_flash *flash);
int spi_flash_wait_for_write (const struct spi_flash *flash, int32_t timeout);


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
	SPI_FLASH_NO_4BYTE_CMDS = SPI_FLASH_ERROR (0x0c),			/**< The device does not support required 4-byte commands. */
	SPI_FLASH_RESET_NOT_SUPPORTED = SPI_FLASH_ERROR (0x0d),		/**< Soft reset is not supported by the device. */
	SPI_FLASH_PWRDOWN_NOT_SUPPORTED = SPI_FLASH_ERROR (0x0e),	/**< Deep power down is not supported by the device. */
	SPI_FLASH_READ_ONLY_INTERFACE = SPI_FLASH_ERROR (0x0f),		/**< The interface is only configured to allow read access. */
};


#endif /* SPI_FLASH_H_ */
