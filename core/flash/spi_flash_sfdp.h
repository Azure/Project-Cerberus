// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FLASH_SFDP_H_
#define SPI_FLASH_SFDP_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "flash_master.h"


#pragma pack(push,1)
/**
 * SFDP parameter header format.
 */
struct spi_flash_sfdp_parameter_header {
	uint8_t id_lsb;					/**< LSB of the parameter identifier. */
	uint8_t minor_revision;			/**< Minor revision of the parameter table. */
	uint8_t major_revision;			/**< Major revision of the parameter table. */
	uint8_t length;					/**< Length of the parameter table, in dwords. */
	uint8_t table_pointer[3];		/**< Address of the parameter table. */
	uint8_t id_msb;					/**< MSB of the parameter identifier. */
};

/**
 * SFDP header format.
 */
struct spi_flash_sfdp_header {
	uint32_t signature;									/**< SFDP header signature. */
	uint8_t minor_revision;								/**< SFDP minor revision. */
	uint8_t major_revision;								/**< SFDP major revision. */
	uint8_t header_count;								/**< The number of parameters headers. */
	uint8_t unused;										/**< Unused.  Must be 0xff. */
	struct spi_flash_sfdp_parameter_header parameter0;	/**< Header for the first parameter table. */
};
#pragma pack(pop)

/**
 * SFDP interface for a single SPI flash.
 */
struct spi_flash_sfdp {
	const struct flash_master *flash;			/**< SPI master for the flash device. */
	struct spi_flash_sfdp_header sfdp_header;	/**< The mandatory SFDP header information. */
	uint8_t vendor;								/**< Vendor ID for the flash device. */
	uint16_t device;							/**< Device ID for the flash device. */
};


int spi_flash_sfdp_init (struct spi_flash_sfdp *sfdp, const struct flash_master *flash);
void spi_flash_sfdp_release (struct spi_flash_sfdp *sfdp);

void spi_flash_sfdp_dump_header (const struct spi_flash_sfdp *sfdp);


/**
 * The number of dwords that make up version 1.5 of the SFDP Basic Parameters Table.
 */
#define	SPI_FLASH_SFDP_BASIC_TABLE_V1_5_DWORDS		16

/**
 * JEDEC SFDP basic parameter table.
 */
struct spi_flash_sfdp_basic_table {
	const struct spi_flash_sfdp *sfdp;						/**< The SFDP instance for the table. */
	uint32_t data[SPI_FLASH_SFDP_BASIC_TABLE_V1_5_DWORDS];	/**< The SFDP basic parameter table data. */
};

/**
 * Details necessary to execute read commands.
 */
struct spi_flash_sfdp_read_cmd {
	uint8_t opcode;								/**< The opcode to use for the read. */
	uint8_t dummy_bytes;						/**< The number of dummy bytes. */
	uint8_t mode_bytes;							/**< The number of mode bytes. */
};

/**
 * Information read commands supported by the flash device.
 */
struct spi_flash_sfdp_read_commands {
	struct spi_flash_sfdp_read_cmd dual_1_1_2;	/**< Dual output (1-1-2) fast read. */
	struct spi_flash_sfdp_read_cmd dual_1_2_2;	/**< Dual I/O (1-2-2) fast read. */
	struct spi_flash_sfdp_read_cmd dual_2_2_2;	/**< DPI (2-2-2) fast read. */
	struct spi_flash_sfdp_read_cmd quad_1_1_4;	/**< Quad output (1-1-4) fast read. */
	struct spi_flash_sfdp_read_cmd quad_1_4_4;	/**< Quad I/O (1-4-4) fast read. */
	struct spi_flash_sfdp_read_cmd quad_4_4_4;	/**< QPI (4-4-4) fast read. */
};

/**
 * Supported methods for entering and exiting 4-byte addressing mode.
 */
enum spi_flash_sfdp_4byte_addressing {
	SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED,			/**< 4-byte addressing is not supported. */
	SPI_FLASH_SFDP_4BYTE_MODE_COMMAND,				/**< Use a command to switch the mode. */
	SPI_FLASH_SFDP_4BYTE_MODE_COMMAND_WRITE_ENABLE,	/**< Issue write enable before mode switch. */
	SPI_FLASH_SFDP_4BYTE_MODE_FIXED,				/**< Device is permanently in 4-byte mode. */
};

/**
 * Mechanisms defined for enabling QSPI.
 */
enum spi_flash_sfdp_quad_enable {
	SPI_FLASH_SFDP_QUAD_NO_QE_BIT = 0,				/**< No quad enable bit is necessary. */
	SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2,				/**< Quad enable is bit 1 in status register 2. */
	SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1,				/**< Quad enable is bit 6 in status register 1. */
	SPI_FLASH_SFDP_QUAD_QE_BIT7_SR2,				/**< Quad enable is bit 7 in status register 2. */
	SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2_NO_CLR,			/**< Quad enable is bit 1 in status register 2, without inadvertent clearing. */
	SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2_35,				/**< Quad enable is bit 1 in status register 2, using 35 to read. */
	SPI_FLASH_SFDP_QUAD_NO_QE_HOLD_DISABLE = 8,		/**< No quad enable bit, but HOLD/RESET can be disabled. */
};


int spi_flash_sfdp_basic_table_init (struct spi_flash_sfdp_basic_table *table,
	const struct spi_flash_sfdp *sfdp);
void spi_flash_sfdp_basic_table_release (struct spi_flash_sfdp_basic_table *table);

int spi_flash_sfdp_get_device_capabilities (const struct spi_flash_sfdp_basic_table *table,
	uint32_t *capabilities);
int spi_flash_sfdp_get_device_size (const struct spi_flash_sfdp_basic_table *table);
int spi_flash_sfdp_get_page_size (const struct spi_flash_sfdp_basic_table *table);

int spi_flash_sfdp_get_read_commands (const struct spi_flash_sfdp_basic_table *table,
	struct spi_flash_sfdp_read_commands *read);

bool spi_flash_sfdp_use_busy_flag_status (const struct spi_flash_sfdp_basic_table *table);
bool spi_flash_sfdp_use_volatile_write_enable (const struct spi_flash_sfdp_basic_table *table);

bool spi_flash_sfdp_supports_4byte_commands (const struct spi_flash_sfdp_basic_table *table);
int spi_flash_sfdp_get_4byte_mode_switch (const struct spi_flash_sfdp_basic_table *table,
	enum spi_flash_sfdp_4byte_addressing *addr_4byte);
bool spi_flash_sfdp_exit_4byte_mode_on_reset (const struct spi_flash_sfdp_basic_table *table);

int spi_flash_sfdp_get_quad_enable (const struct spi_flash_sfdp_basic_table *table,
	enum spi_flash_sfdp_quad_enable *quad_enable);

int spi_flash_sfdp_get_reset_command (const struct spi_flash_sfdp_basic_table *table,
	uint8_t *reset);
int spi_flash_sfdp_get_deep_powerdown_commands (const struct spi_flash_sfdp_basic_table *table,
	uint8_t *enter, uint8_t *exit);

void spi_flash_sfdp_dump_basic_table (const struct spi_flash_sfdp_basic_table *table);


#define	SPI_FLASH_SFDP_ERROR(code)		ROT_ERROR (ROT_MODULE_SPI_FLASH_SFDP, code)

/**
 * Error codes that can be generated by SFDP parsing.
 */
enum {
	SPI_FLASH_SFDP_INVALID_ARGUMENT = SPI_FLASH_SFDP_ERROR (0x00),		/**< Input parameter is null or not valid. */
	SPI_FLASH_SFDP_NO_MEMORY = SPI_FLASH_SFDP_ERROR (0x01),				/**< Memory allocation failed. */
	SPI_FLASH_SFDP_BAD_SIGNATURE = SPI_FLASH_SFDP_ERROR (0x02),			/**< The SFDP header signature is not correct. */
	SPI_FLASH_SFDP_BAD_HEADER = SPI_FLASH_SFDP_ERROR (0x03),			/**< SFDP header information is invalid. */
	SPI_FLASH_SFDP_LARGE_DEVICE = SPI_FLASH_SFDP_ERROR (0x04),			/**< The device is too large to correctly report size. */
	SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE = SPI_FLASH_SFDP_ERROR (0x05),	/**< Device is not compatible with supported 4-byte addressing. */
	SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN = SPI_FLASH_SFDP_ERROR (0x06),	/**< QSPI enabled method cannot be determined. */
	SPI_FLASH_SFDP_RESET_NOT_SUPPORTED = SPI_FLASH_SFDP_ERROR (0x07),	/**< Soft reset is not supported by the device. */
	SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED = SPI_FLASH_SFDP_ERROR (0x08),	/**< Deep power down is not supported by the device. */
};


#endif /* SPI_FLASH_SFDP_H_ */
