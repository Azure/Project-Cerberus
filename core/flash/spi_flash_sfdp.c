// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "platform_io.h"
#include "spi_flash_sfdp.h"
#include "flash_common.h"


/**
 * The expected signature in the SFDP header.
 */
#define	SPI_FLASH_SFDP_SIGNATURE		0x50444653

/**
 * Get the parameter ID from a table header.
 */
#define	SPI_FLASH_SFDP_PARAMETER_ID(x)	((x.id_msb << 8) | x.id_lsb)

/**
 * Get the starting address of a parameter table.
 */
#define	SPI_FLASH_SFDP_PARAMETER_PTR(x)	((x.table_pointer[2] << 16) | (x.table_pointer[1] << 8) | x.table_pointer[0])

/**
 * SFDP basic flash parameter table format version 1.0.
 */
struct spi_flash_sfdp_basic_parameter_table_1_0 {
	uint8_t write_attr;				/**< 1st DWORD: Write attributes. */
	uint8_t erase_4kb;				/**< 1st DWORD: 4kB erase instruction. */
	uint8_t dspi_qspi;				/**< 1st DWORD: DSPI and QSPI support flags. */
#define	SPI_FLASH_SFDP_SUPPORTS_1_1_2	(1U << 0)
#define	SPI_FLASH_SFDP_ADDRESS_BYTES	(3U << 1)
#define	SPI_FLASH_SFDP_3BYTE_ONLY			0
#define	SPI_FLASH_SFDP_3BYTE_4BYTE			(1U << 1)
#define	SPI_FLASH_SFDP_4BYTE_ONLY			(1U << 2)
#define	SPI_FLASH_SFDP_SUPPORTS_DTR		(1U << 3)
#define	SPI_FLASH_SFDP_SUPPORTS_1_2_2	(1U << 4)
#define	SPI_FLASH_SFDP_SUPPORTS_1_4_4	(1U << 5)
#define	SPI_FLASH_SFDP_SUPPORTS_1_1_4	(1U << 6)
	uint8_t unused1;				/**< 1st DWORD: Unused. */
	uint32_t memory_density;		/**< 2nd DWORD: Size of the flash device. */
#define	SPI_FLASH_SFDP_4GB_DENSITY		(1U << 31)
	uint8_t dummy_1_4_4;			/**< 3rd DWORD: 1-4-4 dummy clocks. */
#define	SPI_FLASH_SFDP_MODE_CLKS_MASK	0x7
#define	SPI_FLASH_SFDP_MODE_CLKS_SHIFT	5
#define	SPI_FLASH_SFDP_MODE_CLKS(x)		(((x) >> SPI_FLASH_SFDP_MODE_CLKS_SHIFT) & SPI_FLASH_SFDP_MODE_CLKS_MASK)
#define	SPI_FLASH_SFDP_DUMMY_CLKS_MASK	0x1f
#define	SPI_FLASH_SFDP_DUMMY_CLKS_SHIFT	0
#define	SPI_FLASH_SFDP_DUMMY_CLKS(x)	(((x) >> SPI_FLASH_SFDP_DUMMY_CLKS_SHIFT) & SPI_FLASH_SFDP_DUMMY_CLKS_MASK)
	uint8_t opcode_1_4_4;			/**< 3rd DWORD: 1-4-4 command opcode. */
	uint8_t dummy_1_1_4;			/**< 3rd DWORD: 1-1-4 dummy clocks. */
	uint8_t opcode_1_1_4;			/**< 3rd DWORD: 1-1-4 command opcode. */
	uint8_t dummy_1_1_2;			/**< 4th DWORD: 1-1-2 dummy clocks. */
	uint8_t opcode_1_1_2;			/**< 4th DWORD: 1-1-2 command opcode. */
	uint8_t dummy_1_2_2;			/**< 4th DWORD: 1-2-2 dummy clocks. */
	uint8_t opcode_1_2_2;			/**< 4th DWORD: 1-2-2 command opcode. */
	uint32_t dpi_qpi;				/**< 5th DWORD: DPI and QPI support flags. */
#define	SPI_FLASH_SFDP_SUPPORTS_2_2_2	(1U << 0)
#define	SPI_FLASH_SFDP_SUPPORTS_4_4_4	(1U << 4)
	uint16_t unused6;				/**< 6th DWORD: Unused. */
	uint8_t dummy_2_2_2;			/**< 6th DWORD: 2-2-2 dummy clocks. */
	uint8_t opcode_2_2_2;			/**< 6th DWORD: 2-2-2 command opcode. */
	uint16_t unused7;				/**< 7th DWORD: Unused. */
	uint8_t dummy_4_4_4;			/**< 7th DWORD: 4-4-4 dummy clocks. */
	uint8_t opcode_4_4_4;			/**< 7th DWORD: 4-4-4 command opcode. */
	uint8_t erase1_size;			/**< 8th DWORD: Erase 1 block size. */
	uint8_t erase1;					/**< 8th DWORD: Erase 1 instruction. */
	uint8_t erase2_size;			/**< 8th DWORD: Erase 2 block size. */
	uint8_t erase2;					/**< 8th DWORD: Erase 2 instruction. */
	uint8_t erase3_size;			/**< 9th DWORD: Erase 3 block size. */
	uint8_t erase3;					/**< 9th DWORD: Erase 3 instruction. */
	uint8_t erase4_size;			/**< 9th DWORD: Erase 4 block size. */
	uint8_t erase4;					/**< 9th DWORD: Erase 4 instruction. */
} __attribute__((__packed__));


/**
 * Initialize an SFDP interface for SPI flash.
 *
 * @param sfdp The SFDP interface to initialize.
 * @param flash The SPI master for the flash device.
 *
 * @return 0 if the SFDP interface was successfully initialized or an error code.
 */
int spi_flash_sfdp_init (struct spi_flash_sfdp *sfdp, struct flash_master *flash)
{
	struct flash_xfer xfer;
	int status;

	if ((sfdp == NULL) || (flash == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	memset (sfdp, 0, sizeof (struct spi_flash_sfdp));

	FLASH_XFER_INIT_READ (xfer, FLASH_CMD_SFDP, 0, 1, 0, (uint8_t*) &sfdp->sfdp_header,
		sizeof (sfdp->sfdp_header), 0);
	status = flash->xfer (flash, &xfer);
	if (status != 0) {
		return status;
	}

	if (sfdp->sfdp_header.signature != SPI_FLASH_SFDP_SIGNATURE) {
		return SPI_FLASH_SFDP_BAD_SIGNATURE;
	}

	if ((sfdp->sfdp_header.unused != 0xff) ||
		(SPI_FLASH_SFDP_PARAMETER_ID (sfdp->sfdp_header.parameter0) != 0xff00)) {
		return SPI_FLASH_SFDP_BAD_HEADER;
	}

	sfdp->flash =  flash;

	return 0;
}

/**
 * Release the resources used by an SFDP interface.
 *
 * @param sfdp The SFDP interface to release.
 */
void spi_flash_sfdp_release (struct spi_flash_sfdp *sfdp)
{

}

/**
 * Read the SFDP basic parameter table from the SPI flash.
 *
 * @param table The basic parameter table instance to load.
 * @param sfdp The SFDP interface to use to load the table.
 *
 * @return 0 if the basic parameter table was successfully read or an error code.
 */
int spi_flash_sfdp_basic_table_init (struct spi_flash_sfdp_basic_table *table,
	struct spi_flash_sfdp *sfdp)
{
	struct flash_xfer xfer;
	uint8_t *data;
	size_t length;
	int status;

	if ((table == NULL) || (sfdp == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	memset (table, 0, sizeof (struct spi_flash_sfdp_basic_table));

	length = sfdp->sfdp_header.parameter0.length * 4;
	data = platform_malloc (length);
	if (data == NULL) {
		return SPI_FLASH_SFDP_NO_MEMORY;
	}

	FLASH_XFER_INIT_READ (xfer, FLASH_CMD_SFDP,
		SPI_FLASH_SFDP_PARAMETER_PTR (sfdp->sfdp_header.parameter0), 1, 0, data, length, 0);
	status = sfdp->flash->xfer (sfdp->flash, &xfer);
	if (status != 0) {
		platform_free (data);
		return status;
	}

	table->sfdp_header = &sfdp->sfdp_header;
	table->data = data;

	return 0;
}

/**
 * Release the resources used by a SFDP basic parameter table.
 *
 * @param table The table to release.
 */
void spi_flash_sfdp_basic_table_release (struct spi_flash_sfdp_basic_table *table)
{
	if (table) {
		platform_free (table->data);
	}
}

/**
 * Determine the capabilities of the flash device.
 *
 * @param table The basic parameters table that will be queried to determine the capabilities.
 * @param capabilities Output for the device capabilities.  This will be a bit mask using the same
 * capabilities defined for the SPI flash master.
 *
 * @return 0 if the capabilities were retrieved successfully or an error code.
 */
int spi_flash_sfdp_get_device_capabilities (struct spi_flash_sfdp_basic_table *table,
	uint32_t *capabilities)
{
	struct spi_flash_sfdp_basic_parameter_table_1_0 *basic;

	if ((table == NULL) || (capabilities == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	basic = table->data;
	*capabilities = 0;

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_2) {
		*capabilities |= FLASH_CAP_DUAL_1_1_2;
	}
	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_2_2) {
		*capabilities |= FLASH_CAP_DUAL_1_2_2;
	}
	if (basic->dpi_qpi & SPI_FLASH_SFDP_SUPPORTS_2_2_2) {
		*capabilities |= FLASH_CAP_DUAL_2_2_2;
	}

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_4) {
		*capabilities |= FLASH_CAP_QUAD_1_1_4;
	}
	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_4_4) {
		*capabilities |= FLASH_CAP_QUAD_1_4_4;
	}
	if (basic->dpi_qpi & SPI_FLASH_SFDP_SUPPORTS_4_4_4) {
		*capabilities |= FLASH_CAP_QUAD_4_4_4;
	}

	switch (basic->dspi_qspi & SPI_FLASH_SFDP_ADDRESS_BYTES) {
		case SPI_FLASH_SFDP_3BYTE_ONLY:
			*capabilities |= FLASH_CAP_3BYTE_ADDR;
			break;

		case SPI_FLASH_SFDP_3BYTE_4BYTE:
			*capabilities |= (FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);
			break;

		case SPI_FLASH_SFDP_4BYTE_ONLY:
			*capabilities |= FLASH_CAP_4BYTE_ADDR;
	}

	return 0;
}

/**
 * Determine the amount of storage available in the flash device.
 *
 * @param table The basic parameters table that will be queried to determine the size.
 *
 * @return The size of the device in bytes or an error code.
 */
int spi_flash_sfdp_get_device_size (struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_0 *basic;

	if (table == NULL) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	basic = table->data;

	if (!(basic->memory_density & SPI_FLASH_SFDP_4GB_DENSITY)) {
		return (basic->memory_density + 1) / 8;
	}
	else {
		int factor = (basic->memory_density & (~SPI_FLASH_SFDP_4GB_DENSITY)) - 3;

		if (factor < 31) {
			return 1U << factor;
		}
		else {
			return SPI_FLASH_SFDP_LARGE_DEVICE;
		}
	}
}

/**
 * Parse read command information from the SFDP table.
 *
 * @param cmd The read command to parse.
 * @param opcode The opcode used by the device for this command.
 * @param dummy_clocks The number of dummy clocks for the command.
 * @param clocks_per_byte The number of clocks for each dummy byte.
 */
static void spi_flash_sfdp_parse_read_command (struct spi_flash_sfdp_read_cmd *cmd, uint8_t opcode,
	uint8_t dummy_clocks, uint8_t clocks_per_byte)
{
	uint8_t partial_byte;

	cmd->opcode = opcode;
	cmd->mode_bytes = SPI_FLASH_SFDP_MODE_CLKS (dummy_clocks);
	cmd->dummy_bytes = SPI_FLASH_SFDP_DUMMY_CLKS (dummy_clocks);

	partial_byte = cmd->mode_bytes % clocks_per_byte;
	if (partial_byte != 0) {
		cmd->mode_bytes += partial_byte;
		cmd->dummy_bytes -= partial_byte;
	}

	cmd->mode_bytes /= clocks_per_byte;
	cmd->dummy_bytes /= clocks_per_byte;
}

/**
 * Determine the details about how to execute read commands against the flash device.
 *
 * @param table The basic parameters table that will be queried to determine the read commands.
 * @param read Output for the read command information.
 *
 * @return 0 if the command information was retrieved successfully or an error code.
 */
int spi_flash_sfdp_get_read_commands (struct spi_flash_sfdp_basic_table *table,
	struct spi_flash_sfdp_read_commands *read)
{
	struct spi_flash_sfdp_basic_parameter_table_1_0 *basic;

	if ((table == NULL) || (read == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	basic = table->data;
	memset (read, 0, sizeof (struct spi_flash_sfdp_read_commands));

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_2) {
		spi_flash_sfdp_parse_read_command (&read->dual_1_1_2, basic->opcode_1_1_2,
			basic->dummy_1_1_2, 8);
	}

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_2_2) {
		spi_flash_sfdp_parse_read_command (&read->dual_1_2_2, basic->opcode_1_2_2,
			basic->dummy_1_2_2, 4);
	}

	if (basic->dpi_qpi & SPI_FLASH_SFDP_SUPPORTS_2_2_2) {
		spi_flash_sfdp_parse_read_command (&read->dual_2_2_2, basic->opcode_2_2_2,
			basic->dummy_2_2_2, 4);
	}

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_4) {
		spi_flash_sfdp_parse_read_command (&read->quad_1_1_4, basic->opcode_1_1_4,
			basic->dummy_1_1_4, 8);
	}

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_4_4) {
		spi_flash_sfdp_parse_read_command (&read->quad_1_4_4, basic->opcode_1_4_4,
			basic->dummy_1_4_4, 2);
	}

	if (basic->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_4_4_4) {
		spi_flash_sfdp_parse_read_command (&read->quad_4_4_4, basic->opcode_4_4_4,
			basic->dummy_4_4_4, 2);
	}

	return 0;
}

/**
 * Print the contents of the basic parameters table.
 *
 * @param table The basic parameters table to print.
 */
void spi_flash_sfdp_dump_basic_table (struct spi_flash_sfdp_basic_table *table)
{
	uint32_t *sfdp_data;
	int i;

	if (table) {
		sfdp_data = (uint32_t*) table->sfdp_header;
		platform_printf ("SFDP Header:   0x%lx" NEWLINE, (long unsigned int) sfdp_data[0]);
		platform_printf ("               0x%lx" NEWLINE, (long unsigned int) sfdp_data[1]);
		platform_printf ("1st Param Hdr: 0x%lx" NEWLINE, (long unsigned int) sfdp_data[2]);
		platform_printf ("               0x%lx" NEWLINE, (long unsigned int) sfdp_data[3]);
		platform_printf (NEWLINE);

		sfdp_data = table->data;
		platform_printf ("Basic Flash Parameter Table:" NEWLINE);
		for (i = 0; i < table->sfdp_header->parameter0.length; i++) {
			platform_printf ("  DWORD %2d: 0x%lx" NEWLINE, i + 1, (long unsigned int) sfdp_data[i]);
		}
	}
}
