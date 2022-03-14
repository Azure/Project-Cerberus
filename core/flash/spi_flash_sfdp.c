// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform_io.h"
#include "spi_flash_sfdp.h"
#include "flash_common.h"
#include "common/common_math.h"
#include "common/unused.h"


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
#define	SPI_FLASH_SFDP_PARAMETER_PTR(x)	\
	((x.table_pointer[2] << 16) | (x.table_pointer[1] << 8) | x.table_pointer[0])

#pragma pack(push,1)
/**
 * SFDP basic flash parameter table format version 1.0.
 */
struct spi_flash_sfdp_basic_parameter_table_1_0 {
	uint8_t write_attr;				/**< 1st DWORD: Write attributes. */
	uint8_t erase_4kb;				/**< 1st DWORD: 4kB erase instruction. */
	uint8_t dspi_qspi;				/**< 1st DWORD: DSPI and QSPI support flags. */
#define	SPI_FLASH_SFDP_SUPPORTS_1_1_2	(1U << 0)
#define	SPI_FLASH_SFDP_ADDRESS_BYTES	(3U << 1)
#define	SPI_FLASH_SFDP_3BYTE_ONLY			(0)
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
};

/**
 * SFDP basic flash parameter table format version 1.5.
 */
struct spi_flash_sfdp_basic_parameter_table_1_5 {
	struct spi_flash_sfdp_basic_parameter_table_1_0 table_1_0;
	uint32_t erase_time;			/**< 10th DWORD: Erase typical timing. */
	uint8_t page_size;				/**< 11th DWORD: Page size. */
#define	SPI_FLASH_SFDP_PAGE_SIZE(x)			(((x) & 0xf0) >> 4)
	uint16_t program_time;			/**< 11th DWORD: Page programming typical timing. */
	uint8_t chip_erase_time;		/**< 11th DWORD: Chip erase typical timing. */
	uint32_t suspend_attr;			/**< 12th DWORD: Suspend/Resume attributes. */
	uint8_t program_resume;			/**< 13th DWORD: Program Resume instruction. */
	uint8_t program_suspend;		/**< 13th DWORD: Program Suspend instruction. */
	uint8_t resume;					/**< 13th DWORD: Resume instruction. */
	uint8_t suspend;				/**< 13th DWORD: Suspend instruction. */
	uint8_t status_reg;				/**< 14th DWORD: Status register polling device busy. */
#define	SPI_FLASH_SFDP_BUSY_SR_WIP			(1U << 2)
#define	SPI_FLASH_SFDP_BUSY_SR_FLAG			(1U << 3)
	uint8_t deep_powerdown[3];		/**< 14th DWORD: Deep power down attributes. */
#define	SPI_FLASH_SFDP_PWRDWN_NO_SUPPORT(x)	((x)[2] & (1U << 7))
#define	SPI_FLASH_SFDP_PWRDWN_ENTER(x)		((((x)[2] & 0x7f) << 1) | (((x)[1] & 0x80) >> 7))
#define	SPI_FLASH_SFDP_PWRDWN_EXIT(x)		((((x)[1] & 0x7f) << 1) | (((x)[0] & 0x80) >> 7))
	uint32_t quad_enable;			/**< 15th DWORD: Quad enable sequences. */
#define	SPI_FLASH_SFDP_QER_MASK				0x7
#define	SPI_FLASH_SFDP_QER_SHIFT			20
#define	SPI_FLASH_SFDP_QER(x)				(((x) >> SPI_FLASH_SFDP_QER_SHIFT) & SPI_FLASH_SFDP_QER_MASK)
#define	SPI_FLASH_SFDP_QER_NO_QUAD_ENABLE		0
#define	SPI_FLASH_SFDP_QER_BIT1_SR2				1
#define	SPI_FLASH_SFDP_QER_BIT6_SR1				2
#define	SPI_FLASH_SFDP_QER_BIT7_SR2_3E			3
#define	SPI_FLASH_SFDP_QER_BIT1_SR2_NO_CLR		4
#define	SPI_FLASH_SFDP_QER_BIT1_SR2_35			5
#define	SPI_FLASH_SFDP_QER_RESERVED1			6
#define	SPI_FLASH_SFDP_QER_RESERVED2			7
#define	SPI_FLASH_SFDP_HOLD_RST_DISABLE		(1U << 23)
	uint8_t sr_write_enable;		/**< 16th DWORD: Status register 1 write enable. */
#define	SPI_FLASH_SFDP_NV_SR_06				(1U << 0)
#define	SPI_FLASH_SFDP_VOLATILE_SR_06		(1U << 1)
#define	SPI_FLASH_SFDP_VOLATILE_SR_50		(1U << 2)
#define	SPI_FLASH_SFDP_NV_V_SR_06_50		(1U << 3)
#define	SPI_FLASH_SFDP_NV_V_SR_06			(1U << 4)
#define SPI_FLASH_SFDP_SR_WE_RESERVED		(0xe0)
	uint16_t reset_exit_4b;			/**< 16th DWORD: Soft reset and Exit 4-byte address mode. */
#define	SPI_FLASH_SFDP_RST_F0				(1U << 3)
#define	SPI_FLASH_SFDP_RST_66_99			(1U << 4)
#define	SPI_FLASH_SFDP_4B_EXIT_E9			(1U << 6)
#define	SPI_FLASH_SFDP_4B_EXIT_06_E9		(1U << 7)
#define	SPI_FLASH_SFDP_4B_EXIT_EAR_C5		(1U << 8)
#define	SPI_FLASH_SFDP_4B_EXIT_BANK_REG		(1U << 9)
#define	SPI_FLASH_SFDP_4B_EXIT_NV_CFG		(1U << 10)
#define	SPI_FLASH_SFDP_4B_EXIT_HW_RESET		(1U << 11)
#define	SPI_FLASH_SFDP_4B_EXIT_SW_RESET		(1U << 12)
#define	SPI_FLASH_SFDP_4B_EXIT_AC_RESET		(1U << 13)
	uint8_t enter_4b;				/**< 16th DWORD: Enter 4-byte address mode. */
#define	SPI_FLASH_SFDP_4B_ENTER_B7			(1U << 0)
#define	SPI_FLASH_SFDP_4B_ENTER_06_B7		(1U << 1)
#define	SPI_FLASH_SFDP_4B_ENTER_EAR_C5		(1U << 2)
#define	SPI_FLASH_SFDP_4B_ENTER_BANK_REG	(1U << 3)
#define	SPI_FLASH_SFDP_4B_ENTER_NV_CFG		(1U << 4)
#define	SPI_FLASH_SFDP_4B_OPCODES			(1U << 5)
#define	SPI_FLASH_SFDP_ALWAYS_4B			(1U << 6)
};
#pragma pack(pop)


/**
 * Initialize an SFDP interface for SPI flash.
 *
 * @param sfdp The SFDP interface to initialize.
 * @param flash The SPI master for the flash device.
 *
 * @return 0 if the SFDP interface was successfully initialized or an error code.
 */
int spi_flash_sfdp_init (struct spi_flash_sfdp *sfdp, const struct flash_master *flash)
{
	struct flash_xfer xfer;
	int status;
	uint8_t id[3];

	if ((sfdp == NULL) || (flash == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	memset (sfdp, 0, sizeof (struct spi_flash_sfdp));

	FLASH_XFER_INIT_READ_REG (xfer, FLASH_CMD_RDID, id, sizeof (id), 0);
	status = flash->xfer (flash, &xfer);
	if (status != 0) {
		return status;
	}

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

	sfdp->flash = flash;
	sfdp->vendor = id[0];
	sfdp->device = (id[1] << 8) | id[2];

	return 0;
}

/**
 * Release the resources used by an SFDP interface.
 *
 * @param sfdp The SFDP interface to release.
 */
void spi_flash_sfdp_release (struct spi_flash_sfdp *sfdp)
{
	UNUSED (sfdp);
}

/**
 * Print the contents of the SFDP header.
 *
 * @param sfdp The SFDP information to print.
 */
void spi_flash_sfdp_dump_header (const struct spi_flash_sfdp *sfdp)
{
	struct flash_xfer xfer;
	uint32_t sfdp_data[sizeof (struct spi_flash_sfdp_header)];
	size_t hdr_size = sizeof (struct spi_flash_sfdp_parameter_header);
	uint32_t i;
	int status;

	if (sfdp) {
		memcpy (sfdp_data, &sfdp->sfdp_header, sizeof (sfdp_data));
		platform_printf ("Vendor: 0x%x, Device: 0x%x" NEWLINE, sfdp->vendor, sfdp->device);
		platform_printf ("SFDP Header:   0x%08lx" NEWLINE, (long unsigned int) sfdp_data[0]);
		platform_printf ("               0x%08lx" NEWLINE, (long unsigned int) sfdp_data[1]);
		platform_printf ("1st Param Hdr: 0x%08lx" NEWLINE, (long unsigned int) sfdp_data[2]);
		platform_printf ("               0x%08lx" NEWLINE, (long unsigned int) sfdp_data[3]);

		for (i = 0; i < sfdp->sfdp_header.header_count; i++) {
			FLASH_XFER_INIT_READ (xfer, FLASH_CMD_SFDP,
				sizeof (struct spi_flash_sfdp_header) + (i * hdr_size), 1, 0, (uint8_t*) &sfdp_data,
				hdr_size, 0);
			status = sfdp->flash->xfer (sfdp->flash, &xfer);
			if (status != 0) {
				platform_printf ("Failed to read parameter header: 0x%x" NEWLINE, status);
				break;
			}

			platform_printf ("%d%s Param Hdr: 0x%08lx" NEWLINE, i + 2,
				(i == 0) ? "nd" : ((i == 1) ? "rd" : "th"), (long unsigned int) sfdp_data[0]);
			platform_printf ("               0x%08lx" NEWLINE, (long unsigned int) sfdp_data[1]);
		}
		platform_printf (NEWLINE);
	}
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
	const struct spi_flash_sfdp *sfdp)
{
	struct flash_xfer xfer;
	size_t length;
	int status;

	if ((table == NULL) || (sfdp == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	memset (table, 0, sizeof (struct spi_flash_sfdp_basic_table));

	length = min (sfdp->sfdp_header.parameter0.length * 4, sizeof (table->data));
	FLASH_XFER_INIT_READ (xfer, FLASH_CMD_SFDP,
		SPI_FLASH_SFDP_PARAMETER_PTR (sfdp->sfdp_header.parameter0), 1, 0, (uint8_t*) table->data,
		length, 0);
	status = sfdp->flash->xfer (sfdp->flash, &xfer);
	if (status != 0) {
		return status;
	}

	table->sfdp = sfdp;

	return 0;
}

/**
 * Release the resources used by a SFDP basic parameter table.
 *
 * @param table The table to release.
 */
void spi_flash_sfdp_basic_table_release (struct spi_flash_sfdp_basic_table *table)
{
	UNUSED (table);
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
int spi_flash_sfdp_get_device_capabilities (const struct spi_flash_sfdp_basic_table *table,
	uint32_t *capabilities)
{
	struct spi_flash_sfdp_basic_parameter_table_1_0 *params;

	if ((table == NULL) || (capabilities == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	params = (struct spi_flash_sfdp_basic_parameter_table_1_0*) table->data;
	*capabilities = 0;

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_2) {
		*capabilities |= FLASH_CAP_DUAL_1_1_2;
	}
	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_2_2) {
		*capabilities |= FLASH_CAP_DUAL_1_2_2;
	}
	if (params->dpi_qpi & SPI_FLASH_SFDP_SUPPORTS_2_2_2) {
		*capabilities |= FLASH_CAP_DUAL_2_2_2;
	}

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_4) {
		*capabilities |= FLASH_CAP_QUAD_1_1_4;
	}
	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_4_4) {
		*capabilities |= FLASH_CAP_QUAD_1_4_4;
	}
	if (params->dpi_qpi & SPI_FLASH_SFDP_SUPPORTS_4_4_4) {
		*capabilities |= FLASH_CAP_QUAD_4_4_4;
	}

	if ((table->sfdp->vendor == FLASH_ID_WINBOND) &&
		(FLASH_ID_DEVICE_SERIES (table->sfdp->device) == FLASH_ID_W25Q)) {
		/* Winbond W25Q series devices falsely report support for 4-4-4 read mode.  This mode is
		 * only available in the W25Q-DTR series. */
		*capabilities &= ~FLASH_CAP_QUAD_4_4_4;
	}

	switch (params->dspi_qspi & SPI_FLASH_SFDP_ADDRESS_BYTES) {
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
int spi_flash_sfdp_get_device_size (const struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_0 *params;

	if (table == NULL) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	params = (struct spi_flash_sfdp_basic_parameter_table_1_0*) table->data;

	if (!(params->memory_density & SPI_FLASH_SFDP_4GB_DENSITY)) {
		return (params->memory_density + 1) / 8;
	}
	else {
		int factor = (params->memory_density & (~SPI_FLASH_SFDP_4GB_DENSITY)) - 3;

		if (factor < 31) {
			return 1U << factor;
		}
		else {
			return SPI_FLASH_SFDP_LARGE_DEVICE;
		}
	}
}

/**
 * Get the maximum number of bytes that can programmed at a time.
 *
 * @param table The basic parameters table that will be queried.
 *
 * @return The device page size or an error code.
 */
int spi_flash_sfdp_get_page_size (const struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;
	int page = 256;

	if (table == NULL) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	if (table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
		page = 1U << SPI_FLASH_SFDP_PAGE_SIZE (params->page_size);
	}

	return page;
}

/**
 * Parse read command information from the SFDP table.
 *
 * @param cmd The read command to parse.
 * @param opcode The opcode used by the device for this command.
 * @param dummy_clocks The number of dummy clocks for the command.
 * @param clocks_per_byte The number of clocks for each dummy byte.
 */
static void spi_flash_sfdp_parse_read_command (struct spi_flash_sfdp_read_cmd *cmd,
	uint8_t opcode, uint8_t dummy_clocks, uint8_t clocks_per_byte)
{
	uint8_t partial_byte;

	cmd->opcode = opcode;
	cmd->mode_bytes = SPI_FLASH_SFDP_MODE_CLKS (dummy_clocks);
	cmd->dummy_bytes = SPI_FLASH_SFDP_DUMMY_CLKS (dummy_clocks);

	partial_byte = clocks_per_byte - (cmd->mode_bytes % clocks_per_byte);
	if (partial_byte != clocks_per_byte) {
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
int spi_flash_sfdp_get_read_commands (const struct spi_flash_sfdp_basic_table *table,
	struct spi_flash_sfdp_read_commands *read)
{
	struct spi_flash_sfdp_basic_parameter_table_1_0 *params;

	if ((table == NULL) || (read == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	params = (struct spi_flash_sfdp_basic_parameter_table_1_0*) table->data;
	memset (read, 0, sizeof (struct spi_flash_sfdp_read_commands));

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_2) {
		spi_flash_sfdp_parse_read_command (&read->dual_1_1_2, params->opcode_1_1_2,
			params->dummy_1_1_2, 8);
	}

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_2_2) {
		spi_flash_sfdp_parse_read_command (&read->dual_1_2_2, params->opcode_1_2_2,
			params->dummy_1_2_2, 4);
	}

	if (params->dpi_qpi & SPI_FLASH_SFDP_SUPPORTS_2_2_2) {
		spi_flash_sfdp_parse_read_command (&read->dual_2_2_2, params->opcode_2_2_2,
			params->dummy_2_2_2, 4);
	}

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_1_4) {
		spi_flash_sfdp_parse_read_command (&read->quad_1_1_4, params->opcode_1_1_4,
			params->dummy_1_1_4, 8);
	}

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_1_4_4) {
		spi_flash_sfdp_parse_read_command (&read->quad_1_4_4, params->opcode_1_4_4,
			params->dummy_1_4_4, 2);
	}

	if (params->dspi_qspi & SPI_FLASH_SFDP_SUPPORTS_4_4_4) {
		spi_flash_sfdp_parse_read_command (&read->quad_4_4_4, params->opcode_4_4_4,
			params->dummy_4_4_4, 2);
	}

	if ((table->sfdp->vendor == FLASH_ID_WINBOND) &&
		(FLASH_ID_DEVICE_SERIES (table->sfdp->device) == FLASH_ID_W25Q)) {
		/* Winbond W25Q series devices falsely report support for the 4-4-4 read command.  This
		 * command is only available in the W25Q-DTR series. */
		memset (&read->quad_4_4_4, 0, sizeof (read->quad_4_4_4));
	}

	return 0;
}

/**
 * Indicate if the flash state should be queried the busy bit in the Flag Status Register instead of
 * the WIP bit in the Status Register.
 *
 * @param table The basic parameters table that will be queried for status polling mechanism.
 *
 * @return true if Flag Status Register should be used.
 */
bool spi_flash_sfdp_use_busy_flag_status (const struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;

	if ((table != NULL) && table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
		if (params->status_reg & SPI_FLASH_SFDP_BUSY_SR_WIP) {
			return false;
		}
		else {
			return true;
		}
	}
	else {
		return false;
	}
}

/**
 * Indicate if the main status register should be written using the volatile (0x50) or non-volatile
 * (0x06) write enable command.
 *
 * @param table The basic parameters table that will be queried for status write enable.
 *
 * @return true if the volatile write enable should be used for status register writes.
 */
bool spi_flash_sfdp_use_volatile_write_enable (const struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;

	if ((table != NULL) && table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
		if (params->sr_write_enable ==
			(SPI_FLASH_SFDP_SR_WE_RESERVED | SPI_FLASH_SFDP_VOLATILE_SR_50)) {
			return true;
		}
		else {
			return false;
		}
	}
	else {
		return false;
	}
}

/**
 * Indicate if the device supports a dedicated 4-byte address instruction set.
 *
 * @param table The basic parameter table that will be queried for command support.
 *
 * @return true if the device supports dedicated 4-byte address commands.
 */
bool spi_flash_sfdp_supports_4byte_commands (const struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;
	bool opcodes_4b = false;

	if (table != NULL) {
		if ((table->sfdp->vendor == FLASH_ID_MACRONIX) &&
			(FLASH_ID_DEVICE_SERIES (table->sfdp->device) == FLASH_ID_MX25L)) {
			/* SFDP tables can't be used for the Macronix MX25L series.  Earlier devices
			 * (e.g. MX25L25635F) don't support version 1.5, and at least some newer ones
			 * (e.g. MX25L25645G) don't correctly report support for 4-byte commands. */
			if (FLASH_ID_DEVICE_CAPACITY (table->sfdp->device) >= 0x19) {
				/* Only indicate 4-byte command support for >=256Mb devices. */
				opcodes_4b = true;
			}
		}
		else if (table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
			params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
			if (params->enter_4b & SPI_FLASH_SFDP_4B_OPCODES) {
				opcodes_4b = true;
			}
		}
	}

	return opcodes_4b;
}

/**
 * Get the method to use to enter and exit 4-byte address mode.
 *
 * @param table The basic parameter table that will be queried.
 * @param addr_4byte Output for the method supported by the device.
 *
 * @return 0 if the switching method was successfully determined or an error code.
 */
int spi_flash_sfdp_get_4byte_mode_switch (const struct spi_flash_sfdp_basic_table *table,
	enum spi_flash_sfdp_4byte_addressing *addr_4byte)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;

	if ((table == NULL) || (addr_4byte == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
	if (table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		if ((params->enter_4b & 0x7f) == 0) {
			*addr_4byte = SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED;
		}
		else if ((params->enter_4b & SPI_FLASH_SFDP_4B_ENTER_B7) &&
			(params->reset_exit_4b & SPI_FLASH_SFDP_4B_EXIT_E9)) {
			*addr_4byte = SPI_FLASH_SFDP_4BYTE_MODE_COMMAND;
		}
		else if ((params->enter_4b & SPI_FLASH_SFDP_4B_ENTER_06_B7) &&
			(params->reset_exit_4b & SPI_FLASH_SFDP_4B_EXIT_06_E9)) {
			*addr_4byte = SPI_FLASH_SFDP_4BYTE_MODE_COMMAND_WRITE_ENABLE;
		}
		else {
			return SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE;
		}
	}
	else if ((params->table_1_0.dspi_qspi & SPI_FLASH_SFDP_ADDRESS_BYTES) ==
		SPI_FLASH_SFDP_3BYTE_4BYTE) {
		/* Assume older devices that support 4-byte addressing support a command to switch modes. */
		*addr_4byte = SPI_FLASH_SFDP_4BYTE_MODE_COMMAND;
	}
	else {
		*addr_4byte = SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED;
	}

	return 0;
}

/**
 * Indicate if a device reverts back to 3-byte addressing on soft reset.
 *
 * @param table The basic parameters table that will be queried.
 *
 * @return true if the device will revert on reset or false if not.
 */
bool spi_flash_sfdp_exit_4byte_mode_on_reset (const struct spi_flash_sfdp_basic_table *table)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;
	bool revert = true;		// Assume a device will revert unless SFDP explicitly says otherwise.

	if ((table != NULL) && table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
		revert = !!(params->reset_exit_4b & SPI_FLASH_SFDP_4B_EXIT_SW_RESET);
	}

	return revert;
}

/**
 * Get the method to use for enable QSPI mode.
 *
 * @param table The basic parameters table that will be queried.
 * @param quad_enable Output for the QSPI enable mode.
 *
 * @return 0 if the enable mode was determined successfully or an error code.
 */
int spi_flash_sfdp_get_quad_enable (const struct spi_flash_sfdp_basic_table *table,
	enum spi_flash_sfdp_quad_enable *quad_enable)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;
	int quad;
	uint32_t caps;

	if ((table == NULL) || (quad_enable == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	if (table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;
		quad = SPI_FLASH_SFDP_QER (params->quad_enable);

		switch (quad) {
			case SPI_FLASH_SFDP_QER_RESERVED1:
			case SPI_FLASH_SFDP_QER_RESERVED2:
				return SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN;

			case SPI_FLASH_SFDP_QER_NO_QUAD_ENABLE:
				if (params->quad_enable & SPI_FLASH_SFDP_HOLD_RST_DISABLE) {
					quad = SPI_FLASH_SFDP_QUAD_NO_QE_HOLD_DISABLE;
				}
				break;
		}
	}
	else {
		/* For older tables without this information, use device ID and capabilities to determine
		 * the quad enable method. */
		spi_flash_sfdp_get_device_capabilities (table, &caps);
		if (caps & (FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_4_4_4)) {
			switch (table->sfdp->vendor) {
				case FLASH_ID_MACRONIX:
					quad = SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1;
					break;

				default:
					return SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN;
			}
		}
		else {
			quad = SPI_FLASH_SFDP_QUAD_NO_QE_BIT;
		}
	}

	*quad_enable = (enum spi_flash_sfdp_quad_enable) quad;
	return 0;
}

/**
 * Get the command used to execute a soft reset of the device.
 *
 * @param table The basic parameters table that will be queried.
 * @param reset Output for the reset command.  If the command requires the 66/99 sequence, only 66
 * will be returned.  This will be 0 if reset is not supported.
 *
 * @return 0 if the reset command was retrieved successfully or an error code.
 */
int spi_flash_sfdp_get_reset_command (const struct spi_flash_sfdp_basic_table *table,
	uint8_t *reset)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;
	uint8_t command = FLASH_CMD_RST;
	int status = 0;

	if ((table == NULL) || (reset == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	if (table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;

		if (params->reset_exit_4b & SPI_FLASH_SFDP_RST_66_99) {
			command = FLASH_CMD_RST;
		}
		else if (params->reset_exit_4b & SPI_FLASH_SFDP_RST_F0) {
			command = FLASH_CMD_ALT_RST;
		}
		else {
			command = 0;
			status = SPI_FLASH_SFDP_RESET_NOT_SUPPORTED;
		}
	}

	*reset = command;
	return status;
}

/**
 * Get the commands used to enter and exit deep power down mode of the device.
 *
 * @param table The basic parameters table that will be queried.
 * @param enter Output for the enter deep power down command.  This will be set to 0 if this mode is
 * not supported by the device.
 * @param exit Output for the exit deep power down command.  This will be set to 0 if this mode is
 * not supported by the device.
 *
 * @return 0 if the power down commands were retrieved successfully or an error code.
 */
int spi_flash_sfdp_get_deep_powerdown_commands (const struct spi_flash_sfdp_basic_table *table,
	uint8_t *enter, uint8_t *exit)
{
	struct spi_flash_sfdp_basic_parameter_table_1_5 *params;
	uint8_t cmd_enter = 0;
	uint8_t cmd_exit = 0;
	int status = 0;

	if ((table == NULL) || (enter == NULL) || (exit == NULL)) {
		return SPI_FLASH_SFDP_INVALID_ARGUMENT;
	}

	if (table->sfdp->sfdp_header.parameter0.minor_revision >= 5) {
		params = (struct spi_flash_sfdp_basic_parameter_table_1_5*) table->data;

		if (!SPI_FLASH_SFDP_PWRDWN_NO_SUPPORT (params->deep_powerdown)) {
			cmd_enter = SPI_FLASH_SFDP_PWRDWN_ENTER (params->deep_powerdown);
			cmd_exit = SPI_FLASH_SFDP_PWRDWN_EXIT (params->deep_powerdown);
		}
		else {
			status = SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED;
		}
	}
	else {
		switch (table->sfdp->vendor) {
			case FLASH_ID_MACRONIX:
				cmd_enter = FLASH_CMD_DP;
				cmd_exit = FLASH_CMD_RDP;
				break;

			default:
				status = SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED;
				break;
		}
	}

	*enter = cmd_enter;
	*exit = cmd_exit;
	return status;
}

/**
 * Print the contents of the basic parameters table.
 *
 * @param table The basic parameters table to print.
 */
void spi_flash_sfdp_dump_basic_table (const struct spi_flash_sfdp_basic_table *table)
{
	const uint32_t *sfdp_data;
	int i;

	if (table) {
		sfdp_data = table->data;
		platform_printf ("Basic Flash Parameter Table:" NEWLINE);
		for (i = 0; i < table->sfdp->sfdp_header.parameter0.length; i++) {
			platform_printf ("  DWORD %2d: 0x%08lx" NEWLINE, i + 1,
				(long unsigned int) sfdp_data[i]);
		}
		platform_printf (NEWLINE);
	}
}
