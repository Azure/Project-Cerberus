// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_MASTER_MOCK_H_
#define FLASH_MASTER_MOCK_H_

#include <stdint.h>
#include <stddef.h>
#include "flash/flash_master.h"
#include "flash/flash_util.h"
#include "mock.h"


/**
 * Global variable to use for responding to status register requests.  This indicates no write in
 * progress.
 */
extern const uint8_t WIP_STATUS;

/**
 * A mock for the flash master API.
 */
struct flash_master_mock {
	struct flash_master base;					/**< The base flash master instance. */
	struct mock mock;							/**< The base mock instance. */
	uint8_t blank[FLASH_VERIFICATION_BLOCK];	/**< Blank flash data. */
};


int flash_master_mock_init (struct flash_master_mock *mock);
void flash_master_mock_release (struct flash_master_mock *mock);

int flash_master_mock_validate_and_release (struct flash_master_mock *mock);

int flash_master_mock_expect_xfer (struct flash_master_mock *mock, intptr_t return_val,
	struct flash_xfer xfer);
int flash_master_mock_expect_tx_xfer (struct flash_master_mock *mock, intptr_t return_val,
	struct flash_xfer xfer);
int flash_master_mock_expect_tx_xfer_ext (struct flash_master_mock *mock, intptr_t return_val,
	bool is_tmp, struct flash_xfer xfer);
int flash_master_mock_expect_rx_xfer (struct flash_master_mock *mock, intptr_t return_val,
	const uint8_t *rx_data, size_t rx_length, struct flash_xfer xfer);
int flash_master_mock_expect_rx_xfer_ext (struct flash_master_mock *mock, intptr_t return_val,
	const uint8_t *rx_data, size_t rx_length, bool is_tmp, struct flash_xfer xfer);

int flash_master_mock_expect_blank_check (struct flash_master_mock *mock, uint32_t start,
	size_t length);
int flash_master_mock_expect_blank_check_4byte (struct flash_master_mock *mock, uint32_t start,
	size_t length);
int flash_master_mock_expect_blank_check_4byte_explicit (struct flash_master_mock *mock,
	uint32_t start, size_t length);
int flash_master_mock_expect_value_check (struct flash_master_mock *mock, uint32_t start,
	size_t length, uint8_t value);
int flash_master_mock_expect_value_check_4byte (struct flash_master_mock *mock, uint32_t start,
	size_t length, uint8_t value);
int flash_master_mock_expect_value_check_4byte_explicit (struct flash_master_mock *mock,
	uint32_t start, size_t length, uint8_t value);
int flash_master_mock_expect_erase_flash (struct flash_master_mock *mock, uint32_t addr);
int flash_master_mock_expect_erase_flash_4byte (struct flash_master_mock *mock, uint32_t addr);
int flash_master_mock_expect_erase_flash_4byte_explicit (struct flash_master_mock *mock,
	uint32_t addr);
int flash_master_mock_expect_erase_flash_sector (struct flash_master_mock *mock, uint32_t addr);
int flash_master_mock_expect_erase_flash_sector_4byte (struct flash_master_mock *mock,
	uint32_t addr);
int flash_master_mock_expect_erase_flash_sector_4byte_explicit (struct flash_master_mock *mock,
	uint32_t addr);
int flash_master_mock_expect_erase_flash_verify (struct flash_master_mock *mock, uint32_t addr,
	size_t length);
int flash_master_mock_expect_erase_flash_verify_4byte (struct flash_master_mock *mock,
	uint32_t addr, size_t length);
int flash_master_mock_expect_erase_flash_verify_4byte_explicit (struct flash_master_mock *mock,
	uint32_t addr, size_t length);
int flash_master_mock_expect_erase_flash_sector_verify (struct flash_master_mock *mock,
	uint32_t addr, size_t length);
int flash_master_mock_expect_erase_flash_sector_verify_4byte (struct flash_master_mock *mock,
	uint32_t addr, size_t length);
int flash_master_mock_expect_erase_flash_sector_verify_4byte_explicit (
	struct flash_master_mock *mock, uint32_t addr, size_t length);
int flash_master_mock_expect_chip_erase (struct flash_master_mock *mock);

int flash_master_mock_expect_copy_page (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify);
int flash_master_mock_expect_copy_page_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify);
int flash_master_mock_expect_copy_page_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify);
int flash_master_mock_expect_copy_page_verify (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length);
int flash_master_mock_expect_copy_page_verify_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length);
int flash_master_mock_expect_copy_page_verify_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length);
int flash_master_mock_expect_copy_flash (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify);
int flash_master_mock_expect_copy_flash_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify);
int flash_master_mock_expect_copy_flash_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint8_t verify);
int flash_master_mock_expect_copy_flash_verify (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length);
int flash_master_mock_expect_copy_flash_verify_4byte (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length);
int flash_master_mock_expect_copy_flash_verify_4byte_explicit (struct flash_master_mock *mock_dest,
	struct flash_master_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length);
int flash_master_mock_expect_verify_flash (struct flash_master_mock *mock, uint32_t start,
	const uint8_t *data, size_t length);
int flash_master_mock_expect_verify_flash_4byte (struct flash_master_mock *mock, uint32_t start,
	const uint8_t *data, size_t length);
int flash_master_mock_expect_verify_flash_4byte_explicit (struct flash_master_mock *mock,
	uint32_t start, const uint8_t *data, size_t length);
int flash_master_mock_expect_write (struct flash_master_mock *flash, uint32_t address,
	const uint8_t *data, size_t length);
int flash_master_mock_expect_write_4byte (struct flash_master_mock *flash, uint32_t address,
	const uint8_t *data, size_t length);
int flash_master_mock_expect_write_4byte_explicit (struct flash_master_mock *flash,
	uint32_t address, const uint8_t *data, size_t length);
int flash_master_mock_expect_write_ext (struct flash_master_mock *flash, uint32_t address,
	const uint8_t *data, size_t length, bool is_tmp, uint8_t addr4);
int flash_master_mock_expect_verify_copy (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t src_addr, uint32_t check_addr,
	const uint8_t *data, const uint8_t *check_data, size_t length);
int flash_master_mock_expect_verify_copy_4byte (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t src_addr, uint32_t check_addr,
	const uint8_t *data, const uint8_t *check_data, size_t length);
int flash_master_mock_expect_verify_copy_4byte_explicit (struct flash_master_mock *mock_src,
	struct flash_master_mock *mock_check, uint32_t src_addr, uint32_t check_addr,
	const uint8_t *data, const uint8_t *check_data, size_t length);


/**
 * Helper to define an expected command with only a command code.
 */
#define	FLASH_EXP_OPCODE(code)	(struct flash_xfer) {\
	.cmd = code, \
	.address = 0, \
	.dummy_bytes = 0, \
	.mode_bytes = 0, \
	.data = NULL, \
	.length = 0, \
	.flags = FLASH_FLAG_NO_ADDRESS \
}

/**
 * Helper to define an expected register read command.
 */
#define	FLASH_EXP_READ_REG(code, len)	(struct flash_xfer) {\
	.cmd = code, \
	.address = 0, \
	.dummy_bytes = 0, \
	.mode_bytes = 0, \
	.data = (void*) -1, \
	.length = len, \
	.flags = FLASH_FLAG_NO_ADDRESS \
}

/**
 * Helper to define an expected status register read.
 */
#define	FLASH_EXP_READ_STATUS_REG		FLASH_EXP_READ_REG (0x05, 1)

/**
 * Helper to define an expected flag status register read.
 */
#define	FLASH_EXP_READ_FLAG_STATUS_REG	FLASH_EXP_READ_REG (0x70, 1)

/**
 * Helper to define an expected write enable command.
 */
#define	FLASH_EXP_WRITE_ENABLE			FLASH_EXP_OPCODE (0x06)

/**
 * Helper to define an expected command to read data with any configuration.
 */
#define	FLASH_EXP_READ_EXT_CMD(code, addr, dummy, mode, buf, len, flag_in)	(struct flash_xfer) {\
	.cmd = code, \
	.address = addr, \
	.dummy_bytes = dummy, \
	.mode_bytes = mode, \
	.data = (void*) (buf), \
	.length = len, \
	.flags = flag_in \
}

/**
 * Helper to define an expected command to read data.
 */
#define	FLASH_EXP_READ_CMD(code, addr, dummy, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, 0, buf, len, 0)

/**
 * Helper to define an expected command to read data in 1-1-2 mode.
 */
#define FLASH_EXP_1_1_2_READ_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_DUAL_DATA)

/**
 * Helper to define an expected command to read data in 1-2-2 mode.
 */
#define FLASH_EXP_1_2_2_READ_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_DUAL_DATA | FLASH_FLAG_DUAL_ADDR)

/**
 * Helper to define an expected command to read data in 2-2-2 mode.
 */
#define FLASH_EXP_2_2_2_READ_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mod, buf, len, FLASH_FLAG_DUAL_DATA | FLASH_FLAG_DUAL_ADDR | FLASH_FLAG_DUAL_CMD)

/**
 * Helper to define an expected command to read data in 1-1-4 mode.
 */
#define FLASH_EXP_1_1_4_READ_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_QUAD_DATA)

/**
 * Helper to define an expected command to read data in 1-4-4 mode.
 */
#define FLASH_EXP_1_4_4_READ_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_QUAD_DATA | FLASH_FLAG_QUAD_ADDR)

/**
 * Helper to define an expected command to read data in 4-4-4 mode.
 */
#define FLASH_EXP_4_4_4_READ_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_QUAD_DATA | FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_CMD)

/**
 * Helper to define an expected register write command.
 */
#define	FLASH_EXP_WRITE_REG(code, buf, len)	(struct flash_xfer) {\
	.cmd = code, \
	.address = 0, \
	.dummy_bytes = 0, \
	.mode_bytes = 0, \
	.data = (void*) (buf), \
	.length = len, \
	.flags = (FLASH_FLAG_NO_ADDRESS | FLASH_FLAG_DATA_TX) \
}

/**
 * Helper to define an expected command to write data with any configuration.
 */
#define	FLASH_EXP_WRITE_EXT_CMD(code, addr, dummy, mode, buf, len, flag_in)	(struct flash_xfer) {\
	.cmd = code, \
	.address = addr, \
	.dummy_bytes = dummy, \
	.mode_bytes = mode, \
	.data = (void*) (buf), \
	.length = len, \
	.flags = flag_in | FLASH_FLAG_DATA_TX \
}

/**
 * Helper to define an expected command to write data.
 */
#define	FLASH_EXP_WRITE_CMD(code, addr, dummy, buf, len)	\
	FLASH_EXP_WRITE_EXT_CMD (code, addr, dummy, 0, buf, len, 0)

/**
 * Helper to define an expected command to erase data.
 */
#define	FLASH_EXP_ERASE_CMD(code, addr)	(struct flash_xfer) {\
	.cmd = code, \
	.address = addr, \
	.dummy_bytes = 0, \
	.mode_bytes = 0, \
	.data = NULL, \
	.length = 0, \
	.flags = 0 \
}

/**
 * Helper to define an expected command to read data with 4 byte address.
 */
#define	FLASH_EXP_READ_EXT_4B_CMD(code, addr, dummy, mode, buf, len, flags) \
	FLASH_EXP_READ_EXT_CMD (code, addr, dummy, mode, buf, len, flags | FLASH_FLAG_4BYTE_ADDRESS)

/**
 * Helper to define an expected command to read data with 4 byte address.
 */
#define	FLASH_EXP_READ_4B_CMD(code, addr, dummy, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, 0, buf, len, 0)

/**
 * Helper to define an expected command to read data with 4 byte address in 1-1-2 mode.
 */
#define FLASH_EXP_1_1_2_READ_4B_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_DUAL_DATA)

/**
 * Helper to define an expected command to read data with 4 byte address in 1-2-2 mode.
 */
#define FLASH_EXP_1_2_2_READ_4B_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_DUAL_DATA | FLASH_FLAG_DUAL_ADDR)

/**
 * Helper to define an expected command to read data with 4 byte address in 2-2-2 mode.
 */
#define FLASH_EXP_2_2_2_READ_4B_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_DUAL_DATA | FLASH_FLAG_DUAL_ADDR | FLASH_FLAG_DUAL_CMD)

/**
 * Helper to define an expected command to read data with 4 byte address in 1-1-4 mode.
 */
#define FLASH_EXP_1_1_4_READ_4B_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_QUAD_DATA)

/**
 * Helper to define an expected command to read data with 4 byte address in 1-4-4 mode.
 */
#define FLASH_EXP_1_4_4_READ_4B_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_QUAD_DATA | FLASH_FLAG_QUAD_ADDR)

/**
 * Helper to define an expected command to read data with 4 byte address in 4-4-4 mode.
 */
#define FLASH_EXP_4_4_4_READ_4B_CMD(code, addr, dummy, mode, buf, len) \
	FLASH_EXP_READ_EXT_4B_CMD (code, addr, dummy, mode, buf, len, FLASH_FLAG_QUAD_DATA | FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_CMD)

/**
 * Helper to define an expected command to write data with 4 byte address.
 */
#define	FLASH_EXP_WRITE_4B_CMD(code, addr, dummy, buf, len)	\
	FLASH_EXP_WRITE_EXT_CMD (code, addr, dummy, 0, buf, len, FLASH_FLAG_4BYTE_ADDRESS)

/**
 * Helper to define an expected command to erase data with 4 byte address.
 */
#define	FLASH_EXP_ERASE_4B_CMD(code, addr)	(struct flash_xfer) {\
	.cmd = code, \
	.address = addr, \
	.dummy_bytes = 0, \
	.mode_bytes = 0, \
	.data = NULL, \
	.length = 0, \
	.flags = FLASH_FLAG_4BYTE_ADDRESS \
}


#endif /* FLASH_MASTER_MOCK_H_ */
