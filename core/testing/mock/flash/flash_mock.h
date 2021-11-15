// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef FLASH_MOCK_H_
#define FLASH_MOCK_H_

#include "flash/flash.h"
#include "flash/flash_util.h"
#include "mock.h"
#include "testing/mock/crypto/hash_mock.h"


/**
 * A mock for the flash API.
 */
struct flash_mock {
	struct flash base;							/**< The base flash API instance. */
	struct mock mock;							/**< The base mock interface. */
	uint8_t blank[FLASH_VERIFICATION_BLOCK];	/**< Blank flash data. */
};


int flash_mock_init (struct flash_mock *mock);
void flash_mock_release (struct flash_mock *mock);

int flash_mock_validate_and_release (struct flash_mock *mock);


/* Helper functions to mock flash operations based on flash_util functions. */

int flash_mock_expect_blank_check (struct flash_mock *mock, uint32_t start, size_t length);

int flash_mock_expect_erase_flash (struct flash_mock *mock, uint32_t addr, size_t length);
int flash_mock_expect_erase_flash_ext (struct flash_mock *mock, uint32_t addr, size_t length,
	uint32_t block_size);
int flash_mock_expect_erase_flash_sector (struct flash_mock *mock, uint32_t addr, size_t length);
int flash_mock_expect_erase_flash_sector_ext (struct flash_mock *mock, uint32_t addr, size_t length,
	uint32_t sector_size);

int flash_mock_expect_erase_flash_verify (struct flash_mock *mock, uint32_t addr, size_t length);
int flash_mock_expect_erase_flash_verify_ext (struct flash_mock *mock, uint32_t addr, size_t length,
	uint32_t block_size);
int flash_mock_expect_erase_flash_sector_verify (struct flash_mock *mock, uint32_t addr,
	size_t length);
int flash_mock_expect_erase_flash_sector_verify_ext (struct flash_mock *mock, uint32_t addr,
	size_t length, uint32_t sector_size);

int flash_mock_expect_copy_flash_verify (struct flash_mock *mock_dest, struct flash_mock *mock_src,
	uint32_t dest_addr, uint32_t src_addr, const uint8_t *data, size_t length);
int flash_mock_expect_copy_flash_verify_ext (struct flash_mock *mock_dest,
	struct flash_mock *mock_src, uint32_t dest_addr, uint32_t src_addr, const uint8_t *data,
	size_t length, uint32_t page_size);

int flash_mock_expect_erase_copy_verify (struct flash_mock *mock_dest, struct flash_mock *mock_src,
	uint32_t dest_addr, uint32_t src_addr, const uint8_t *data, size_t length);

int flash_mock_expect_verify_flash (struct flash_mock *mock, uint32_t start, const uint8_t *data,
	size_t length);
int flash_mock_expect_verify_flash_and_hash (struct flash_mock *mock, struct hash_engine_mock *hash,
	uint32_t start, const uint8_t *data, size_t length);
int flash_mock_expect_verify_copy (struct flash_mock *mock1, uint32_t start1, const uint8_t *data1,
	struct flash_mock *mock2, uint32_t start2, const uint8_t *data2, size_t length);


#endif /* FLASH_MOCK_H_ */
