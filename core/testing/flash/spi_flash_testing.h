// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPI_FLASH_TESTING_H_
#define SPI_FLASH_TESTING_H_

#include <stdint.h>
#include <stddef.h>
#include "testing.h"
#include "flash/spi_flash.h"
#include "testing/mock/flash/flash_master_mock.h"


extern const uint8_t TEST_ID[FLASH_ID_LEN];
extern const uint32_t FULL_CAPABILITIES;

void spi_flash_testing_discover_params (CuTest *test, struct spi_flash *flash,
	struct spi_flash_state *state, struct flash_master_mock *mock, const uint8_t *id,
	const uint32_t *header, const uint32_t *params, size_t params_len, uint32_t params_addr,
	uint32_t capabilities);
void spi_flash_testing_discover_params_fast_read (CuTest *test, struct spi_flash *flash,
	struct spi_flash_state *state, struct flash_master_mock *mock, const uint8_t *id,
	const uint32_t *header, const uint32_t *params, size_t params_len, uint32_t params_addr,
	uint32_t capabilities);


#endif /* SPI_FLASH_TESTING_H_ */
