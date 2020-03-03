// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/spi_flash_sfdp.h"
#include "mock/flash_master_mock.h"


static const char *SUITE = "spi_flash_sfdp";


/**
 * Initialize expectations for initializing the SFDP interface.
 *
 * @param test The test framework.
 * @param flash The flash mock to set the expectations on.
 * @param header The header data to return.
 */
static void spi_flash_sfdp_testing_init_expectations (CuTest *test, struct flash_master_mock *flash,
	uint32_t *header)
{
	int status;
	int header_length = sizeof (uint32_t) * 4;

	status = flash_master_mock_expect_rx_xfer (flash, 0, (uint8_t*) header, header_length,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, header_length));

	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void spi_flash_sfdp_test_init (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_init_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (NULL, &flash.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_init (&sfdp, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_sfdp_test_init_header_error (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, 16));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_sfdp_test_init_bad_header_signature (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444663,
		0xff000106,
		0x10010600,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_sfdp_test_init_bad_header (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0x7f000106,
		0x10010600,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_BAD_HEADER, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_sfdp_test_init_bad_header_parameter_table (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010681,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_BAD_HEADER, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_sfdp_test_release_null (CuTest *test)
{
	TEST_START;

	spi_flash_sfdp_release (NULL);
}

static void spi_flash_sfdp_test_basic_table_init (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_basic_table_init_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (NULL, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_basic_table_init (&table, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_basic_table_init_flash_error (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, 36));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_basic_table_release_null (CuTest *test)
{
	TEST_START;

	spi_flash_sfdp_basic_table_release (NULL);
}

static void spi_flash_sfdp_test_get_device_capabilities_mx25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_mx1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8120e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_3BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000105,
		0x10010500,
		0xff000080
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9,
	};
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000080, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* The SFDP table from this device reports QPI and DTR support even though the device does not
	 * actually support these modes.  These are supported by the W25Q16JV-DTR part. */
	expected = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_supports_dpi (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_spi_only (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_3BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_4byte_only (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff520e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_4BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	uint32_t capabilities;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_capabilities (NULL, &capabilities);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_device_capabilities (&table, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_size_mx25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (&table);
	CuAssertIntEquals (test, (32 * 1024 * 1024), status);	// 32MB (256Mb)

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_size_mx1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8120e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (&table);
	CuAssertIntEquals (test, (2 * 1024 * 1024), status);	// 2MB (16Mb)

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_size_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000105,
		0x10010500,
		0xff000080
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9,
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000080, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (&table);
	CuAssertIntEquals (test, (2 * 1024 * 1024), status);	// 2MB (16Mb)

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_size_8gb (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x80000021,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (&table);
	CuAssertIntEquals (test, (1 * 1024 * 1024 * 1024), status);	// 1GB (8Gb)

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_size_16gb (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x80000022,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (&table);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_LARGE_DEVICE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_size_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_mx25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_read_commands (&table, &read);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x3b, read.dual_1_1_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_1_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.mode_bytes);

	CuAssertIntEquals (test, 0xbb, read.dual_1_2_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.dual_2_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.mode_bytes);

	CuAssertIntEquals (test, 0x6b, read.quad_1_1_4.opcode);
	CuAssertIntEquals (test, 1, read.quad_1_1_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_1_4_4.opcode);
	CuAssertIntEquals (test, 2, read.quad_1_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_1_4_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 2, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_mx1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8120e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_read_commands (&table, &read);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x3b, read.dual_1_1_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_1_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.dual_1_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.dual_2_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.quad_1_1_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.mode_bytes);

	CuAssertIntEquals (test, 0, read.quad_1_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_1_4_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_4_4.mode_bytes);

	CuAssertIntEquals (test, 0, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000105,
		0x10010500,
		0xff000080
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9,
	};
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000080, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	/* The SFDP table from this device reports QPI and DTR support even though the device does not
	 * actually support these modes.  These are supported by the W25Q16JV-DTR part. */
	status = spi_flash_sfdp_get_read_commands (&table, &read);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x3b, read.dual_1_1_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_1_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.mode_bytes);

	CuAssertIntEquals (test, 0xbb, read.dual_1_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.dummy_bytes);
	CuAssertIntEquals (test, 1, read.dual_1_2_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.dual_2_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.mode_bytes);

	CuAssertIntEquals (test, 0x6b, read.quad_1_1_4.opcode);
	CuAssertIntEquals (test, 1, read.quad_1_1_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_1_4_4.opcode);
	CuAssertIntEquals (test, 2, read.quad_1_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_1_4_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_supports_dpi (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xba08ffff,
		0xea46ffff,
		0x520f200c,
		0xff00d810
	};
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_read_commands (&table, &read);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x3b, read.dual_1_1_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_1_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.mode_bytes);

	CuAssertIntEquals (test, 0xbb, read.dual_1_2_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.mode_bytes);

	CuAssertIntEquals (test, 0xba, read.dual_2_2_2.opcode);
	CuAssertIntEquals (test, 2, read.dual_2_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.mode_bytes);

	CuAssertIntEquals (test, 0x6b, read.quad_1_1_4.opcode);
	CuAssertIntEquals (test, 1, read.quad_1_1_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_1_4_4.opcode);
	CuAssertIntEquals (test, 2, read.quad_1_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_1_4_4.mode_bytes);

	CuAssertIntEquals (test, 0xea, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 3, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_spi_only (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_read_commands (&table, &read);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0, read.dual_1_1_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.dual_1_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_1_2_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.dual_2_2_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.dummy_bytes);
	CuAssertIntEquals (test, 0, read.dual_2_2_2.mode_bytes);

	CuAssertIntEquals (test, 0, read.quad_1_1_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.mode_bytes);

	CuAssertIntEquals (test, 0, read.quad_1_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_1_4_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_1_4_4.mode_bytes);

	CuAssertIntEquals (test, 0, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfff320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000010, 1, -1, sizeof (params)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_read_commands (NULL, &read);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_read_commands (&table, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}


CuSuite* get_spi_flash_sfdp_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_init);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_init_null);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_init_header_error);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_init_bad_header_signature);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_init_bad_header);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_init_bad_header_parameter_table);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_release_null);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_basic_table_init);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_basic_table_init_null);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_basic_table_init_flash_error);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_basic_table_release_null);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_mx25635f);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_mx1606e);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_w25q16jv);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_supports_dpi);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_spi_only);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_capabilities_null);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_size_mx25635f);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_size_mx1606e);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_size_w25q16jv);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_size_8gb);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_size_16gb);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_device_size_null);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_read_commands_mx25635f);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_read_commands_mx1606e);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_read_commands_w25q16jv);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_read_commands_supports_dpi);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_read_commands_spi_only);
	SUITE_ADD_TEST (suite, spi_flash_sfdp_test_get_read_commands_null);

	return suite;
}
