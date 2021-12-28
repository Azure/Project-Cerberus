// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/spi_flash_sfdp.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/flash/spi_flash_sfdp_testing.h"


TEST_SUITE_LABEL ("spi_flash_sfdp");


/* Macronix flash */

/* MX25L1606E */
const uint8_t FLASH_ID_MX25L1606E[] = {0xc2, 0x20, 0x15};

const uint32_t SFDP_HEADER_MX25L1606E[] = {
	0x50444653,
	0xff010100,
	0x09010000,
	0xff000030,
	0x040100c2,
	0xff000060
};

const size_t SFDP_HEADER_MX25L1606E_LEN = sizeof (SFDP_HEADER_MX25L1606E);

const uint32_t SFDP_PARAMS_ADDR_MX25L1606E = 0x000030;

const uint32_t SFDP_PARAMS_MX25L1606E[] = {
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

const size_t SFDP_PARAMS_MX25L1606E_LEN = sizeof (SFDP_PARAMS_MX25L1606E);

/* MX25L25635F */
const uint8_t FLASH_ID_MX25L25635F[] = {0xc2, 0x20, 0x19};

const uint32_t SFDP_HEADER_MX25L25635F[] = {
	0x50444653,
	0xff010100,
	0x09010000,
	0xff000030,
	0x040100c2,
	0xff000060
};

const size_t SFDP_HEADER_MX25L25635F_LEN = sizeof (SFDP_HEADER_MX25L25635F);

const uint32_t SFDP_PARAMS_ADDR_MX25L25635F = 0x000030;

const uint32_t SFDP_PARAMS_MX25L25635F[] = {
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

const size_t SFDP_PARAMS_MX25L25635F_LEN = sizeof (SFDP_PARAMS_MX25L25635F);

/* MX25L25645G */
const uint8_t FLASH_ID_MX25L25645G[] = {0xc2, 0x20, 0x19};

const uint32_t SFDP_HEADER_MX25L25645G[] = {
	0x50444653,
	0xff020106,
	0x10010600,
	0xff000030,
	0x040100c2,
	0xff000110,
	0x02010084,
	0xff0000c0
};

const size_t SFDP_HEADER_MX25L25645G_LEN = sizeof (SFDP_HEADER_MX25L25645G);

const uint32_t SFDP_PARAMS_ADDR_MX25L25645G = 0x000030;

const uint32_t SFDP_PARAMS_MX25L25645G[] = {
	0xfffb20e5,
	0x0fffffff,
	0x6b08eb44,
	0xbb043b08,
	0xfffffffe,
	0xff00ffff,
	0xeb44ffff,
	0x520f200c,
	0xff00d810,
	0x00dd59d6,
	0xdb039f82,
	0x38670344,
	0xb030b030,
	0x5cd5bdf7,
	0xff299e4a,
	0x85f950f0
};

const size_t SFDP_PARAMS_MX25L25645G_LEN = sizeof (SFDP_PARAMS_MX25L25645G);


/* Winbond flash */

/* W25Q16JV */
const uint8_t FLASH_ID_W25Q16JV[] = {0xef, 0x40, 0x15};

const uint32_t SFDP_HEADER_W25Q16JV[] = {
	0x50444653,
	0xff000105,
	0x10010500,
	0xff000080
};

const size_t SFDP_HEADER_W25Q16JV_LEN = sizeof (SFDP_HEADER_W25Q16JV);

const uint32_t SFDP_PARAMS_ADDR_W25Q16JV = 0x000080;

const uint32_t SFDP_PARAMS_W25Q16JV[] = {
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
	0x80f830e9
};

const size_t SFDP_PARAMS_W25Q16JV_LEN = sizeof (SFDP_PARAMS_W25Q16JV);

/* W25Q256JV */
const uint8_t FLASH_ID_W25Q256JV[] = {0xef, 0x40, 0x19};

const uint32_t SFDP_HEADER_W25Q256JV[] = {
	0x50444653,
	0xff000105,
	0x10010500,
	0xff000080
};

const size_t SFDP_HEADER_W25Q256JV_LEN = sizeof (SFDP_HEADER_W25Q256JV);

const uint32_t SFDP_PARAMS_ADDR_W25Q256JV = 0x000080;

const uint32_t SFDP_PARAMS_W25Q256JV[] = {
	0xfffb20e5,
	0x0fffffff,
	0x6b08eb44,
	0xbb423b08,
	0xfffffffe,
	0x0000ffff,
	0xeb40ffff,
	0x520f200c,
	0x0000d810,
	0x00a60236,
	0xd314ea82,
	0x337663e9,
	0x757a757a,
	0x5cd5a2f7,
	0xff4df719,
	0xa5f970e9
};

const size_t SFDP_PARAMS_W25Q256JV_LEN = sizeof (SFDP_PARAMS_W25Q256JV);


/* Micron flash */

/* MT25Q256ABA */
const uint8_t FLASH_ID_MT25Q256ABA[] = {0x20, 0xba, 0x19};

const uint32_t SFDP_HEADER_MT25Q256ABA[] = {
	0x50444653,
	0xff010106,
	0x10010600,
	0xff000030,
	0x02010084,
	0xff000080
};

const size_t SFDP_HEADER_MT25Q256ABA_LEN = sizeof (SFDP_HEADER_MT25Q256ABA);

const uint32_t SFDP_PARAMS_ADDR_MT25Q256ABA = 0x000030;

const uint32_t SFDP_PARAMS_MT25Q256ABA[] = {
	0xfffb20e5,
	0x0fffffff,
	0x6b27eb29,
	0xbb273b27,
	0xffffffff,
	0xbb27ffff,
	0xeb29ffff,
	0xd810200c,
	0x0000520f,
	0x00994a24,
	0xd4038e8b,
	0x382701ac,
	0x757a757a,
	0x5cd5bdfb,
	0xff820f4a,
	0x363dbd81
};

const size_t SFDP_PARAMS_MT25Q256ABA_LEN = sizeof (SFDP_PARAMS_MT25Q256ABA);


/* Microchip flash */

/* SST26VF064B */
const uint8_t FLASH_ID_SST26VF064B[] = {0xbf, 0x26, 0x43};

const uint32_t SFDP_HEADER_SST26VF064B[] = {
	0x50444653,
	0xff020106,
	0x10010600,
	0xff000030,
	0x06010081,
	0xff000100,
	0x180100bf,
	0x01000200
};

const size_t SFDP_HEADER_SST26VF064B_LEN = sizeof (SFDP_HEADER_SST26VF064B);

const uint32_t SFDP_PARAMS_ADDR_SST26VF064B = 0x000030;

const uint32_t SFDP_PARAMS_SST26VF064B[] = {
	0xfff120fd,
	0x03ffffff,
	0x6b08eb44,
	0xbb803b08,
	0xfffffffe,
	0xff00ffff,
	0x0b44ffff,
	0xd80d200c,
	0xd810d80f,
	0x24489120,
	0x811d6f80,
	0x38770fed,
	0xb030b030,
	0xfffffff7,
	0xff5cc229,
	0x80c030f0
};

const size_t SFDP_PARAMS_SST26VF064B_LEN = sizeof (SFDP_PARAMS_SST26VF064B);


/**
 * Initialize expectations for initializing the SFDP interface.
 *
 * @param test The test framework.
 * @param flash The flash mock to set the expectations on.
 * @param header The header data to return.
 * @param id The flash device ID to report.
 */
static void spi_flash_sfdp_testing_init_expectations (CuTest *test, struct flash_master_mock *flash,
	const uint32_t *header, const uint8_t *id)
{
	int status;
	int header_length = sizeof (uint32_t) * 4;

	status = flash_master_mock_expect_rx_xfer (flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (flash, 0, (uint8_t*) header, header_length,
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
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
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

static void spi_flash_sfdp_test_init_id_error (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_init_header_error (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_xfer (&flash, FLASH_MASTER_XFER_FAILED,
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
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444663,
		0xff000106,
		0x10010600,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
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
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0x7f000106,
		0x10010600,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) header, sizeof (header),
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
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010681,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status |= flash_master_mock_expect_rx_xfer (&flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

static void spi_flash_sfdp_test_get_device_capabilities_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

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

static void spi_flash_sfdp_test_get_device_capabilities_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

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

static void spi_flash_sfdp_test_get_device_capabilities_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

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

static void spi_flash_sfdp_test_get_device_capabilities_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_1_4_4 |
		FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	expected = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_1_4_4 |
		FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	status = spi_flash_sfdp_get_device_capabilities (&table, &capabilities);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, expected, capabilities);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_device_capabilities_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

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

static void spi_flash_sfdp_test_get_device_capabilities_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint32_t capabilities;
	uint32_t expected;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

static void spi_flash_sfdp_test_get_device_size_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

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

static void spi_flash_sfdp_test_get_device_size_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

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

static void spi_flash_sfdp_test_get_device_size_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

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

static void spi_flash_sfdp_test_get_device_size_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

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

static void spi_flash_sfdp_test_get_device_size_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

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

static void spi_flash_sfdp_test_get_device_size_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

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

static void spi_flash_sfdp_test_get_device_size_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_device_size (&table);
	CuAssertIntEquals (test, (8 * 1024 * 1024), status);	// 8MB (64Mb)

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

static void spi_flash_sfdp_test_get_read_commands_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

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

static void spi_flash_sfdp_test_get_read_commands_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

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

static void spi_flash_sfdp_test_get_read_commands_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

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

static void spi_flash_sfdp_test_get_read_commands_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

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

	CuAssertIntEquals (test, 0, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

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

	CuAssertIntEquals (test, 0, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 0, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_read_commands (&table, &read);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, 0x3b, read.dual_1_1_2.opcode);
	CuAssertIntEquals (test, 0, read.dual_1_1_2.dummy_bytes);
	CuAssertIntEquals (test, 1, read.dual_1_1_2.mode_bytes);

	CuAssertIntEquals (test, 0xbb, read.dual_1_2_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_1_2_2.dummy_bytes);
	CuAssertIntEquals (test, 1, read.dual_1_2_2.mode_bytes);

	CuAssertIntEquals (test, 0xbb, read.dual_2_2_2.opcode);
	CuAssertIntEquals (test, 1, read.dual_2_2_2.dummy_bytes);
	CuAssertIntEquals (test, 1, read.dual_2_2_2.mode_bytes);

	CuAssertIntEquals (test, 0x6b, read.quad_1_1_4.opcode);
	CuAssertIntEquals (test, 0, read.quad_1_1_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_1_1_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_1_4_4.opcode);
	CuAssertIntEquals (test, 4, read.quad_1_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_1_4_4.mode_bytes);

	CuAssertIntEquals (test, 0xeb, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 4, read.quad_4_4_4.dummy_bytes);
	CuAssertIntEquals (test, 1, read.quad_4_4_4.mode_bytes);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_read_commands_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	struct spi_flash_sfdp_read_commands read;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

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

	CuAssertIntEquals (test, 0x0b, read.quad_4_4_4.opcode);
	CuAssertIntEquals (test, 2, read.quad_4_4_4.dummy_bytes);
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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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
	uint8_t id[] = {0x11, 0x22, 0x33};
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

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

static void spi_flash_sfdp_test_use_busy_flag_status_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, true, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	flag_status = spi_flash_sfdp_use_busy_flag_status (&table);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_busy_flag_status_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
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
	bool flag_status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	flag_status = spi_flash_sfdp_use_busy_flag_status (NULL);
	CuAssertIntEquals (test, false, flag_status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_volatile_only (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x80f830e4
	};
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, true, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_both_volatile_and_nv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x80f830ec
	};
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (&table);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_use_volatile_write_enable_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
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
	bool volatile_enable;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	volatile_enable = spi_flash_sfdp_use_volatile_write_enable (NULL);
	CuAssertIntEquals (test, false, volatile_enable);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, false, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, true, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, true, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, false, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, true, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, true, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	support_4byte = spi_flash_sfdp_supports_4byte_commands (&table);
	CuAssertIntEquals (test, false, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_supports_4byte_commands_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
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
	bool support_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	support_4byte = spi_flash_sfdp_supports_4byte_commands (NULL);
	CuAssertIntEquals (test, false, support_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_COMMAND, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_COMMAND, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_COMMAND, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_COMMAND_WRITE_ENABLE, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, switch_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_only_extended_addr_reg (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x84f930e4
	};
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_only_bank_reg (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x88fa30e4
	};
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_only_nv_config_reg (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x90fc30e4
	};
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x80f830e4
	};
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_4byte_mode_switch (NULL, &switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_no_exit_command (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x81f830e4
	};
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_4byte_mode_switch_no_exit_command_write_enable (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x82f830e4
	};
	enum spi_flash_sfdp_4byte_addressing switch_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_4byte_mode_switch (&table, &switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_NO_QE_BIT, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2_NO_CLR, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2_NO_CLR, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_NO_QE_HOLD_DISABLE, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2_35, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_no_qe_bit_no_hold_disable (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xff0df719,
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_NO_QE_BIT, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_bit1_sr2_with_clear (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xff1df719,
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_bit7_sr2 (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xff3df719,
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT7_SR2, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_bit1_sr2_with_35_read (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xff5df719,
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT1_SR2_35, quad);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_old_table_version_no_qspi (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xff9320e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_NO_QE_BIT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (NULL, &quad);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_quad_enable (&table, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_reserved_value_6 (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xff6df719,
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_reserved_value_7 (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xff7df719,
		0x80f830e4
	};
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_quad_enable_old_table_version_with_qspi (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
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
	enum spi_flash_sfdp_quad_enable quad;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_quad_enable (&table, &quad);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, false, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_no_revert (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5e970e9
	};
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (&table);
	CuAssertIntEquals (test, false, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_exit_4byte_mode_on_reset_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5e970e9
	};
	bool exit_4byte;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	exit_4byte = spi_flash_sfdp_exit_4byte_mode_on_reset (NULL);
	CuAssertIntEquals (test, true, exit_4byte);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_f0 (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f968e9
	};
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xf0, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_both_f0_and_66 (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f978e9
	};
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x99, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_no_soft_reset (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f940e9
	};
	uint8_t command = 0xaa;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_RESET_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_8clocks_f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f941e9
	};
	uint8_t command = 0xaa;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_RESET_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_10clocks_f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f942e9
	};
	uint8_t command = 0xaa;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_RESET_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_16clocks_f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f944e9
	};
	uint8_t command = 0xaa;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (&table, &command);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_RESET_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, command);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_reset_command_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f968e9
	};
	uint8_t command;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_reset_command (NULL, &command);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_reset_command (&table, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25645G, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 256, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_128_byte_page (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xb314ea72,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 128, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_max_page_size (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xb314eaf2,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_page_size (&table);
	CuAssertIntEquals (test, 32768, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_page_size_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
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
		0xb314ea72,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_page_size (NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_mx25l1606e (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L1606E,
		FLASH_ID_MX25L1606E);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L1606E,
		SFDP_PARAMS_MX25L1606E_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L1606E, 1, -1, SFDP_PARAMS_MX25L1606E_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xb9, enter_cmd);
	CuAssertIntEquals (test, 0xab, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_mx25l25635f (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25635F,
		FLASH_ID_MX25L25635F);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25635F,
		SFDP_PARAMS_MX25L25635F_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25635F_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xb9, enter_cmd);
	CuAssertIntEquals (test, 0xab, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_mx25l25645g (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MX25L25645G,
		FLASH_ID_MX25L25645G);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MX25L25645G,
		SFDP_PARAMS_MX25L25645G_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MX25L25635F, 1, -1,
			SFDP_PARAMS_MX25L25645G_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xb9, enter_cmd);
	CuAssertIntEquals (test, 0xab, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_w25q16jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q16JV,
		FLASH_ID_W25Q16JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q16JV,
		SFDP_PARAMS_W25Q16JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q16JV, 1, -1, SFDP_PARAMS_W25Q16JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xb9, enter_cmd);
	CuAssertIntEquals (test, 0xab, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_w25q256jv (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_W25Q256JV,
		FLASH_ID_W25Q256JV);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_W25Q256JV,
		SFDP_PARAMS_W25Q256JV_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_W25Q256JV, 1, -1, SFDP_PARAMS_W25Q256JV_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xb9, enter_cmd);
	CuAssertIntEquals (test, 0xab, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_mt25q256aba (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_MT25Q256ABA,
		FLASH_ID_MT25Q256ABA);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_MT25Q256ABA,
		SFDP_PARAMS_MT25Q256ABA_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_MT25Q256ABA, 1, -1,
			SFDP_PARAMS_MT25Q256ABA_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xb9, enter_cmd);
	CuAssertIntEquals (test, 0xab, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_sst26vf064b (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t enter_cmd = 0xaa;
	uint8_t exit_cmd = 0x55;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, SFDP_HEADER_SST26VF064B,
		FLASH_ID_SST26VF064B);

	status = spi_flash_sfdp_init (&sfdp, &flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash, 0, (uint8_t*) SFDP_PARAMS_SST26VF064B,
		SFDP_PARAMS_SST26VF064B_LEN,
		FLASH_EXP_READ_CMD (0x5a, SFDP_PARAMS_ADDR_SST26VF064B, 1, -1,
			SFDP_PARAMS_SST26VF064B_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_basic_table_init (&table, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, enter_cmd);
	CuAssertIntEquals (test, 0, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_non_standard (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x7cd7a2f7,
		0xff4df719,
		0xa5f968e9
	};
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xf9, enter_cmd);
	CuAssertIntEquals (test, 0xaf, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_not_supported (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x800000f7,
		0xff4df719,
		0xa5f968e9
	};
	uint8_t enter_cmd = 0xaa;
	uint8_t exit_cmd = 0x55;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, enter_cmd);
	CuAssertIntEquals (test, 0, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_old_table_version (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x09010000,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810
	};
	uint8_t enter_cmd = 0xaa;
	uint8_t exit_cmd = 0x55;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_PWRDOWN_NOT_SUPPORTED, status);
	CuAssertIntEquals (test, 0, enter_cmd);
	CuAssertIntEquals (test, 0, exit_cmd);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}

static void spi_flash_sfdp_test_get_deep_powerdown_commands_null (CuTest *test)
{
	struct flash_master_mock flash;
	struct spi_flash_sfdp sfdp;
	struct spi_flash_sfdp_basic_table table;
	int status;
	uint8_t id[] = {0x11, 0x22, 0x33};
	uint32_t header[] = {
		0x50444653,
		0xff000106,
		0x10010600,
		0xff000010
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f968e9
	};
	uint8_t enter_cmd;
	uint8_t exit_cmd;

	TEST_START;

	status = flash_master_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_testing_init_expectations (test, &flash, header, id);

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

	status = spi_flash_sfdp_get_deep_powerdown_commands (NULL, &enter_cmd, &exit_cmd);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, NULL, &exit_cmd);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = spi_flash_sfdp_get_deep_powerdown_commands (&table, &enter_cmd, NULL);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_basic_table_release (&table);
	spi_flash_sfdp_release (&sfdp);
}


TEST_SUITE_START (spi_flash_sfdp);

TEST (spi_flash_sfdp_test_init);
TEST (spi_flash_sfdp_test_init_null);
TEST (spi_flash_sfdp_test_init_id_error);
TEST (spi_flash_sfdp_test_init_header_error);
TEST (spi_flash_sfdp_test_init_bad_header_signature);
TEST (spi_flash_sfdp_test_init_bad_header);
TEST (spi_flash_sfdp_test_init_bad_header_parameter_table);
TEST (spi_flash_sfdp_test_release_null);
TEST (spi_flash_sfdp_test_basic_table_init);
TEST (spi_flash_sfdp_test_basic_table_init_null);
TEST (spi_flash_sfdp_test_basic_table_init_flash_error);
TEST (spi_flash_sfdp_test_basic_table_release_null);
TEST (spi_flash_sfdp_test_get_device_capabilities_mx25l1606e);
TEST (spi_flash_sfdp_test_get_device_capabilities_mx25l25635f);
TEST (spi_flash_sfdp_test_get_device_capabilities_mx25l25645g);
TEST (spi_flash_sfdp_test_get_device_capabilities_w25q16jv);
TEST (spi_flash_sfdp_test_get_device_capabilities_w25q256jv);
TEST (spi_flash_sfdp_test_get_device_capabilities_mt25q256aba);
TEST (spi_flash_sfdp_test_get_device_capabilities_sst26vf064b);
TEST (spi_flash_sfdp_test_get_device_capabilities_supports_dpi);
TEST (spi_flash_sfdp_test_get_device_capabilities_spi_only);
TEST (spi_flash_sfdp_test_get_device_capabilities_4byte_only);
TEST (spi_flash_sfdp_test_get_device_capabilities_null);
TEST (spi_flash_sfdp_test_get_device_size_mx25l1606e);
TEST (spi_flash_sfdp_test_get_device_size_mx25l25635f);
TEST (spi_flash_sfdp_test_get_device_size_mx25l25645g);
TEST (spi_flash_sfdp_test_get_device_size_w25q16jv);
TEST (spi_flash_sfdp_test_get_device_size_w25q256jv);
TEST (spi_flash_sfdp_test_get_device_size_mt25q256aba);
TEST (spi_flash_sfdp_test_get_device_size_sst26vf064b);
TEST (spi_flash_sfdp_test_get_device_size_8gb);
TEST (spi_flash_sfdp_test_get_device_size_16gb);
TEST (spi_flash_sfdp_test_get_device_size_null);
TEST (spi_flash_sfdp_test_get_read_commands_mx25l1606e);
TEST (spi_flash_sfdp_test_get_read_commands_mx25l25635f);
TEST (spi_flash_sfdp_test_get_read_commands_mx25l25645g);
TEST (spi_flash_sfdp_test_get_read_commands_w25q16jv);
TEST (spi_flash_sfdp_test_get_read_commands_w25q256jv);
TEST (spi_flash_sfdp_test_get_read_commands_mt25q256aba);
TEST (spi_flash_sfdp_test_get_read_commands_sst26vf064b);
TEST (spi_flash_sfdp_test_get_read_commands_supports_dpi);
TEST (spi_flash_sfdp_test_get_read_commands_spi_only);
TEST (spi_flash_sfdp_test_get_read_commands_null);
TEST (spi_flash_sfdp_test_use_busy_flag_status_mx25l1606e);
TEST (spi_flash_sfdp_test_use_busy_flag_status_mx25l25635f);
TEST (spi_flash_sfdp_test_use_busy_flag_status_mx25l25645g);
TEST (spi_flash_sfdp_test_use_busy_flag_status_w25q16jv);
TEST (spi_flash_sfdp_test_use_busy_flag_status_w25q256jv);
TEST (spi_flash_sfdp_test_use_busy_flag_status_mt25q256aba);
TEST (spi_flash_sfdp_test_use_busy_flag_status_sst26vf064b);
TEST (spi_flash_sfdp_test_use_busy_flag_status_null);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_mx25l1606e);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_mx25l25635f);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_mx25l25645g);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_w25q16jv);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_w25q256jv);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_mt25q256aba);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_sst26vf064b);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_volatile_only);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_both_volatile_and_nv);
TEST (spi_flash_sfdp_test_use_volatile_write_enable_null);
TEST (spi_flash_sfdp_test_supports_4byte_commands_mx25l1606e);
TEST (spi_flash_sfdp_test_supports_4byte_commands_mx25l25635f);
TEST (spi_flash_sfdp_test_supports_4byte_commands_mx25l25645g);
TEST (spi_flash_sfdp_test_supports_4byte_commands_w25q16jv);
TEST (spi_flash_sfdp_test_supports_4byte_commands_w25q256jv);
TEST (spi_flash_sfdp_test_supports_4byte_commands_mt25q256aba);
TEST (spi_flash_sfdp_test_supports_4byte_commands_sst26vf064b);
TEST (spi_flash_sfdp_test_supports_4byte_commands_null);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_mx25l1606e);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_mx25l25635f);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_mx25l25645g);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_w25q16jv);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_w25q256jv);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_mt25q256aba);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_sst26vf064b);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_only_extended_addr_reg);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_only_bank_reg);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_only_nv_config_reg);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_null);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_no_exit_command);
TEST (spi_flash_sfdp_test_get_4byte_mode_switch_no_exit_command_write_enable);
TEST (spi_flash_sfdp_test_get_quad_enable_mx25l1606e);
TEST (spi_flash_sfdp_test_get_quad_enable_mx25l25635f);
TEST (spi_flash_sfdp_test_get_quad_enable_mx25l25645g);
TEST (spi_flash_sfdp_test_get_quad_enable_w25q16jv);
TEST (spi_flash_sfdp_test_get_quad_enable_w25q256jv);
TEST (spi_flash_sfdp_test_get_quad_enable_mt25q256aba);
TEST (spi_flash_sfdp_test_get_quad_enable_sst26vf064b);
TEST (spi_flash_sfdp_test_get_quad_enable_no_qe_bit_no_hold_disable);
TEST (spi_flash_sfdp_test_get_quad_enable_bit1_sr2_with_clear);
TEST (spi_flash_sfdp_test_get_quad_enable_bit7_sr2);
TEST (spi_flash_sfdp_test_get_quad_enable_bit1_sr2_with_35_read);
TEST (spi_flash_sfdp_test_get_quad_enable_old_table_version_no_qspi);
TEST (spi_flash_sfdp_test_get_quad_enable_null);
TEST (spi_flash_sfdp_test_get_quad_enable_reserved_value_6);
TEST (spi_flash_sfdp_test_get_quad_enable_reserved_value_7);
TEST (spi_flash_sfdp_test_get_quad_enable_old_table_version_with_qspi);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_mx25l1606e);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_mx25l25635f);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_mx25l25645g);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_w25q16jv);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_w25q256jv);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_mt25q256aba);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_sst26vf064b);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_no_revert);
TEST (spi_flash_sfdp_test_exit_4byte_mode_on_reset_null);
TEST (spi_flash_sfdp_test_get_reset_command_mx25l1606e);
TEST (spi_flash_sfdp_test_get_reset_command_mx25l25635f);
TEST (spi_flash_sfdp_test_get_reset_command_mx25l25645g);
TEST (spi_flash_sfdp_test_get_reset_command_w25q16jv);
TEST (spi_flash_sfdp_test_get_reset_command_w25q256jv);
TEST (spi_flash_sfdp_test_get_reset_command_mt25q256aba);
TEST (spi_flash_sfdp_test_get_reset_command_sst26vf064b);
TEST (spi_flash_sfdp_test_get_reset_command_f0);
TEST (spi_flash_sfdp_test_get_reset_command_both_f0_and_66);
TEST (spi_flash_sfdp_test_get_reset_command_no_soft_reset);
TEST (spi_flash_sfdp_test_get_reset_command_8clocks_f);
TEST (spi_flash_sfdp_test_get_reset_command_10clocks_f);
TEST (spi_flash_sfdp_test_get_reset_command_16clocks_f);
TEST (spi_flash_sfdp_test_get_reset_command_null);
TEST (spi_flash_sfdp_test_get_page_size_mx25l1606e);
TEST (spi_flash_sfdp_test_get_page_size_mx25l25635f);
TEST (spi_flash_sfdp_test_get_page_size_mx25l25645g);
TEST (spi_flash_sfdp_test_get_page_size_w25q16jv);
TEST (spi_flash_sfdp_test_get_page_size_w25q256jv);
TEST (spi_flash_sfdp_test_get_page_size_mt25q256aba);
TEST (spi_flash_sfdp_test_get_page_size_sst26vf064b);
TEST (spi_flash_sfdp_test_get_page_size_128_byte_page);
TEST (spi_flash_sfdp_test_get_page_size_max_page_size);
TEST (spi_flash_sfdp_test_get_page_size_null);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_mx25l1606e);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_mx25l25635f);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_mx25l25645g);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_w25q16jv);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_w25q256jv);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_mt25q256aba);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_sst26vf064b);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_non_standard);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_not_supported);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_old_table_version);
TEST (spi_flash_sfdp_test_get_deep_powerdown_commands_null);

TEST_SUITE_END;
