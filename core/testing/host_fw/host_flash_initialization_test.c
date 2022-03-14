// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_flash_initialization.h"
#include "testing/mock/flash/flash_master_mock.h"


TEST_SUITE_LABEL ("host_flash_initialization");


/*******************
 * Test cases
 *******************/

static void host_flash_initialization_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);
}

static void host_flash_initialization_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (NULL, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init (&init, NULL, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init (&init, &flash0, NULL, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, NULL, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, NULL,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		NULL, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, NULL, false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);
}

static void host_flash_initialization_test_init_single_flash (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_flash_initialization init;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init_single_flash (&init, &flash, &state, &flash_mock.base,
		false, false);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);
}

static void host_flash_initialization_test_init_single_flash_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_flash_initialization init;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init_single_flash (NULL, &flash, &state, &flash_mock.base,
		false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init_single_flash (&init, NULL, &state, &flash_mock.base,
		false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init_single_flash (&init, &flash, NULL, &flash_mock.base,
		false, false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = host_flash_initialization_init_single_flash (&init, &flash, &state, NULL, false,
		false);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);
}

static void host_flash_initialization_test_release_null (CuTest *test)
{
	TEST_START;

	host_flash_initialization_release (NULL);
}

static void host_flash_initialization_test_initialize_flash (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock1.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	status = flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash0, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash1, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
}

static void host_flash_initialization_test_initialize_flash_fast_read (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, true, false);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock1.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	status = flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash0, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash1, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
}

static void host_flash_initialization_test_initialize_flash_drive_strength (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t id_length = sizeof (winbond);
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, true);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x11, &configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &configured, sizeof (configured),
		FLASH_EXP_READ_REG (0x15, sizeof (configured)));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x11, &configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &configured, sizeof (configured),
		FLASH_EXP_READ_REG (0x15, sizeof (configured)));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock1.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash0, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash1, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
}

static void host_flash_initialization_test_initialize_flash_twice (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock1.mock);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
}

static void host_flash_initialization_test_initialize_flash_single_flash (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init_single_flash (&init, &flash, &state, &flash_mock.base,
		false, false);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock.mock, flash_mock.base.capabilities, &flash_mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash);
}

static void host_flash_initialization_test_initialize_flash_null (CuTest *test)
{
	int status;

	TEST_START;

	status = host_flash_initialization_initialize_flash (NULL);
	CuAssertIntEquals (test, HOST_FLASH_INIT_INVALID_ARGUMENT, status);
}

static void host_flash_initialization_test_initialize_flash_cs0_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_xfer (&flash_mock0, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, id_length));

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock1.mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
}

static void host_flash_initialization_test_initialize_flash_cs1_error (CuTest *test)
{
	struct flash_master_mock flash_mock0;
	struct flash_master_mock flash_mock1;
	struct spi_flash_state state0;
	struct spi_flash_state state1;
	struct spi_flash flash0;
	struct spi_flash flash1;
	struct host_flash_initialization init;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;

	TEST_START;

	status = flash_master_mock_init (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_init (&init, &flash0, &state0, &flash_mock0.base, &flash1,
		&state1, &flash_mock1.base, false, false);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock0.mock, flash_mock0.base.capabilities, &flash_mock0,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock0, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock0, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock0, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Get Device ID. */
	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, id_length));

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&flash_mock0.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash_mock1.mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&flash_mock1.mock, flash_mock1.base.capabilities, &flash_mock1,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&flash_mock1, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&flash_mock1, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock1, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = host_flash_initialization_initialize_flash (&init);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	host_flash_initialization_release (&init);

	spi_flash_release (&flash0);
	spi_flash_release (&flash1);
}


TEST_SUITE_START (host_flash_initialization);

TEST (host_flash_initialization_test_init);
TEST (host_flash_initialization_test_init_null);
TEST (host_flash_initialization_test_init_single_flash);
TEST (host_flash_initialization_test_init_single_flash_null);
TEST (host_flash_initialization_test_release_null);
TEST (host_flash_initialization_test_initialize_flash);
TEST (host_flash_initialization_test_initialize_flash_fast_read);
TEST (host_flash_initialization_test_initialize_flash_drive_strength);
TEST (host_flash_initialization_test_initialize_flash_twice);
TEST (host_flash_initialization_test_initialize_flash_single_flash);
TEST (host_flash_initialization_test_initialize_flash_null);
TEST (host_flash_initialization_test_initialize_flash_cs0_error);
TEST (host_flash_initialization_test_initialize_flash_cs1_error);

TEST_SUITE_END;
