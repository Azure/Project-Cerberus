// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_fw_util.h"
#include "mock/flash_master_mock.h"
#include "mock/spi_filter_interface_mock.h"
#include "engines/hash_testing_engine.h"
#include "engines/rsa_testing_engine.h"
#include "rsa_testing.h"


static const char *SUITE = "host_fw_util";


/*******************
 * Test cases
 *******************/

static void host_fw_determine_version_test (CuTest *test)
{
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x1234, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x1234;

	version_list.versions = &version;
	version_list.count = 1;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version, (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_no_match (CuTest *test)
{
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) "Test", 4,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x1234;

	version_list.versions = &version;
	version_list.count = 1;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_check_multiple (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x400, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x200, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_check_multiple_no_match (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x400, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x200, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x100, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_different_lengths (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "222222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x400, 0, -1, 4));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, 5));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x200, 0, -1, 6));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "222222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_same_address (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x100, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_same_address_different_lengths (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "222222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x100, 0, -1, 4));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x104, 0, -1, 2));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "222222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_same_address_different_lengths_shorter (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 6,
		FLASH_EXP_READ_CMD (0x03, 0x100, 0, -1, 6));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "444444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_null (CuTest *test)
{
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x1234;

	version_list.versions = &version;
	version_list.count = 1;

	status = host_fw_determine_version (NULL, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_determine_version (&flash, NULL, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_determine_version (&flash, &version_list, NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_empty_list (CuTest *test)
{
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	version_list.versions = NULL;
	version_list.count = 0;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_read_fail (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x400, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_version_test_read_fail_cache_update (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "222222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x100, 0, -1, 4));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "222222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_version (&flash, &version_list, &version_out);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test (CuTest *test)
{
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x51234, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x1234;

	version_list.versions = &version;
	version_list.count = 1;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version, (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_no_match (CuTest *test)
{
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) "Test", 4,
		FLASH_EXP_READ_CMD (0x03, 0x51234, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x1234;

	version_list.versions = &version;
	version_list.count = 1;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_check_multiple (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50400, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50300, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50200, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_check_multiple_no_match (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50400, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50300, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50200, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50100, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_different_lengths (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "222222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x50400, 0, -1, 4));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x50300, 0, -1, 5));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x50200, 0, -1, 6));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "222222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_same_address (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50100, 0, -1, strlen (version_exp)));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_same_address_different_lengths (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "222222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x50100, 0, -1, 4));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x50104, 0, -1, 2));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "222222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_same_address_different_lengths_shorter (
	CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 6,
		FLASH_EXP_READ_CMD (0x03, 0x50100, 0, -1, 6));

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "444444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, &version[1], (void*) version_out);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_null (CuTest *test)
{
	struct pfm_firmware_version version;
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "1234";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	version.fw_version_id = version_exp;
	version.version_addr = 0x1234;

	version_list.versions = &version;
	version_list.count = 1;

	status = host_fw_determine_offset_version (NULL, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_determine_offset_version (&flash, 0x50000, NULL, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_empty_list (CuTest *test)
{
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	version_list.versions = NULL;
	version_list.count = 0;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, HOST_FW_UTIL_UNSUPPORTED_VERSION, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_read_fail (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "2222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp,
		strlen (version_exp), FLASH_EXP_READ_CMD (0x03, 0x50400, 0, -1, strlen (version_exp)));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "2222";
	version[1].version_addr = 0x200;
	version[2].fw_version_id = "3333";
	version[2].version_addr = 0x300;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x400;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_determine_offset_version_test_read_fail_cache_update (CuTest *test)
{
	struct pfm_firmware_version version[4];
	struct pfm_firmware_versions version_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	int status;
	const char *version_exp = "222222";
	const struct pfm_firmware_version *version_out;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) version_exp, 7,
		FLASH_EXP_READ_CMD (0x03, 0x50100, 0, -1, 4));

	status |= flash_master_mock_expect_xfer (&flash_mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	version[0].fw_version_id = "1111111";
	version[0].version_addr = 0x100;
	version[1].fw_version_id = "222222";
	version[1].version_addr = 0x100;
	version[2].fw_version_id = "33333";
	version[2].version_addr = 0x100;
	version[3].fw_version_id = "4444";
	version[3].version_addr = 0x100;

	version_list.versions = version;
	version_list.count = 4;

	status = host_fw_determine_offset_version (&flash, 0x50000, &version_list, &version_out);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void host_fw_verify_images_test (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, strlen (data)));

	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_invalid (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, strlen (data)));

	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_not_contiguous (CuTest *test)
{
	struct flash_region region[4];
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data + 1, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data + 2, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x30000, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data + 3, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x40000, 0, -1, 1));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = 1;
	region[1].start_addr = 0x20000;
	region[1].length = 1;
	region[2].start_addr = 0x30000;
	region[2].length = 1;
	region[3].start_addr = 0x40000;
	region[3].length = 1;

	sig.regions = region;
	sig.count = 4;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_multiple (CuTest *test)
{
	struct flash_region region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";
	char *data3 = "Nope";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data3, strlen (data3),
		FLASH_EXP_READ_CMD (0x03, 0x30000, 0, -1, strlen (data3)));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = strlen (data1);
	region[1].start_addr = 0x20000;
	region[1].length = strlen (data2);
	region[2].start_addr = 0x30000;
	region[2].length = strlen (data3);

	sig[0].regions = &region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	sig[2].regions = &region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	list.images = sig;
	list.count = 3;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_multiple_one_invalid (CuTest *test)
{
	struct flash_region region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";
	char *data3 = "Nope";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0x20000, 0, -1, strlen (data2)));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = strlen (data1);
	region[1].start_addr = 0x20000;
	region[1].length = strlen (data2);
	region[2].start_addr = 0x30000;
	region[2].length = strlen (data3);

	sig[0].regions = &region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	sig[2].regions = &region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	list.images = sig;
	list.count = 3;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_partial_validation (CuTest *test)
{
	struct flash_region region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";
	char *data3 = "Nope";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data3, strlen (data3),
		FLASH_EXP_READ_CMD (0x03, 0x30000, 0, -1, strlen (data3)));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = strlen (data1);
	region[1].start_addr = 0x20000;
	region[1].length = strlen (data2);
	region[2].start_addr = 0x30000;
	region[2].length = strlen (data3);

	sig[0].regions = &region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 0;

	sig[2].regions = &region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	list.images = sig;
	list.count = 3;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_no_images (CuTest *test)
{
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	list.images = NULL;
	list.count = 0;

	status = host_fw_verify_images (&flash, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_images_test_null (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_images (NULL, &list, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_verify_images (&flash, NULL, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_verify_images (&flash, &list, NULL, &rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_verify_images (&flash, &list, &hash.base, NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x410000, 0, -1, strlen (data)));

	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_no_offset (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, strlen (data)));

	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_offset_images (&flash, &list, 0, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_invalid (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x310000, 0, -1, strlen (data)));

	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_offset_images (&flash, &list, 0x300000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_not_contiguous (CuTest *test)
{
	struct flash_region region[4];
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x410000, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data + 1, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x420000, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data + 2, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x430000, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data + 3, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x440000, 0, -1, 1));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = 1;
	region[1].start_addr = 0x20000;
	region[1].length = 1;
	region[2].start_addr = 0x30000;
	region[2].length = 1;
	region[3].start_addr = 0x40000;
	region[3].length = 1;

	sig.regions = region;
	sig.count = 4;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_multiple (CuTest *test)
{
	struct flash_region region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";
	char *data3 = "Nope";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x410000, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0x420000, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data3, strlen (data3),
		FLASH_EXP_READ_CMD (0x03, 0x430000, 0, -1, strlen (data3)));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = strlen (data1);
	region[1].start_addr = 0x20000;
	region[1].length = strlen (data2);
	region[2].start_addr = 0x30000;
	region[2].length = strlen (data3);

	sig[0].regions = &region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	sig[2].regions = &region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	list.images = sig;
	list.count = 3;

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_multiple_one_invalid (CuTest *test)
{
	struct flash_region region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";
	char *data3 = "Nope";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x410000, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0x420000, 0, -1, strlen (data2)));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = strlen (data1);
	region[1].start_addr = 0x20000;
	region[1].length = strlen (data2);
	region[2].start_addr = 0x30000;
	region[2].length = strlen (data3);

	sig[0].regions = &region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	sig[2].regions = &region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	list.images = sig;
	list.count = 3;

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_partial_validation (CuTest *test)
{
	struct flash_region region[3];
	struct pfm_image_signature sig[3];
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";
	char *data3 = "Nope";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x410000, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data3, strlen (data3),
		FLASH_EXP_READ_CMD (0x03, 0x430000, 0, -1, strlen (data3)));

	CuAssertIntEquals (test, 0, status);

	region[0].start_addr = 0x10000;
	region[0].length = strlen (data1);
	region[1].start_addr = 0x20000;
	region[1].length = strlen (data2);
	region[2].start_addr = 0x30000;
	region[2].length = strlen (data3);

	sig[0].regions = &region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 0;

	sig[2].regions = &region[2];
	sig[2].count = 1;
	memcpy (&sig[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[2].signature, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	sig[2].sig_length = RSA_ENCRYPT_LEN;
	sig[2].always_validate = 1;

	list.images = sig;
	list.count = 3;

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_no_images (CuTest *test)
{
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	list.images = NULL;
	list.count = 0;

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_verify_offset_images_test_null (CuTest *test)
{
	struct flash_region region;
	struct pfm_image_signature sig;
	struct pfm_image_list list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	region.start_addr = 0x10000;
	region.length = strlen (data);

	sig.regions = &region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	list.images = &sig;
	list.count = 1;

	status = host_fw_verify_offset_images (NULL, &list, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_verify_offset_images (&flash, NULL, 0x400000, &hash.base, &rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, NULL, &rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_verify_offset_images (&flash, &list, 0x400000, &hash.base, NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data),
		0x200 - strlen (data));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x300, 0x1000 - 0x300);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_not_blank_byte (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data)));

	status |= flash_master_mock_expect_value_check (&flash_mock, 0 + strlen (data),
		0x200 - strlen (data), 0x55);
	status |= flash_master_mock_expect_value_check (&flash_mock, 0x300, 0x1000 - 0x300, 0x55);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0x55, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_multiple_rw_regions (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data),
		0x200 - strlen (data));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x300, 0x300);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x700, 0x1000 - 0x700);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0x600;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_image_between_rw_regions (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0x900, 0, -1, strlen (data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0, 0x800);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x900 + strlen (data),
		0xb00 - (0x900 + strlen (data)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xc00, 0x1000 - 0xc00);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0x900;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region[0].start_addr = 0x800;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xb00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_multiple_images (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0x900, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data1),
		0x800 - strlen (data1));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x900 + strlen (data2),
		0xc00 - (0x900 + strlen (data2)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xd00, 0x1000 - 0xd00);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (data1);
	img_region[1].start_addr = 0x900;
	img_region[1].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0x800;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xc00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_offset_image (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0xb00, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data1),
		0x800 - strlen (data1));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x900, 0xb00 - 0x900);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xb00 + strlen (data2),
		0xd00 - (0xb00 + strlen (data2)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xe00, 0x1000 - 0xe00);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (data1);
	img_region[1].start_addr = 0xb00;
	img_region[1].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0x800;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xd00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_first_region_rw (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0xa00, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x100, 0x200);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x300 + strlen (data1),
		0xa00 - (0x300 + strlen (data1)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xa00 + strlen (data2),
		0xc00 - (0xa00 + strlen (data2)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xd00, 0x1000 - 0xd00);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0x300;
	img_region[0].length = strlen (data1);
	img_region[1].start_addr = 0xa00;
	img_region[1].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xc00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_last_region_rw (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0xa00, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data1),
		0x200 - strlen (data1));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x300, 0xa00 - 0x300);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xa00 + strlen (data2),
		0xf00 - (0xa00 + strlen (data2)));

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (data1);
	img_region[1].start_addr = 0xa00;
	img_region[1].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xf00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_multipart_image (CuTest *test)
{
	struct flash_region img_region[4];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, 1));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1 + 1, 3,
		FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, 2));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1 + 3, 1,
		FLASH_EXP_READ_CMD (0x03, 0xe00, 0, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0xa00, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x001, 0x1ff);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x300 + 2, 0xa00 - 0x302);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xa00 + strlen (data2),
		0xc00 - (0xa00 + strlen (data2)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xd00, 0x100);
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xe01, 0x1000 - 0xe01);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = 1;
	img_region[1].start_addr = 0x300;
	img_region[1].length = 2;
	img_region[2].start_addr = 0xe00;
	img_region[2].length = 1;
	img_region[3].start_addr = 0xa00;
	img_region[3].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 3;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[3];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0x200;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xc00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_partial_validation (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data1)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data2, strlen (data2),
		FLASH_EXP_READ_CMD (0x03, 0x900, 0, -1, strlen (data2)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data1),
		0x800 - strlen (data1));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0x900 + strlen (data2),
		0xc00 - (0x900 + strlen (data2)));
	status |= flash_master_mock_expect_blank_check (&flash_mock, 0xd00, 0x1000 - 0xd00);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (data1);
	img_region[1].start_addr = 0x900;
	img_region[1].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 0;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0x800;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xc00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_invalid_image (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region[2];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data1, strlen (data1),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data1)));

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (data1);
	img_region[1].start_addr = 0x900;
	img_region[1].length = strlen (data2);

	sig[0].regions = &img_region[0];
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region[0].start_addr = 0x800;
	rw_region[0].length = 0x100;
	rw_region[1].start_addr = 0xc00;
	rw_region[1].length = 0x100;

	rw_list.regions = rw_region;
	rw_list.count = 2;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_not_blank (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN,
		FLASH_EXP_READ_CMD (0x03, 0 + strlen (data), 0, -1, FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, FLASH_UTIL_UNEXPECTED_VALUE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_last_not_blank (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) data, strlen (data),
		FLASH_EXP_READ_CMD (0x03, 0, 0, -1, strlen (data)));

	status |= flash_master_mock_expect_blank_check (&flash_mock, 0 + strlen (data),
		0x200 - strlen (data));
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x300, 0, -1, FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, FLASH_UTIL_UNEXPECTED_VALUE, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_full_flash_verification_test_null (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x200;
	rw_region.length = 0x100;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_full_flash_verification (NULL, &img_list, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_full_flash_verification (&flash, NULL, &rw_list, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_full_flash_verification (&flash, &img_list, NULL, 0xff, &hash.base,
		&rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, NULL,
		&rsa.base);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_full_flash_verification (&flash, &img_list, &rw_list, 0xff, &hash.base,
		NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void host_fw_migrate_read_write_data_test (CuTest *test)
{
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list, &flash1, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_multiple_regions (CuTest *test)
{
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 16);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, 32);

	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x30000,
		0x30000, RSA_ENCRYPT_TEST2, 16);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x50000,
		0x50000, RSA_ENCRYPT_NOPE, 32);

	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = RSA_ENCRYPT_LEN;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 16;
	rw_region[2].start_addr = 0x50000;
	rw_region[2].length = 32;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list, &flash1, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_different_addresses (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, RSA_ENCRYPT_LEN);

	CuAssertIntEquals (test, 0, status);

	rw_region1.start_addr = 0x10000;
	rw_region1.length = RSA_ENCRYPT_LEN;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x50000;
	rw_region2.length = RSA_ENCRYPT_LEN;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_ADDR, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_multiple_diff_addresses (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x40000, 16);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, 32);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x40000;
	rw_region2[1].length = 16;
	rw_region2[2].start_addr = 0x50000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_ADDR, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_dest_larger (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000,
		RSA_ENCRYPT_LEN * 2);

	CuAssertIntEquals (test, 0, status);

	rw_region1.start_addr = 0x10000;
	rw_region1.length = RSA_ENCRYPT_LEN;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x10000;
	rw_region2.length = RSA_ENCRYPT_LEN * 2;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_SIZE, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_dest_smaller (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000,
		RSA_ENCRYPT_LEN - 1);

	CuAssertIntEquals (test, 0, status);

	rw_region1.start_addr = 0x10000;
	rw_region1.length = RSA_ENCRYPT_LEN;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x10000;
	rw_region2.length = RSA_ENCRYPT_LEN - 1;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_SIZE, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_multiple_one_smaller (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 8);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, 32);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 8;
	rw_region2[2].start_addr = 0x50000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_SIZE, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_dest_more_regions (CuTest *test)
{
	struct flash_region rw_region1[2];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 16);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x60000, 32);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;

	rw_list1.regions = rw_region1;
	rw_list1.count = 2;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 16;
	rw_region2[2].start_addr = 0x60000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_COUNT, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_src_more_regions (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 16);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 16;

	rw_list2.regions = rw_region2;
	rw_list2.count = 2;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_COUNT, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_diff_address_and_size (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x40000, 16);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, 16);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x40000;
	rw_region2[1].length = 16;
	rw_region2[2].start_addr = 0x50000;
	rw_region2[2].length = 16;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_ADDR, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_diff_size_and_address (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 8);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x60000, 32);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 8;
	rw_region2[2].start_addr = 0x60000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_SIZE, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_all_different (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x20000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 8);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x20000;
	rw_region2[0].length = RSA_ENCRYPT_LEN;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 8;

	rw_list2.regions = rw_region2;
	rw_list2.count = 2;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, HOST_FW_UTIL_DIFF_REGION_COUNT, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_multiple_diff_ordering (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 16);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, 32);

	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x30000,
		0x30000, RSA_ENCRYPT_TEST2, 16);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x50000,
		0x50000, RSA_ENCRYPT_NOPE, 32);

	CuAssertIntEquals (test, 0, status);

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = RSA_ENCRYPT_LEN;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x50000;
	rw_region2[0].length = 32;
	rw_region2[1].start_addr = 0x10000;
	rw_region2[1].length = RSA_ENCRYPT_LEN;
	rw_region2[2].start_addr = 0x30000;
	rw_region2[2].length = 16;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list2, &flash1, &rw_list1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_no_source_regions (CuTest *test)
{
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_copy_flash_verify (&flash_mock2, &flash_mock1, 0x10000,
		0x10000, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);

	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list, &flash1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_null (CuTest *test)
{
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = RSA_ENCRYPT_LEN;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = host_fw_migrate_read_write_data (NULL, &rw_list, &flash1, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_migrate_read_write_data (&flash2, NULL, &flash1, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_migrate_read_write_data (&flash2, &rw_list, NULL, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_erase_error (CuTest *test)
{
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock2, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = RSA_ENCRYPT_LEN;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 16;
	rw_region[2].start_addr = 0x50000;
	rw_region[2].length = 32;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list, &flash1, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_migrate_read_write_data_test_copy_error (CuTest *test)
{
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x10000, RSA_ENCRYPT_LEN);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x30000, 16);
	status |= flash_master_mock_expect_erase_flash_verify (&flash_mock2, 0x50000, 32);

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = RSA_ENCRYPT_LEN;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 16;
	rw_region[2].start_addr = 0x50000;
	rw_region[2].length = 32;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = host_fw_migrate_read_write_data (&flash2, &rw_list, &flash1, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_are_read_write_regions_different_test (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1.start_addr = 0x10000;
	rw_region1.length = 0x100;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x10000;
	rw_region2.length = 0x100;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_read_write_regions_different_test_different_address (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1.start_addr = 0x10000;
	rw_region1.length = 0x100;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x50000;
	rw_region2.length = 0x100;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_read_write_regions_different_test_different_size (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1.start_addr = 0x10000;
	rw_region1.length = 0x100;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x10000;
	rw_region2.length = 0x101;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_read_write_regions_different_test_multiple (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = 0x100;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = 0x100;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 16;
	rw_region2[2].start_addr = 0x50000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_read_write_regions_different_test_multiple_diff_addr (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = 0x100;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = 0x100;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 16;
	rw_region2[2].start_addr = 0x60000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_read_write_regions_different_test_multiple_diff_size (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = 0x100;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = 0x100;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 24;
	rw_region2[2].start_addr = 0x50000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_read_write_regions_different_test_second_fewer (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2[2];
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = 0x100;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = 0x100;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 16;

	rw_list2.regions = rw_region2;
	rw_list2.count = 2;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_read_write_regions_different_test_first_fewer (CuTest *test)
{
	struct flash_region rw_region1[2];
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = 0x100;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;

	rw_list1.regions = rw_region1;
	rw_list1.count = 2;

	rw_region2[0].start_addr = 0x10000;
	rw_region2[0].length = 0x100;
	rw_region2[1].start_addr = 0x30000;
	rw_region2[1].length = 16;
	rw_region2[2].start_addr = 0x50000;
	rw_region2[2].length = 32;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_read_write_regions_different_test_multiple_reordered (CuTest *test)
{
	struct flash_region rw_region1[3];
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2[3];
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1[0].start_addr = 0x10000;
	rw_region1[0].length = 0x100;
	rw_region1[1].start_addr = 0x30000;
	rw_region1[1].length = 16;
	rw_region1[2].start_addr = 0x50000;
	rw_region1[2].length = 32;

	rw_list1.regions = rw_region1;
	rw_list1.count = 3;

	rw_region2[0].start_addr = 0x50000;
	rw_region2[0].length = 32;
	rw_region2[1].start_addr = 0x10000;
	rw_region2[1].length = 0x100;
	rw_region2[2].start_addr = 0x30000;
	rw_region2[2].length = 16;

	rw_list2.regions = rw_region2;
	rw_list2.count = 3;

	status = host_fw_are_read_write_regions_different (&rw_list1, &rw_list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_read_write_regions_different_test_null (CuTest *test)
{
	struct flash_region rw_region1;
	struct pfm_read_write_regions rw_list1;
	struct flash_region rw_region2;
	struct pfm_read_write_regions rw_list2;
	bool status;

	TEST_START;

	rw_region1.start_addr = 0x10000;
	rw_region1.length = 0x100;

	rw_list1.regions = &rw_region1;
	rw_list1.count = 1;

	rw_region2.start_addr = 0x10000;
	rw_region2.length = 0x100;

	rw_list2.regions = &rw_region2;
	rw_list2.count = 1;

	status = host_fw_are_read_write_regions_different (NULL, &rw_list2);
	CuAssertIntEquals (test, true, status);

	status = host_fw_are_read_write_regions_different (&rw_list1, NULL);
	CuAssertIntEquals (test, true, status);

	status = host_fw_are_read_write_regions_different (NULL, NULL);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_restore_flash_device_test (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);

	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0, 0,
		(uint8_t*) data, strlen (data), 0);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_multipart_image (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);

	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0, 0,
		(uint8_t*) data, 1, 0);
	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0x20000, 0x20000,
		(uint8_t*) data + 1, strlen (data) - 1, 0);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = 1;
	img_region[1].start_addr = 0x20000;
	img_region[1].length = strlen (data) - 1;

	sig.regions = img_region;
	sig.count = 2;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_multiple_images (CuTest *test)
{
	struct flash_region img_region[2];
	struct pfm_image_signature sig[2];
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data1 = "Test";
	char *data2 = "Test2";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);

	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0, 0,
		(uint8_t*) data1, strlen (data1), 0);
	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0x20000, 0x20000,
		(uint8_t*) data2, strlen (data2), 0);

	CuAssertIntEquals (test, 0, status);

	img_region[0].start_addr = 0;
	img_region[0].length = strlen (data1);

	sig[0].regions = img_region;
	sig[0].count = 1;
	memcpy (&sig[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig[0].sig_length = RSA_ENCRYPT_LEN;
	sig[0].always_validate = 1;

	img_region[1].start_addr = 0x20000;
	img_region[1].length = strlen (data2);

	sig[1].regions = &img_region[1];
	sig[1].count = 1;
	memcpy (&sig[1].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig[1].signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig[1].sig_length = RSA_ENCRYPT_LEN;
	sig[1].always_validate = 1;

	img_list.images = sig;
	img_list.count = 2;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_multiple_rw_regions (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x40000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x60000);

	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0, 0,
		(uint8_t*) data, strlen (data), 0);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = 0x10000;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 0x10000;
	rw_region[2].start_addr = 0x50000;
	rw_region[2].length = 0x10000;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = spi_flash_set_device_size (&flash2, 0x70000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_rw_regions_not_ordered (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x40000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x60000);

	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0, 0,
		(uint8_t*) data, strlen (data), 0);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region[0].start_addr = 0x50000;
	rw_region[0].length = 0x10000;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 0x10000;
	rw_region[2].start_addr = 0x10000;
	rw_region[2].length = 0x10000;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = spi_flash_set_device_size (&flash2, 0x70000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_start_and_end_rw (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0x10000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x40000);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x50000);

	status |= flash_master_mock_expect_copy_flash (&flash_mock2, &flash_mock1, 0x20000, 0x20000,
		(uint8_t*) data, strlen (data), 0);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0x20000;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region[0].start_addr = 0;
	rw_region[0].length = 0x10000;
	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 0x10000;
	rw_region[2].start_addr = 0x60000;
	rw_region[2].length = 0x10000;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = spi_flash_set_device_size (&flash2, 0x70000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_null (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (NULL, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_restore_flash_device (&flash2, NULL, &img_list, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, NULL, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_erase_error (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&flash_mock2, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_last_erase_error (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_xfer (&flash_mock2, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_restore_flash_device_test_copy_error (CuTest *test)
{
	struct flash_region img_region;
	struct pfm_image_signature sig;
	struct pfm_image_list img_list;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	struct flash_master_mock flash_mock1;
	struct spi_flash flash1;
	struct flash_master_mock flash_mock2;
	struct spi_flash flash2;
	int status;
	char *data = "Test";

	TEST_START;

	status = flash_master_mock_init (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash1, &flash_mock1.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash2, &flash_mock2.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash1, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash2, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_erase_flash (&flash_mock2, 0);
	status |= flash_master_mock_expect_erase_flash (&flash_mock2, 0x20000);

	status |= flash_master_mock_expect_xfer (&flash_mock1, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	img_region.start_addr = 0;
	img_region.length = strlen (data);

	sig.regions = &img_region;
	sig.count = 1;
	memcpy (&sig.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig.sig_length = RSA_ENCRYPT_LEN;
	sig.always_validate = 1;

	img_list.images = &sig;
	img_list.count = 1;

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = spi_flash_set_device_size (&flash2, 0x30000);
	CuAssertIntEquals (test, 0, status);

	status = host_fw_restore_flash_device (&flash2, &flash1, &img_list, &rw_list);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&flash_mock1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock2);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash1);
	spi_flash_release (&flash2);
}

static void host_fw_config_spi_filter_read_write_regions_test (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = mock_expect (&filter.mock, filter.base.clear_filter_rw_regions, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_filter_rw_region, &filter, 0,
		MOCK_ARG (1), MOCK_ARG (0x10000), MOCK_ARG (0x20000));

	CuAssertIntEquals (test, 0, status);

	status = host_fw_config_spi_filter_read_write_regions (&filter.base, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);
}

static void host_fw_config_spi_filter_read_write_regions_test_multiple_regions (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = 0x10000;

	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 0x20000;

	rw_region[2].start_addr = 0x60000;
	rw_region[2].length = 0x30000;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = mock_expect (&filter.mock, filter.base.clear_filter_rw_regions, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_filter_rw_region, &filter, 0,
		MOCK_ARG (1), MOCK_ARG (0x10000), MOCK_ARG (0x20000));
	status |= mock_expect (&filter.mock, filter.base.set_filter_rw_region, &filter, 0,
		MOCK_ARG (2), MOCK_ARG (0x30000), MOCK_ARG (0x50000));
	status |= mock_expect (&filter.mock, filter.base.set_filter_rw_region, &filter, 0,
		MOCK_ARG (3), MOCK_ARG (0x60000), MOCK_ARG (0x90000));

	CuAssertIntEquals (test, 0, status);

	status = host_fw_config_spi_filter_read_write_regions (&filter.base, &rw_list);
	CuAssertIntEquals (test, 0, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);
}

static void host_fw_config_spi_filter_read_write_regions_test_null (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct flash_region rw_region;
	struct pfm_read_write_regions rw_list;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	rw_region.start_addr = 0x10000;
	rw_region.length = 0x10000;

	rw_list.regions = &rw_region;
	rw_list.count = 1;

	status = host_fw_config_spi_filter_read_write_regions (NULL, &rw_list);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = host_fw_config_spi_filter_read_write_regions (&filter.base, NULL);
	CuAssertIntEquals (test, HOST_FW_UTIL_INVALID_ARGUMENT, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);
}

static void host_fw_config_spi_filter_read_write_regions_test_filter_error (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = 0x10000;

	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 0x20000;

	rw_region[2].start_addr = 0x60000;
	rw_region[2].length = 0x30000;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = mock_expect (&filter.mock, filter.base.clear_filter_rw_regions, &filter, 0);
	status |= mock_expect (&filter.mock, filter.base.set_filter_rw_region, &filter, 0,
		MOCK_ARG (1), MOCK_ARG (0x10000), MOCK_ARG (0x20000));
	status |= mock_expect (&filter.mock, filter.base.set_filter_rw_region, &filter,
		SPI_FILTER_SET_RW_FAILED, MOCK_ARG (2), MOCK_ARG (0x30000), MOCK_ARG (0x50000));

	CuAssertIntEquals (test, 0, status);

	status = host_fw_config_spi_filter_read_write_regions (&filter.base, &rw_list);
	CuAssertIntEquals (test, SPI_FILTER_SET_RW_FAILED, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);
}

static void host_fw_config_spi_filter_read_write_regions_test_clear_error (CuTest *test)
{
	struct spi_filter_interface_mock filter;
	struct flash_region rw_region[3];
	struct pfm_read_write_regions rw_list;
	int status;

	TEST_START;

	status = spi_filter_interface_mock_init (&filter);
	CuAssertIntEquals (test, 0, status);

	rw_region[0].start_addr = 0x10000;
	rw_region[0].length = 0x10000;

	rw_region[1].start_addr = 0x30000;
	rw_region[1].length = 0x20000;

	rw_region[2].start_addr = 0x60000;
	rw_region[2].length = 0x30000;

	rw_list.regions = rw_region;
	rw_list.count = 3;

	status = mock_expect (&filter.mock, filter.base.clear_filter_rw_regions, &filter,
		SPI_FILTER_CLEAR_RW_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = host_fw_config_spi_filter_read_write_regions (&filter.base, &rw_list);
	CuAssertIntEquals (test, SPI_FILTER_CLEAR_RW_FAILED, status);

	status = spi_filter_interface_mock_validate_and_release (&filter);
	CuAssertIntEquals (test, 0, status);
}

static void host_fw_are_images_different_test (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_images_different_test_different_key_mod_length (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	sig2.key.mod_length -= 1;
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_key_exponent(CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	sig2.key.exponent = 3;
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_key_modulus (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_sig_length (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN - 1;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_signature (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST2, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_validate_flag (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 0;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_region_addr (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x20000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_different_region_length (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x200;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_key_mod_length (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	sig2[2].key.mod_length -= 1;
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_key_exponent (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	sig2[2].key.exponent = 3;
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_key_modulus (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_sig_length (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN - 1;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_signature (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST2, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_validate_flag (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 0;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_images_diff_image_count (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12;
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22;
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12.start_addr = 0x30000;
	region12.length = 32;

	sig1[1].regions = &region12;
	sig1[1].count = 1;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22.start_addr = 0x30000;
	region22.length = 32;

	sig2[1].regions = &region22;
	sig2[1].count = 1;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 2;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_regions (CuTest *test)
{
	struct flash_region region1[3];
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2[3];
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1[0].start_addr = 0x10000;
	region1[0].length = 0x100;
	region1[1].start_addr = 0x30000;
	region1[1].length = 16;
	region1[2].start_addr = 0x50000;
	region1[2].length = 32;

	sig1.regions = region1;
	sig1.count = 3;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2[0].start_addr = 0x10000;
	region2[0].length = 0x100;
	region2[1].start_addr = 0x30000;
	region2[1].length = 16;
	region2[2].start_addr = 0x50000;
	region2[2].length = 32;

	sig2.regions = region2;
	sig2.count = 3;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_images_different_test_multiple_regions_diff_addr (CuTest *test)
{
	struct flash_region region1[3];
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2[3];
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1[0].start_addr = 0x10000;
	region1[0].length = 0x100;
	region1[1].start_addr = 0x30000;
	region1[1].length = 16;
	region1[2].start_addr = 0x50000;
	region1[2].length = 32;

	sig1.regions = region1;
	sig1.count = 3;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2[0].start_addr = 0x10000;
	region2[0].length = 0x100;
	region2[1].start_addr = 0x30000;
	region2[1].length = 16;
	region2[2].start_addr = 0x60000;
	region2[2].length = 32;

	sig2.regions = region2;
	sig2.count = 3;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_regions_diff_length (CuTest *test)
{
	struct flash_region region1[3];
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2[3];
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1[0].start_addr = 0x10000;
	region1[0].length = 0x100;
	region1[1].start_addr = 0x30000;
	region1[1].length = 16;
	region1[2].start_addr = 0x50000;
	region1[2].length = 32;

	sig1.regions = region1;
	sig1.count = 3;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2[0].start_addr = 0x10000;
	region2[0].length = 0x100;
	region2[1].start_addr = 0x30000;
	region2[1].length = 24;
	region2[2].start_addr = 0x50000;
	region2[2].length = 32;

	sig2.regions = region2;
	sig2.count = 3;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_regions_diff_count (CuTest *test)
{
	struct flash_region region1[3];
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2[3];
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1[0].start_addr = 0x10000;
	region1[0].length = 0x100;
	region1[1].start_addr = 0x30000;
	region1[1].length = 16;
	region1[2].start_addr = 0x50000;
	region1[2].length = 32;

	sig1.regions = region1;
	sig1.count = 3;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2[0].start_addr = 0x10000;
	region2[0].length = 0x100;
	region2[1].start_addr = 0x30000;
	region2[1].length = 16;
	region2[2].start_addr = 0x50000;
	region2[2].length = 32;

	sig2.regions = region2;
	sig2.count = 2;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_multiple_regions_reordered (CuTest *test)
{
	struct flash_region region1[3];
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2[3];
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1[0].start_addr = 0x10000;
	region1[0].length = 0x100;
	region1[1].start_addr = 0x30000;
	region1[1].length = 16;
	region1[2].start_addr = 0x50000;
	region1[2].length = 32;

	sig1.regions = region1;
	sig1.count = 3;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2[0].start_addr = 0x50000;
	region2[0].length = 32;
	region2[1].start_addr = 0x10000;
	region2[1].length = 0x100;
	region2[2].start_addr = 0x30000;
	region2[2].length = 16;

	sig2.regions = region2;
	sig2.count = 3;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_images_different_test_multiple_images_multiple_regions (CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12[3];
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22[3];
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12[0].start_addr = 0x30000;
	region12[0].length = 32;
	region12[1].start_addr = 0x60000;
	region12[1].length = 64;
	region12[2].start_addr = 0x90000;
	region12[2].length = 128;

	sig1[1].regions = region12;
	sig1[1].count = 3;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22[0].start_addr = 0x30000;
	region22[0].length = 32;
	region22[1].start_addr = 0x60000;
	region22[1].length = 64;
	region22[2].start_addr = 0x90000;
	region22[2].length = 128;

	sig2[1].regions = region22;
	sig2[1].count = 3;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, false, status);
}

static void host_fw_are_images_different_test_multiple_images_multiple_regions_diff_region_count (
	CuTest *test)
{
	struct flash_region region11;
	struct flash_region region12[3];
	struct flash_region region13;
	struct pfm_image_signature sig1[3];
	struct pfm_image_list list1;
	struct flash_region region21;
	struct flash_region region22[3];
	struct flash_region region23;
	struct pfm_image_signature sig2[3];
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region11.start_addr = 0x10000;
	region11.length = 0x100;

	sig1[0].regions = &region11;
	sig1[0].count = 1;
	memcpy (&sig1[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1[0].sig_length = RSA_ENCRYPT_LEN;
	sig1[0].always_validate = 1;

	region12[0].start_addr = 0x30000;
	region12[0].length = 32;
	region12[1].start_addr = 0x60000;
	region12[1].length = 64;
	region12[2].start_addr = 0x90000;
	region12[2].length = 128;

	sig1[1].regions = region12;
	sig1[1].count = 3;
	memcpy (&sig1[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig1[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig1[1].sig_length = RSA_ENCRYPT_LEN;
	sig1[1].always_validate = 1;

	region13.start_addr = 0x50000;
	region13.length = 16;

	sig1[2].regions = &region13;
	sig1[2].count = 1;
	memcpy (&sig1[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig1[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig1[2].sig_length = RSA_ENCRYPT_LEN;
	sig1[2].always_validate = 1;

	list1.images = sig1;
	list1.count = 3;

	region21.start_addr = 0x10000;
	region21.length = 0x100;

	sig2[0].regions = &region21;
	sig2[0].count = 1;
	memcpy (&sig2[0].key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2[0].signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2[0].sig_length = RSA_ENCRYPT_LEN;
	sig2[0].always_validate = 1;

	region22[0].start_addr = 0x30000;
	region22[0].length = 32;
	region22[1].start_addr = 0x60000;
	region22[1].length = 64;
	region22[2].start_addr = 0x90000;
	region22[2].length = 128;

	sig2[1].regions = region22;
	sig2[1].count = 2;
	memcpy (&sig2[1].key, &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	memcpy (&sig2[1].signature, RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	sig2[1].sig_length = RSA_ENCRYPT_LEN;
	sig2[1].always_validate = 1;

	region23.start_addr = 0x50000;
	region23.length = 16;

	sig2[2].regions = &region23;
	sig2[2].count = 1;
	memcpy (&sig2[2].key, &RSA_PUBLIC_KEY3, sizeof (RSA_PUBLIC_KEY3));
	memcpy (&sig2[2].signature, RSA_SIGNATURE3_TEST, RSA_ENCRYPT_LEN);
	sig2[2].sig_length = RSA_ENCRYPT_LEN;
	sig2[2].always_validate = 1;

	list2.images = sig2;
	list2.count = 3;

	status = host_fw_are_images_different (&list1, &list2);
	CuAssertIntEquals (test, true, status);
}

static void host_fw_are_images_different_test_null (CuTest *test)
{
	struct flash_region region1;
	struct pfm_image_signature sig1;
	struct pfm_image_list list1;
	struct flash_region region2;
	struct pfm_image_signature sig2;
	struct pfm_image_list list2;
	bool status;

	TEST_START;

	region1.start_addr = 0x10000;
	region1.length = 0x100;

	sig1.regions = &region1;
	sig1.count = 1;
	memcpy (&sig1.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig1.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig1.sig_length = RSA_ENCRYPT_LEN;
	sig1.always_validate = 1;

	list1.images = &sig1;
	list1.count = 1;

	region2.start_addr = 0x10000;
	region2.length = 0x100;

	sig2.regions = &region2;
	sig2.count = 1;
	memcpy (&sig2.key, &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY));
	memcpy (&sig2.signature, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	sig2.sig_length = RSA_ENCRYPT_LEN;
	sig2.always_validate = 1;

	list2.images = &sig2;
	list2.count = 1;

	status = host_fw_are_images_different (&list1, NULL);
	CuAssertIntEquals (test, true, status);

	status = host_fw_are_images_different (NULL, &list2);
	CuAssertIntEquals (test, true, status);

	status = host_fw_are_images_different (NULL, NULL);
	CuAssertIntEquals (test, false, status);
}


CuSuite* get_host_fw_util_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, host_fw_determine_version_test);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_no_match);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_check_multiple);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_check_multiple_no_match);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_different_lengths);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_same_address);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_same_address_different_lengths);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_same_address_different_lengths_shorter);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_null);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_empty_list);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_read_fail);
	SUITE_ADD_TEST (suite, host_fw_determine_version_test_read_fail_cache_update);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_no_match);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_check_multiple);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_check_multiple_no_match);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_different_lengths);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_same_address);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_same_address_different_lengths);
	SUITE_ADD_TEST (suite,
		host_fw_determine_offset_version_test_same_address_different_lengths_shorter);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_null);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_empty_list);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_read_fail);
	SUITE_ADD_TEST (suite, host_fw_determine_offset_version_test_read_fail_cache_update);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_invalid);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_not_contiguous);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_multiple);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_multiple_one_invalid);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_partial_validation);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_no_images);
	SUITE_ADD_TEST (suite, host_fw_verify_images_test_null);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_no_offset);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_invalid);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_not_contiguous);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_multiple);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_multiple_one_invalid);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_partial_validation);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_no_images);
	SUITE_ADD_TEST (suite, host_fw_verify_offset_images_test_null);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_not_blank_byte);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_multiple_rw_regions);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_image_between_rw_regions);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_multiple_images);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_offset_image);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_first_region_rw);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_last_region_rw);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_multipart_image);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_partial_validation);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_invalid_image);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_not_blank);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_last_not_blank);
	SUITE_ADD_TEST (suite, host_fw_full_flash_verification_test_null);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_multiple_regions);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_different_addresses);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_multiple_diff_addresses);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_dest_larger);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_dest_smaller);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_multiple_one_smaller);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_dest_more_regions);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_src_more_regions);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_diff_address_and_size);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_diff_size_and_address);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_all_different);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_multiple_diff_ordering);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_no_source_regions);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_null);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_erase_error);
	SUITE_ADD_TEST (suite, host_fw_migrate_read_write_data_test_copy_error);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_different_address);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_different_size);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_multiple);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_multiple_diff_addr);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_multiple_diff_size);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_second_fewer);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_first_fewer);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_multiple_reordered);
	SUITE_ADD_TEST (suite, host_fw_are_read_write_regions_different_test_null);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_multipart_image);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_multiple_images);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_multiple_rw_regions);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_rw_regions_not_ordered);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_start_and_end_rw);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_null);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_erase_error);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_last_erase_error);
	SUITE_ADD_TEST (suite, host_fw_restore_flash_device_test_copy_error);
	SUITE_ADD_TEST (suite, host_fw_config_spi_filter_read_write_regions_test);
	SUITE_ADD_TEST (suite, host_fw_config_spi_filter_read_write_regions_test_multiple_regions);
	SUITE_ADD_TEST (suite, host_fw_config_spi_filter_read_write_regions_test_null);
	SUITE_ADD_TEST (suite, host_fw_config_spi_filter_read_write_regions_test_filter_error);
	SUITE_ADD_TEST (suite, host_fw_config_spi_filter_read_write_regions_test_clear_error);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_key_mod_length);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_key_exponent);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_key_modulus);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_sig_length);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_signature);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_validate_flag);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_region_addr);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_different_region_length);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_key_mod_length);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_key_exponent);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_key_modulus);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_sig_length);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_signature);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_validate_flag);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_diff_image_count);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_regions);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_regions_diff_addr);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_regions_diff_length);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_regions_diff_count);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_regions_reordered);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_multiple_images_multiple_regions);
	SUITE_ADD_TEST (suite,
		host_fw_are_images_different_test_multiple_images_multiple_regions_diff_region_count);
	SUITE_ADD_TEST (suite, host_fw_are_images_different_test_null);

	return suite;
}
