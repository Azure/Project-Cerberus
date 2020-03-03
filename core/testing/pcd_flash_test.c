// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "manifest/pcd/pcd_flash.h"
#include "manifest/pcd/pcd_format.h"
#include "mock/flash_master_mock.h"
#include "mock/signature_verification_mock.h"
#include "engines/hash_testing_engine.h"
#include "pcd_testing.h"
#include "cmd_interface/device_manager.h"
#include "flash/flash.h"


static const char *SUITE = "pcd_flash";


/*******************
 * Test cases
 *******************/

static void pcd_flash_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, pcd.base.get_platform_id);
	CuAssertPtrNotNull (test, pcd.base.get_devices_info);
	CuAssertPtrNotNull (test, pcd.base.get_rot_info);
	CuAssertPtrNotNull (test, pcd.base.get_port_info);
	CuAssertPtrNotNull (test, pcd.base.base.verify);
	CuAssertPtrNotNull (test, pcd.base.base.get_id);
	CuAssertPtrNotNull (test, pcd.base.base.get_hash);
	CuAssertPtrNotNull (test, pcd.base.base.get_signature);

	CuAssertIntEquals (test, 0x10000, pcd_flash_get_addr (&pcd));
	CuAssertPtrEquals (test, &flash, pcd_flash_get_flash (&pcd));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (NULL, &flash, 0x10000);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd_flash_init (&pcd, NULL, 0x10000);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_init_manifest_flash_init_fail (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10001);
	CuAssertIntEquals (test, MANIFEST_STORAGE_NOT_ALIGNED, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_release_null (CuTest *test)
{
	TEST_START;

	pcd_flash_release (NULL);
}

static void pcd_flash_test_release_no_init (CuTest *test)
{
	struct pcd_flash manifest;

	TEST_START;

	memset (&manifest, 0, sizeof (manifest));

	pcd_flash_release (&manifest);
}

static void pcd_flash_test_get_addr_null (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, 0, pcd_flash_get_addr (NULL));
}

static void pcd_flash_test_get_flash_null (CuTest *test)
{
	TEST_START;

	CuAssertPtrEquals (test, NULL, pcd_flash_get_flash (NULL));
}

static void pcd_flash_test_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (NULL, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.base.verify (&pcd.base.base, NULL, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, NULL, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_manifest_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, pcd_bad_data, 
		sizeof (pcd_bad_data), FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_rot_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_port_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_components_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_component_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_mux_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_read_platform_header_fail (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_header pcd_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;
	
	memcpy (&pcd_header, PCD_DATA + PCD_HEADER_SIZE, sizeof (struct pcd_header));
	pcd_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_header_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_header pcd_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_header, PCD_DATA + PCD_HEADER_SIZE, sizeof (struct pcd_header));
	pcd_header.header_len += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_rot_too_big (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_header pcd_rot_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_rot_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header), 
		sizeof (struct pcd_rot_header));
	pcd_rot_header.length = PCD_DATA_LEN;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_rot_header, 
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_rot_too_big2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_header pcd_rot_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_rot_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header), 
		sizeof (struct pcd_rot_header));
	pcd_rot_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_rot_header, 
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_rot_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_header pcd_rot_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_rot_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header), 
		sizeof (struct pcd_rot_header));
	pcd_rot_header.header_len += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_port_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_port_header pcd_port_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_port_header, 
		PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + sizeof (struct pcd_rot_header), 
		sizeof (struct pcd_port_header));
	pcd_port_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_components_too_big (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_components_header pcd_components_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_components_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header), 
		sizeof (struct pcd_components_header));
	pcd_components_header.length = PCD_DATA_LEN;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_components_header, 
		sizeof (struct pcd_components_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 
		0, -1, sizeof (struct pcd_components_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_components_too_big2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_components_header pcd_components_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_components_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header), 
		sizeof (struct pcd_components_header));
	pcd_components_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_components_header,
		sizeof (struct pcd_components_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 
		0, -1, sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_components_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_components_header pcd_components_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_components_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header), 
		sizeof (struct pcd_components_header));
	pcd_components_header.header_len += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_component_too_big (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_component_header pcd_component_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_component_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header), sizeof (struct pcd_component_header));
	pcd_component_header.length = PCD_DATA_LEN;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_component_header, 
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_component_too_big2 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_component_header pcd_component_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_component_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header), sizeof (struct pcd_component_header));
	pcd_component_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_component_header, 
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_component_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_component_header pcd_component_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_component_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header), sizeof (struct pcd_component_header));
	pcd_component_header.header_len += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_mux_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_mux_header pcd_mux_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_mux_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header) + 2 * sizeof (struct pcd_component_header), 
		sizeof (struct pcd_mux_header));
	pcd_mux_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_platform_too_big (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_platform_header pcd_platform_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_platform_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header) + 2 * sizeof (struct pcd_component_header) + \
		2 * sizeof (struct pcd_mux_header), sizeof (struct pcd_platform_header));
	pcd_platform_header.length += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_platform_header, 
		sizeof (struct pcd_platform_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_invalid_pcd_platform_header_header_len (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_platform_header pcd_platform_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_platform_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header) + 2 * sizeof (struct pcd_component_header) + \
		2 * sizeof (struct pcd_mux_header), sizeof (struct pcd_platform_header));
	pcd_platform_header.header_len += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, (uint8_t*) &pcd_platform_header, 
		sizeof (struct pcd_platform_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, PCD_INVALID_SEG_HDR_LEN, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_pcd_platform_header_different (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_platform_header pcd_platform_header = {0};
	uint32_t pcd_offset;
	int status;

	TEST_START;

	memcpy (&pcd_platform_header, PCD_DATA + PCD_HEADER_SIZE + sizeof (struct pcd_header) + \
		sizeof (struct pcd_rot_header) + 2 * sizeof (struct pcd_port_header) + \
		sizeof (struct pcd_components_header) + 2 * sizeof (struct pcd_component_header) + \
		2 * sizeof (struct pcd_mux_header), sizeof (struct pcd_platform_header));
	pcd_platform_header.length += 1;
	pcd_platform_header.header_len += 1;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_bad_magic_number (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_verify_invalid_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_get_id (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_id (&pcd.base.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_id_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	uint32_t id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_id (NULL, &id);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.base.get_id (&pcd.base.base, NULL);
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_id_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	uint32_t id;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_id (&pcd.base.base, &id);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_hash (&pcd.base.base, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCD_HASH, hash_out, PCD_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_get_hash_after_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint32_t pcd_offset;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	status |= flash_master_mock_expect_verify_flash (&flash_mock, 0x10000, PCD_DATA,
		PCD_DATA_LEN - PCD_SIGNATURE_LEN);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (PCD_HASH, PCD_HASH_LEN), MOCK_ARG (PCD_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (PCD_SIGNATURE, PCD_SIGNATURE_LEN), MOCK_ARG (PCD_SIGNATURE_LEN));
	CuAssertIntEquals (test, 0, status);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, 
		PCD_DATA_LEN - PCD_HEADER_SIZE, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	pcd_offset = PCD_HEADER_SIZE;

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_header)));

	pcd_offset += sizeof (struct pcd_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset += sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_components_header)));

	pcd_offset += sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_mux_header)));

	pcd_offset += sizeof (struct pcd_mux_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		PCD_DATA_LEN - pcd_offset, FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_platform_header)));

	status = pcd.base.base.verify (&pcd.base.base, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_hash (&pcd.base.base, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (PCD_HASH, hash_out, PCD_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_hash (NULL, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.base.get_hash (&pcd.base.base, NULL, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = pcd.base.base.get_hash (&pcd.base.base, &hash.base, NULL, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_get_hash_bad_magic_num (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_hash (&pcd.base.base, &hash.base, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void pcd_flash_test_get_signature (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t sig_out[PCD_SIGNATURE_LEN];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_SIGNATURE, PCD_SIGNATURE_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_SIGNATURE_OFFSET, 0, -1, PCD_SIGNATURE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_signature (&pcd.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_SIGNATURE_LEN, status);

	status = testing_validate_array (PCD_SIGNATURE, sig_out, PCD_SIGNATURE_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_signature_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_signature (NULL, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.base.get_signature (&pcd.base.base, NULL, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_signature_bad_magic_number (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t sig_out[SHA256_HASH_LENGTH];
	int status;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.base.get_signature (&pcd.base.base, sig_out, sizeof (sig_out));
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE)); 

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_COMPONENTS_OFFSET,
		PCD_DATA_LEN - PCD_COMPONENTS_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1, 
		sizeof (struct pcd_components_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		PCD_DATA + PCD_PLATFORM_ID_HDR_OFFSET, PCD_DATA_LEN - PCD_PLATFORM_ID_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_PLATFORM_ID_HDR_OFFSET, 0, -1,
			sizeof (struct pcd_platform_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_PLATFORM_ID_OFFSET,
		PCD_DATA_LEN - (PCD_PLATFORM_ID_OFFSET), 
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_PLATFORM_ID_OFFSET, 0, -1, PCD_PLATFORM_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, PCD_PLATFORM_ID, id);

	platform_free (id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pcd.base.get_platform_id (NULL, &id);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, id);

	status = pcd.base.get_platform_id (&pcd.base, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	CuAssertIntEquals (test, 0, status);

	id = (char*) &status;
	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);
	CuAssertPtrEquals (test, NULL, id);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_pcd_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_rot_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_components_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_platform_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_COMPONENTS_OFFSET,
		PCD_DATA_LEN - PCD_COMPONENTS_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1, 
		sizeof (struct pcd_components_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_platform_id_identifier_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;
	char *id;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE,
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_COMPONENTS_OFFSET,
		PCD_DATA_LEN - PCD_COMPONENTS_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1, 
		sizeof (struct pcd_components_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,
		PCD_DATA + PCD_PLATFORM_ID_HDR_OFFSET, PCD_DATA_LEN - PCD_PLATFORM_ID_HDR_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_PLATFORM_ID_HDR_OFFSET, 0, -1,
			sizeof (struct pcd_platform_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_platform_id (&pcd.base, &id);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	
	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	size_t pcd_offset;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_COMPONENTS_OFFSET,
		sizeof (struct pcd_components_header), FLASH_EXP_READ_CMD (0x03, 
		0x10000 + PCD_COMPONENTS_OFFSET, 0, -1, sizeof (struct pcd_components_header)));

	pcd_offset = PCD_COMPONENTS_OFFSET + sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	pcd_offset += sizeof (struct pcd_component_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, num_devices);
	CuAssertPtrNotNull (test, devices_info);

	CuAssertIntEquals (test, 0x10, devices_info[0].smbus_addr);
	CuAssertIntEquals (test, 0x0C, devices_info[0].eid);
	CuAssertIntEquals (test, 0x15, devices_info[1].smbus_addr);
	CuAssertIntEquals (test, 0x0D, devices_info[1].eid);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	platform_free (devices_info);
	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_devices_info (NULL, &devices_info, &num_devices);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.get_devices_info (&pcd.base, NULL, &num_devices);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, PCD_DATA, 
		PCD_DATA_LEN, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];
	size_t num_devices;
	int status;

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_pcd_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_HEADER_SIZE, PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_rot_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE, 
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_ROT_OFFSET, PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_components_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE, 
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0,	PCD_DATA + PCD_ROT_OFFSET, 
		PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_COMPONENTS_OFFSET, PCD_DATA_LEN - PCD_COMPONENTS_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_COMPONENTS_OFFSET, 0, -1, 
		sizeof (struct pcd_components_header)));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertPtrEquals (test, devices_info, NULL);
	CuAssertIntEquals (test, num_devices, 0);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_devices_info_component_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct device_manager_info *devices_info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t num_devices;
	size_t pcd_offset;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_COMPONENTS_OFFSET,
		sizeof (struct pcd_components_header), FLASH_EXP_READ_CMD (0x03, 
		0x10000 + PCD_COMPONENTS_OFFSET, 0, -1, sizeof (struct pcd_components_header)));

	pcd_offset = PCD_COMPONENTS_OFFSET + sizeof (struct pcd_components_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, PCD_DATA + pcd_offset,
		sizeof (struct pcd_component_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_component_header)));

	status = pcd.base.get_devices_info (&pcd.base, &devices_info, &num_devices);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);
	CuAssertIntEquals (test, 0, num_devices);
	CuAssertPtrEquals (test, NULL, devices_info);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_rot_info (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	status = pcd.base.get_rot_info (&pcd.base, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, info.is_pa_rot);
	CuAssertIntEquals (test, 0x41, info.i2c_slave_addr);
	CuAssertIntEquals (test, 0x10, info.bmc_i2c_addr);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_rot_info_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_rot_info (NULL, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.get_rot_info (&pcd.base, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_rot_info_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, PCD_DATA, 
		PCD_DATA_LEN, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = pcd.base.get_rot_info (&pcd.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_rot_info_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_info info;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];
	int status;

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = pcd.base.get_rot_info (&pcd.base, &info);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_rot_info_pcd_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_HEADER_SIZE, PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status = pcd.base.get_rot_info (&pcd.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_rot_info_rot_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_rot_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE, 
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_ROT_OFFSET, PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status = pcd.base.get_rot_info (&pcd.base, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_port_info info;
	size_t pcd_offset;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	status = pcd.base.get_port_info (&pcd.base, 0, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 48000000, info.spi_freq);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	status = pcd.base.get_port_info (&pcd.base, 1, &info);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 32000000, info.spi_freq);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_port_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = pcd.base.get_port_info (NULL, 0, &info);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = pcd.base.get_port_info (&pcd.base, 0, NULL);
	CuAssertIntEquals (test, PCD_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct pcd_port_info info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, PCD_DATA, 
		PCD_DATA_LEN, FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = pcd.base.get_port_info (&pcd.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_bad_magic_num (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct pcd_port_info info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	uint8_t pcd_bad_data[PCD_SIGNATURE_OFFSET];
	int status;

	TEST_START;

	memcpy (pcd_bad_data, PCD_DATA, sizeof (pcd_bad_data));
	pcd_bad_data[2] ^= 0x55;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, pcd_bad_data, sizeof (pcd_bad_data),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status = pcd.base.get_port_info (&pcd.base, 0, &info);
	CuAssertIntEquals (test, MANIFEST_BAD_MAGIC_NUMBER, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_pcd_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct pcd_port_info info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_HEADER_SIZE, PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status = pcd.base.get_port_info (&pcd.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_rot_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct pcd_port_info info;
	struct spi_flash flash;
	struct pcd_flash pcd;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_DATA_LEN,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_SIZE, 
		PCD_DATA_LEN - PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_SIZE, 0, -1, sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, 
		PCD_DATA + PCD_ROT_OFFSET, PCD_DATA_LEN - PCD_ROT_OFFSET,
		FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, sizeof (struct pcd_rot_header)));

	status = pcd.base.get_port_info (&pcd.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);

	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_port_header_read_error (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	size_t pcd_offset;
	struct pcd_port_info info;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, FLASH_NO_MEMORY, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	status = pcd.base.get_port_info (&pcd.base, 0, &info);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

static void pcd_flash_test_get_port_info_port_id_invalid (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash flash;
	struct pcd_flash pcd;
	struct pcd_port_info info;
	size_t pcd_offset;
	int status;

	TEST_START;

	status = flash_master_mock_init (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &flash_mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = pcd_flash_init (&pcd, &flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA, PCD_HEADER_SIZE,
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, PCD_HEADER_SIZE));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_HEADER_OFFSET,
		sizeof (struct pcd_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_HEADER_OFFSET, 0, -1, 
		sizeof (struct pcd_header)));

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + PCD_ROT_OFFSET,
		sizeof (struct pcd_rot_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + PCD_ROT_OFFSET, 0, -1, 
		sizeof (struct pcd_rot_header)));

	pcd_offset = PCD_ROT_OFFSET + sizeof (struct pcd_rot_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset,
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	pcd_offset += sizeof (struct pcd_port_header);

	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&flash_mock, 0, PCD_DATA + pcd_offset, 
		sizeof (struct pcd_port_header), FLASH_EXP_READ_CMD (0x03, 0x10000 + pcd_offset, 0, -1, 
		sizeof (struct pcd_port_header)));

	status = pcd.base.get_port_info (&pcd.base, 2, &info);
	CuAssertIntEquals (test, PCD_INVALID_PORT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	pcd_flash_release (&pcd);
	spi_flash_release (&flash);
}

CuSuite* get_pcd_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, pcd_flash_test_init);
	SUITE_ADD_TEST (suite, pcd_flash_test_init_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_init_manifest_flash_init_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_release_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_release_no_init);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_addr_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_flash_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_manifest_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_rot_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_port_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_components_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_component_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_mux_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_read_platform_header_fail);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_header_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_rot_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_rot_too_big2);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_rot_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_port_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_components_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_components_too_big2);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_components_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_component_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_component_too_big2);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_component_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_mux_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_platform_too_big);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_invalid_pcd_platform_header_header_len);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_pcd_platform_header_different);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_bad_magic_number);
	SUITE_ADD_TEST (suite, pcd_flash_test_verify_invalid_signature);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_id);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_id_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_id_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash_after_verify);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_hash_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_signature_bad_magic_number);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_components_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_platform_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_platform_id_identifier_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_components_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_devices_info_component_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_rot_info_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_null);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_bad_magic_num);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_pcd_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_rot_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_port_header_read_error);
	SUITE_ADD_TEST (suite, pcd_flash_test_get_port_info_port_id_invalid);

	return suite;
}
